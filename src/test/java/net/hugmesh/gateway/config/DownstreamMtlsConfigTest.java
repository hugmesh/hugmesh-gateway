package net.hugmesh.gateway.config;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.webclient.WebClientCustomizer;
import org.springframework.cloud.gateway.config.HttpClientCustomizer;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.File;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Gating + wiring tests for {@link DownstreamMtlsConfig} — the DOWNSTREAM
 * (gateway -> API) client-cert presentation config.
 *
 * <p>Uses {@link ApplicationContextRunner} (no full Spring Boot context, no
 * Cassandra/Casdoor) so it is a fast unit gate. The PKCS12 stores are generated
 * at runtime with {@code keytool} into a {@link TempDir} — NO keystore is ever
 * committed to git.
 */
class DownstreamMtlsConfigTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(DownstreamMtlsConfig.class);

    /**
     * DEFAULT OFF: with the flag unset the config is skipped entirely, no
     * HttpClientCustomizer is registered, and nothing touches the (absent)
     * stores — exactly what keeps local/dev/CI + the smoke test proxying http://.
     */
    @Test
    void disabledByDefault_noCustomizerBean() {
        runner.run(ctx -> {
            assertThat(ctx).hasNotFailed();
            assertThat(ctx).doesNotHaveBean(HttpClientCustomizer.class);
            assertThat(ctx).doesNotHaveBean(DownstreamMtlsConfig.class);
        });
    }

    /**
     * Explicit enabled=false behaves the same as unset (no matchIfMissing surprise).
     */
    @Test
    void disabledExplicitly_noCustomizerBean() {
        runner.withPropertyValues("hugmesh.gateway.mtls.enabled=false")
                .run(ctx -> {
                    assertThat(ctx).hasNotFailed();
                    assertThat(ctx).doesNotHaveBean(HttpClientCustomizer.class);
                });
    }

    /**
     * ENABLED with real stores: the HttpClientCustomizer is built from the
     * keystore (client identity) + truststore (cluster CA) and is non-null —
     * proving the gateway will present its cert + validate backend certs.
     */
    @Test
    void enabledWithStores_registersCustomizer(@TempDir Path dir) throws Exception {
        String pw = "changeit";
        String keyStore = dir.resolve("keystore.p12").toString();
        String trustStore = dir.resolve("truststore.p12").toString();
        String certPem = dir.resolve("ca.crt").toString();

        // Self-signed identity -> keystore.p12; export its cert; import into truststore.
        keytool("-genkeypair", "-alias", "gw", "-keyalg", "RSA", "-keysize", "2048",
                "-dname", "CN=hugmesh-be-gateway", "-validity", "1",
                "-keystore", keyStore, "-storetype", "PKCS12", "-storepass", pw, "-keypass", pw);
        keytool("-exportcert", "-alias", "gw",
                "-keystore", keyStore, "-storetype", "PKCS12", "-storepass", pw,
                "-rfc", "-file", certPem);
        keytool("-importcert", "-noprompt", "-alias", "ca", "-file", certPem,
                "-keystore", trustStore, "-storetype", "PKCS12", "-storepass", pw);

        runner.withPropertyValues(
                        "hugmesh.gateway.mtls.enabled=true",
                        "hugmesh.tls.key-store=" + keyStore,
                        "hugmesh.tls.key-store-password=" + pw,
                        "hugmesh.tls.trust-store=" + trustStore,
                        "hugmesh.tls.trust-store-password=" + pw)
                .run(ctx -> {
                    assertThat(ctx).hasNotFailed();
                    assertThat(ctx).hasSingleBean(HttpClientCustomizer.class);
                    assertThat(ctx).hasSingleBean(DownstreamMtlsProperties.class);
                    // BOTH hooks, not just the Spring Cloud Gateway one. See below.
                    assertThat(ctx).hasSingleBean(WebClientCustomizer.class);
                });
    }

    /**
     * THE REGRESSION THIS EXISTS FOR. {@link HttpClientCustomizer} is a Spring Cloud
     * Gateway interface: SCG's {@code HttpClientFactory} applies it to the HttpClient
     * that forwards ROUTED traffic. Boot's {@code WebClient.Builder} never consults it
     * — it consults {@link WebClientCustomizer} beans. So every WebClient built from
     * the auto-configured builder (notably
     * {@code BffSessionConfig.bffIntrospectWebClient}) used the DEFAULT JDK trust,
     * which holds public roots and never the cluster CA.
     *
     * <p>Live on kind 2026-08-06, after the generator corrected BFF_BASE_URL from
     * http:// to https://, the gateway's session bridge moved from
     * "Connection prematurely closed BEFORE response" to
     * "(certificate_unknown) PKIX path building failed" and STILL answered every
     * /bff/session with 503 session_backend_unavailable. Both are this bean's absence.
     *
     * <p>Asserting the bean exists is not enough — that would pass on a customizer
     * that does nothing. This APPLIES it to a real builder and asserts the resulting
     * WebClient's connector actually changed, which is what carries the SslContext.
     */
    @Test
    void enabledWithStores_webClientBuilderActuallyGetsTheMtlsConnector(@TempDir Path dir) throws Exception {
        String pw = "changeit";
        String keyStore = dir.resolve("keystore.p12").toString();
        String trustStore = dir.resolve("truststore.p12").toString();
        String certPem = dir.resolve("ca.crt").toString();
        keytool("-genkeypair", "-alias", "gw", "-keyalg", "RSA", "-keysize", "2048",
                "-dname", "CN=hugmesh-be-gateway", "-validity", "1",
                "-keystore", keyStore, "-storetype", "PKCS12", "-storepass", pw, "-keypass", pw);
        keytool("-exportcert", "-alias", "gw",
                "-keystore", keyStore, "-storetype", "PKCS12", "-storepass", pw,
                "-rfc", "-file", certPem);
        keytool("-importcert", "-noprompt", "-alias", "ca", "-file", certPem,
                "-keystore", trustStore, "-storetype", "PKCS12", "-storepass", pw);

        runner.withPropertyValues(
                        "hugmesh.gateway.mtls.enabled=true",
                        "hugmesh.tls.key-store=" + keyStore,
                        "hugmesh.tls.key-store-password=" + pw,
                        "hugmesh.tls.trust-store=" + trustStore,
                        "hugmesh.tls.trust-store-password=" + pw)
                .run(ctx -> {
                    assertThat(ctx).hasNotFailed();
                    WebClientCustomizer customizer = ctx.getBean(WebClientCustomizer.class);

                    // Assert the BEHAVIOUR (it installs a connector) rather than reaching
                    // into WebClient's internals: a built WebClient keeps its connector
                    // inside an ExchangeFunction, not in a ClientHttpConnector field, so
                    // reflection there silently returns null and the assertion passes on
                    // a customizer that does nothing at all.
                    WebClient.Builder builder = mock(WebClient.Builder.class);
                    customizer.customize(builder);

                    ArgumentCaptor<ClientHttpConnector> captor =
                            ArgumentCaptor.forClass(ClientHttpConnector.class);
                    verify(builder).clientConnector(captor.capture());
                    assertThat(captor.getValue())
                            .as("the customizer must install a reactor-netty connector carrying the mTLS SslContext")
                            .isInstanceOf(ReactorClientHttpConnector.class);
                });
    }

    /** Invoke the JDK keytool that runs the test JVM. */
    private static void keytool(String... args) throws Exception {
        String javaHome = System.getProperty("java.home");
        String keytool = javaHome + File.separator + "bin" + File.separator + "keytool";
        java.util.List<String> cmd = new java.util.ArrayList<>();
        cmd.add(keytool);
        for (String a : args) {
            cmd.add(a);
        }
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes());
        int rc = p.waitFor();
        if (rc != 0) {
            throw new IllegalStateException("keytool " + String.join(" ", args) + " failed (rc=" + rc + "):\n" + out);
        }
    }
}
