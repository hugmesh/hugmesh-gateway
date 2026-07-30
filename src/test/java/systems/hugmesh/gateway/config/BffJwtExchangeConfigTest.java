package systems.hugmesh.gateway.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.web.reactive.function.client.WebClient;
import systems.hugmesh.gateway.filter.BffJwtExchangeWebFilter;

import java.io.File;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Gating + wiring tests for the SSO {@code bff_} → custody-JWT exchange seam — the
 * {@link BffJwtExchangeConfig} WebClient AND the {@link BffJwtExchangeWebFilter}.
 *
 * <p><b>Ships-dark proof.</b> With {@code hugmesh.gateway.bff-exchange.enabled}
 * unset (the default) NEITHER the WebClient bean NOR the filter bean exists — the
 * chain is byte-identical to today (a {@code bff_} bearer just 401s at the JWT
 * decoder). Flipping the flag on materializes both; turning on mTLS too builds the
 * WebClient on the cluster-CA client identity (fail-fast on a missing store, never a
 * plaintext fallback).
 *
 * <p>Uses {@link ApplicationContextRunner} (no full Spring Boot context, no
 * Cassandra/Casdoor) so it is a fast unit gate. The PKCS12 stores are generated at
 * runtime with {@code keytool} into a {@link TempDir} — NO keystore is committed.
 */
class BffJwtExchangeConfigTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(BffJwtExchangeConfig.class, BffJwtExchangeWebFilter.class);

    /**
     * DEFAULT OFF: with the flag unset the config is skipped entirely — no WebClient,
     * no filter bean. This is the ships-dark invariant: the bff_ swap is absent and
     * the chain is byte-identical to today.
     */
    @Test
    void disabledByDefault_noWebClientNoFilter() {
        runner.run(ctx -> {
            assertThat(ctx).hasNotFailed();
            assertThat(ctx).doesNotHaveBean(BffJwtExchangeConfig.class);
            assertThat(ctx).doesNotHaveBean(BffJwtExchangeWebFilter.class);
            assertThat(ctx).doesNotHaveBean(WebClient.class);
        });
    }

    /** Explicit enabled=false behaves the same as unset (no matchIfMissing surprise). */
    @Test
    void disabledExplicitly_noWebClientNoFilter() {
        runner.withPropertyValues("hugmesh.gateway.bff-exchange.enabled=false")
                .run(ctx -> {
                    assertThat(ctx).hasNotFailed();
                    assertThat(ctx).doesNotHaveBean(BffJwtExchangeConfig.class);
                    assertThat(ctx).doesNotHaveBean(BffJwtExchangeWebFilter.class);
                });
    }

    /**
     * ENABLED, mTLS OFF (local/dev/CI): the WebClient + the filter materialize, no
     * stores are touched — the default connector proxies plain http://.
     */
    @Test
    void enabledMtlsOff_buildsWebClientAndFilter_noStores() {
        runner.withPropertyValues(
                        "hugmesh.gateway.bff-exchange.enabled=true",
                        "hugmesh.gateway.bff-exchange.admin-bff-uri=http://admin-bff:8080")
                .run(ctx -> {
                    assertThat(ctx).hasNotFailed();
                    assertThat(ctx).hasSingleBean(BffJwtExchangeConfig.class);
                    assertThat(ctx).hasSingleBean(WebClient.class);
                    assertThat(ctx).hasSingleBean(BffJwtExchangeWebFilter.class);
                });
    }

    /**
     * ENABLED + mTLS ON with real stores: the WebClient is built on the cluster-CA
     * client identity (proving the back-channel will present the gateway cert), and
     * the filter is wired to it.
     */
    @Test
    void enabledMtlsOn_withStores_buildsMtlsWebClient(@TempDir Path dir) throws Exception {
        String pw = "changeit";
        String keyStore = dir.resolve("keystore.p12").toString();
        String trustStore = dir.resolve("truststore.p12").toString();
        String certPem = dir.resolve("ca.crt").toString();

        keytool("-genkeypair", "-alias", "gw", "-keyalg", "RSA", "-keysize", "2048",
                "-dname", "CN=hugmesh-fe-gateway", "-validity", "1",
                "-keystore", keyStore, "-storetype", "PKCS12", "-storepass", pw, "-keypass", pw);
        keytool("-exportcert", "-alias", "gw",
                "-keystore", keyStore, "-storetype", "PKCS12", "-storepass", pw,
                "-rfc", "-file", certPem);
        keytool("-importcert", "-noprompt", "-alias", "ca", "-file", certPem,
                "-keystore", trustStore, "-storetype", "PKCS12", "-storepass", pw);

        runner.withPropertyValues(
                        "hugmesh.gateway.bff-exchange.enabled=true",
                        "hugmesh.gateway.mtls.enabled=true",
                        "hugmesh.tls.key-store=" + keyStore,
                        "hugmesh.tls.key-store-password=" + pw,
                        "hugmesh.tls.trust-store=" + trustStore,
                        "hugmesh.tls.trust-store-password=" + pw)
                .run(ctx -> {
                    assertThat(ctx).hasNotFailed();
                    assertThat(ctx).hasSingleBean(WebClient.class);
                    assertThat(ctx).hasSingleBean(BffJwtExchangeWebFilter.class);
                });
    }

    /**
     * ENABLED + mTLS ON but the store is MISSING: fail FAST (context refresh fails)
     * rather than silently fall back to plaintext on a back-channel carrying the
     * session-exchanging internal token.
     */
    @Test
    void enabledMtlsOn_missingStore_failsFast(@TempDir Path dir) {
        runner.withPropertyValues(
                        "hugmesh.gateway.bff-exchange.enabled=true",
                        "hugmesh.gateway.mtls.enabled=true",
                        "hugmesh.tls.key-store=" + dir.resolve("does-not-exist.p12"))
                .run(ctx -> assertThat(ctx).hasFailed());
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
