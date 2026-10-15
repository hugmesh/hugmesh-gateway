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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;

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

    // ── FAIL-FAST, AND SAYING WHY ──────────────────────────────────────────────────
    //
    // The class javadoc and DownstreamMtlsProperties both lean on "a wrong or missing
    // store password is a crash-loop, never a silent plaintext downgrade" — and until
    // these tests nothing held that in place: every test above feeds the CORRECT
    // password. hugmesh-gateway#1 was precisely an EMPTY password (the chart's
    // profile-named application-tls.properties never loaded, so hugmesh.tls.*-password
    // fell through to the packaged "" fallback). The JDK reports that as a bare
    // "keystore password was incorrect", identical to a wrong password and naming
    // neither the store nor the property; these pin that the gateway (a) still refuses
    // to start, (b) says WHICH store and WHICH property, (c) names the missing-file cause
    // only when the password is actually empty, and (d) never echoes a password.

    /**
     * THE hugmesh-gateway#1 SHAPE: real, password-protected stores; both password
     * properties left at their empty default — exactly what the pod saw while the
     * initContainer's file went unloaded. Must fail startup, name the key-store property
     * as EMPTY, and point at /stores/application.properties + the additional location.
     */
    @Test
    void enabledWithEmptyPasswords_failsFastAndNamesTheUnloadedStoresFile(@TempDir Path dir) throws Exception {
        Stores s = protectedStores(dir, "changeit");

        runner.withPropertyValues(
                        "hugmesh.gateway.mtls.enabled=true",
                        "hugmesh.tls.key-store=" + s.keyStore(),
                        "hugmesh.tls.trust-store=" + s.trustStore())
                .run(ctx -> {
                    assertThat(ctx).hasFailed();
                    IllegalStateException e = openFailure(ctx.getStartupFailure());
                    assertThat(e.getMessage())
                            .contains("key-store at " + s.keyStore())
                            .contains("hugmesh.tls.key-store-password is EMPTY")
                            .contains("/stores/application.properties")
                            .contains("SPRING_CONFIG_ADDITIONAL_LOCATION includes file:/stores/")
                            .contains("application-<name>.properties");
                    // The JDK's own exception is kept, not swallowed: an empty password
                    // against a CORRUPT file lands in this branch too.
                    assertThat(e.getCause()).isInstanceOf(IOException.class);
                });
    }

    /**
     * A set-but-WRONG password must still refuse to start, must NOT send the operator
     * hunting for a missing file (the file clearly loaded), and must never put the
     * password into the message — it would land in the pod log.
     */
    @Test
    void enabledWithWrongPassword_failsFastWithoutBlamingTheFileAndNeverEchoesIt(@TempDir Path dir)
            throws Exception {
        Stores s = protectedStores(dir, "changeit");
        String wrong = "not-the-store-password";

        runner.withPropertyValues(
                        "hugmesh.gateway.mtls.enabled=true",
                        "hugmesh.tls.key-store=" + s.keyStore(),
                        "hugmesh.tls.key-store-password=" + wrong,
                        "hugmesh.tls.trust-store=" + s.trustStore(),
                        "hugmesh.tls.trust-store-password=" + wrong)
                .run(ctx -> {
                    assertThat(ctx).hasFailed();
                    IllegalStateException e = openFailure(ctx.getStartupFailure());
                    assertThat(e.getMessage())
                            .contains("key-store at " + s.keyStore())
                            .contains("hugmesh.tls.key-store-password is set but does not open this store")
                            .doesNotContain("EMPTY")
                            .doesNotContain("/stores/application.properties")
                            .doesNotContain(wrong);
                });
    }

    /**
     * The chart writes the two password keys on separate lines, so losing just one is a
     * plausible shape (sibling BFF manifests once shipped writing some store-password keys
     * and not others — see the generator's tests/scripts/test-outbound-mtls-client.sh).
     * The message must name the store that actually failed — the trust-store here — not
     * the one that opened fine.
     */
    @Test
    void enabledWithOnlyTheTrustStorePasswordMissing_namesTheTrustStoreProperty(@TempDir Path dir)
            throws Exception {
        Stores s = protectedStores(dir, "changeit");

        runner.withPropertyValues(
                        "hugmesh.gateway.mtls.enabled=true",
                        "hugmesh.tls.key-store=" + s.keyStore(),
                        "hugmesh.tls.key-store-password=changeit",
                        "hugmesh.tls.trust-store=" + s.trustStore())
                .run(ctx -> {
                    assertThat(ctx).hasFailed();
                    IllegalStateException e = openFailure(ctx.getStartupFailure());
                    assertThat(e.getMessage())
                            .contains("trust-store at " + s.trustStore())
                            .contains("hugmesh.tls.trust-store-password is EMPTY")
                            .doesNotContain("key-store-password");
                });
    }

    /** No store on disk (e.g. keystore.enabled=false in the chart while the flag is on). */
    @Test
    void enabledWithNoStoreOnDisk_failsFast(@TempDir Path dir) {
        String missing = dir.resolve("absent.p12").toString();

        runner.withPropertyValues(
                        "hugmesh.gateway.mtls.enabled=true",
                        "hugmesh.tls.key-store=" + missing)
                .run(ctx -> {
                    assertThat(ctx).hasFailed();
                    assertThat(openFailure(ctx.getStartupFailure()).getMessage())
                            .contains("the store is not readable: " + missing);
                });
    }

    /**
     * Why the gateway does NOT simply refuse an empty password up front:
     * DownstreamMtlsProperties documents that a passwordless PKCS12 still loads with
     * the empty defaults, and it does. This holds that supported shape in place so a
     * future "empty password ⇒ refuse" shortcut has to delete a test to land.
     */
    @Test
    void enabledWithPasswordlessStores_andEmptyPasswords_stillStarts(@TempDir Path dir) throws Exception {
        Stores protectedOnes = protectedStores(dir, "changeit");
        Stores s = passwordlessCopies(dir, protectedOnes, "changeit");

        runner.withPropertyValues(
                        "hugmesh.gateway.mtls.enabled=true",
                        "hugmesh.tls.key-store=" + s.keyStore(),
                        "hugmesh.tls.trust-store=" + s.trustStore())
                .run(ctx -> {
                    assertThat(ctx).hasNotFailed();
                    assertThat(ctx).hasSingleBean(HttpClientCustomizer.class);
                });
    }

    private record Stores(String keyStore, String trustStore) {
    }

    /** keystore.p12 (self-signed identity) + truststore.p12 (its cert), both under {@code pw}. */
    private static Stores protectedStores(Path dir, String pw) throws Exception {
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
        return new Stores(keyStore, trustStore);
    }

    /**
     * Re-save both stores with an EMPTY password (keytool refuses one, so via the
     * KeyStore API) — the passwordless-PKCS12 shape DownstreamMtlsProperties allows.
     */
    private static Stores passwordlessCopies(Path dir, Stores src, String pw) throws Exception {
        char[] none = new char[0];
        KeyStore srcKs = open(src.keyStore(), pw);
        Key key = srcKs.getKey("gw", pw.toCharArray());
        Certificate[] chain = srcKs.getCertificateChain("gw");
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("gw", key, none, chain);

        KeyStore ts = KeyStore.getInstance("PKCS12");
        ts.load(null, null);
        ts.setCertificateEntry("ca", open(src.trustStore(), pw).getCertificate("ca"));

        Path keyStore = dir.resolve("keystore-nopass.p12");
        Path trustStore = dir.resolve("truststore-nopass.p12");
        try (OutputStream out = Files.newOutputStream(keyStore)) {
            ks.store(out, none);
        }
        try (OutputStream out = Files.newOutputStream(trustStore)) {
            ts.store(out, none);
        }
        return new Stores(keyStore.toString(), trustStore.toString());
    }

    private static KeyStore open(String location, String pw) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(Path.of(location))) {
            ks.load(in, pw.toCharArray());
        }
        return ks;
    }

    /** The gateway's own IllegalStateException, wherever bean creation nested it. */
    private static IllegalStateException openFailure(Throwable startupFailure) {
        for (Throwable t = startupFailure; t != null; t = t.getCause()) {
            if (t instanceof IllegalStateException ise && ise.getMessage() != null
                    && ise.getMessage().startsWith("hugmesh.gateway.mtls.enabled=true but the")) {
                return ise;
            }
        }
        throw new AssertionError("expected DownstreamMtlsConfig's fail-fast IllegalStateException in the "
                + "startup failure chain, got: " + startupFailure, startupFailure);
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
