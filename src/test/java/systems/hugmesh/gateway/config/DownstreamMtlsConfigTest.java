package systems.hugmesh.gateway.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.cloud.gateway.config.HttpClientCustomizer;

import java.io.File;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

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
                });
    }

    /**
     * ENABLED but the store is missing: fail FAST (context refresh fails) rather
     * than silently fall back to plaintext or an insecure trust manager.
     */
    @Test
    void enabledWithMissingStore_failsFast(@TempDir Path dir) {
        runner.withPropertyValues(
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
