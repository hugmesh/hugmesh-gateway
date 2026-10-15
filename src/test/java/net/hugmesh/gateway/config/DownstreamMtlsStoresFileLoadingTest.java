package net.hugmesh.gateway.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.Banner;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Pins the Spring Boot config-data behaviour the downstream-mTLS password hand-off
 * rests on — i.e. answers hugmesh-gateway#1 by EXECUTION, on this repo's own Boot
 * version and packaged {@code application.yml}, instead of by reading.
 *
 * <p>The hand-off: the chart's {@code build-keystore} initContainer writes the generated
 * store password into {@code /stores/application.properties}, and the gateway container
 * runs with {@code SPRING_CONFIG_ADDITIONAL_LOCATION=file:/config/,file:/stores/} and
 * {@code SPRING_PROFILES_ACTIVE=routes} (hugmesh-generator
 * {@code specs/cluster/charts/hugmesh-gateway/templates/deployment.yaml}; nothing in any
 * gateway Application overrides either variable as of 2026-09-24). Until
 * hugmesh-generator {@code 39f9fce4} that file was named {@code application-tls.properties}.
 * These tests reproduce both shapes with a real {@link SpringApplicationBuilder} run
 * (no auto-configuration, no web server — only the Environment is under test) and bind
 * {@code hugmesh.tls.*} exactly as {@link DownstreamMtlsProperties} does:
 *
 * <ul>
 *   <li>the plain file loads with only {@code routes} active and OVERRIDES the packaged
 *       {@code application.yml}'s empty {@code ${HUGMESH_TLS_KEY_STORE_PASSWORD:}}
 *       fallback — the working, current shape;</li>
 *   <li>the profile-named file under {@code routes} leaves the password EMPTY — the #1
 *       bug, reproduced;</li>
 *   <li>the same profile-named file DOES load once {@code tls} is active — the control
 *       that proves the previous case is the profile gate and not an unreadable fixture.</li>
 * </ul>
 *
 * <p><b>What this does NOT prove:</b> that a real pod boots with mTLS on. That still has
 * no live run on record (README, Known Gaps). If the password does fail to arrive,
 * {@code DownstreamMtlsConfigTest} pins that startup fails and names this file as the
 * usual cause.
 */
class DownstreamMtlsStoresFileLoadingTest {

    /** Bare configuration: no auto-config, so no Cassandra/Casdoor/Netty — just config data. */
    @Configuration(proxyBeanMethods = false)
    static class EnvironmentOnly {
    }

    @BeforeEach
    void noEnvironmentOverride() {
        // An OS env var relaxed-binds to hugmesh.tls.key-store-password and outranks every
        // config file, which would make the "stays empty" assertion below meaningless.
        assumeTrue(System.getenv("HUGMESH_TLS_KEY_STORE_PASSWORD") == null,
                "HUGMESH_TLS_KEY_STORE_PASSWORD is set in this environment; it would shadow the files under test");
    }

    /** The current chart shape: plain application.properties, only `routes` active. */
    @Test
    void plainStoresFile_loadsWithoutAnyTlsProfile_andOverridesThePackagedEmptyFallback(@TempDir Path stores)
            throws Exception {
        Files.writeString(stores.resolve("application.properties"),
                "hugmesh.tls.key-store-password=from-stores-file\n");

        assertThat(boundKeyStorePassword(stores, "routes")).isEqualTo("from-stores-file");
    }

    /** The pre-39f9fce4 chart shape: profile-named file, only `routes` active ⇒ never loaded. */
    @Test
    void profileNamedStoresFile_isSilentlySkippedUnderTheChartsRoutesProfile(@TempDir Path stores)
            throws Exception {
        Files.writeString(stores.resolve("application-tls.properties"),
                "hugmesh.tls.key-store-password=from-stores-file\n");

        assertThat(boundKeyStorePassword(stores, "routes"))
                .as("the packaged application.yml's ${HUGMESH_TLS_KEY_STORE_PASSWORD:} fallback — empty")
                .isEmpty();
    }

    /** Control for the case above: the same file IS read once a `tls` profile is active. */
    @Test
    void profileNamedStoresFile_loadsOnlyOnceTheTlsProfileIsActive(@TempDir Path stores) throws Exception {
        Files.writeString(stores.resolve("application-tls.properties"),
                "hugmesh.tls.key-store-password=from-stores-file\n");

        assertThat(boundKeyStorePassword(stores, "routes,tls")).isEqualTo("from-stores-file");
    }

    private static String boundKeyStorePassword(Path storesDir, String activeProfiles) {
        try (ConfigurableApplicationContext ctx = new SpringApplicationBuilder(EnvironmentOnly.class)
                .web(WebApplicationType.NONE)
                .bannerMode(Banner.Mode.OFF)
                .logStartupInfo(false)
                // Command-line args, like the pod's env vars: both are read before config data.
                .run("--spring.config.additional-location=file:" + storesDir.toAbsolutePath() + "/",
                        "--spring.profiles.active=" + activeProfiles)) {
            // Non-vacuity: the packaged application.yml (the only source of this key) must
            // be in play, or "overrides the packaged empty fallback" would prove nothing.
            assertThat(ctx.getEnvironment().containsProperty("hugmesh.gateway.mtls.enabled"))
                    .as("packaged application.yml loaded")
                    .isTrue();
            return Binder.get(ctx.getEnvironment())
                    .bind("hugmesh.tls", Bindable.of(DownstreamMtlsProperties.class))
                    .orElseGet(DownstreamMtlsProperties::new)
                    .getKeyStorePassword();
        }
    }
}
