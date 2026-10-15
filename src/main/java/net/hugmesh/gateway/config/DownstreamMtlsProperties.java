package net.hugmesh.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Coordinates of the in-pod-assembled PKCS12 stores used for DOWNSTREAM
 * (gateway -> API) mutual TLS — see {@link DownstreamMtlsConfig}.
 *
 * <p>Bound from {@code hugmesh.tls.*}, the SAME keys the chart's
 * {@code build-keystore} initContainer writes into the in-pod tmpfs file
 * {@code /stores/application.properties} (loaded via
 * {@code SPRING_CONFIG_ADDITIONAL_LOCATION=file:/config/,file:/stores/}). The
 * passwords are therefore NEVER in git or the pod spec.
 *
 * <p>Defaults match the chart's {@code /stores} layout so a stock in-cluster pod
 * needs no extra config beyond {@code hugmesh.gateway.mtls.enabled=true}; the
 * passwords default empty (a passwordless PKCS12 still loads — held in place by
 * {@code DownstreamMtlsConfigTest#enabledWithPasswordlessStores_andEmptyPasswords_stillStarts},
 * which is why an empty password is diagnosed on a FAILED open rather than refused up front).
 *
 * <p><b>Why the emitted file is a plain {@code application.properties}, not the
 * profile-named {@code application-tls.properties} it once was</b>
 * (hugmesh/hugmesh-gateway#1). An additional-location DIRECTORY only auto-loads
 * {@code application-<name>.properties} when a profile literally named {@code <name>}
 * is ACTIVE, and the chart activates only {@code routes} — so the original file was
 * silently never loaded, {@link #keyStorePassword}/{@link #trustStorePassword} fell
 * through to the packaged {@code application.yml}'s
 * {@code ${HUGMESH_TLS_KEY_STORE_PASSWORD:}} (empty), and {@code KeyStore.load(...)}
 * in {@link DownstreamMtlsConfig#load} could not open the real PKCS12 store. Fixed
 * chart-side in hugmesh-generator commit {@code 39f9fce4} (2026-07-17; the identical
 * emitted-file block now sits in all nine BFF/API deployment manifests too): a plain
 * {@code application.properties} loads UNCONDITIONALLY from the additional location,
 * needs no profile, and shares no keys with the {@code /config/} route table, so it
 * shadows nothing. Re-verified against the chart's
 * {@code charts/hugmesh-gateway/templates/deployment.yaml} ({@code FILENAME IS
 * LOAD-BEARING} block) on 2026-09-09, and again on 2026-09-24 together with the gateway
 * Applications: every one that sets {@code HUGMESH_GATEWAY_MTLS_ENABLED=true} (be, fe,
 * superadmin) also sets {@code keystore.enabled: true} — the switch that adds
 * {@code file:/stores/} to {@code SPRING_CONFIG_ADDITIONAL_LOCATION} — and none overrides
 * that variable or {@code SPRING_PROFILES_ACTIVE}. The Spring side of that mechanism (plain
 * file loads under {@code routes} alone and overrides the packaged empty fallback; the old
 * profile-named file does not) is now executed, on this repo's Boot version and packaged
 * {@code application.yml}, by {@code DownstreamMtlsStoresFileLoadingTest}.
 *
 * <p>A live in-cluster boot with mTLS ON is still not on record. The backstop is the
 * fail-fast in {@link DownstreamMtlsConfig}'s store loading, now under test
 * ({@code DownstreamMtlsConfigTest}): an empty or wrong password is a crash-loop, never a
 * silent plaintext downgrade, and the startup error names the store, the exact
 * {@code hugmesh.tls.*-password} key, and — when that key is empty — the unloaded
 * {@code /stores/application.properties} as the usual cause.
 */
@ConfigurationProperties(prefix = "hugmesh.tls")
public class DownstreamMtlsProperties {

    /** Client-identity keystore the gateway PRESENTS downstream. */
    private String keyStore = "/stores/keystore.p12";
    private String keyStoreType = "PKCS12";
    private String keyStorePassword = "";

    /** Cluster-CA truststore the gateway validates backend server certs against. */
    private String trustStore = "/stores/truststore.p12";
    private String trustStoreType = "PKCS12";
    private String trustStorePassword = "";

    public String getKeyStore() {
        return keyStore;
    }

    public void setKeyStore(String keyStore) {
        this.keyStore = keyStore;
    }

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public void setKeyStoreType(String keyStoreType) {
        this.keyStoreType = keyStoreType;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    public String getTrustStore() {
        return trustStore;
    }

    public void setTrustStore(String trustStore) {
        this.trustStore = trustStore;
    }

    public String getTrustStoreType() {
        return trustStoreType;
    }

    public void setTrustStoreType(String trustStoreType) {
        this.trustStoreType = trustStoreType;
    }

    public String getTrustStorePassword() {
        return trustStorePassword;
    }

    public void setTrustStorePassword(String trustStorePassword) {
        this.trustStorePassword = trustStorePassword;
    }
}
