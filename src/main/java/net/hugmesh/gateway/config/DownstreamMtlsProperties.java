package net.hugmesh.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Coordinates of the in-pod-assembled PKCS12 stores used for DOWNSTREAM
 * (gateway -> API) mutual TLS — see {@link DownstreamMtlsConfig}.
 *
 * <p>Bound from {@code hugmesh.tls.*}, the SAME keys the chart's
 * {@code build-keystore} initContainer writes into
 * {@code /stores/application-tls.properties} (loaded via
 * {@code SPRING_CONFIG_ADDITIONAL_LOCATION=file:/stores/}). The passwords are
 * therefore NEVER in git or the pod spec — only in the in-pod tmpfs file.
 *
 * <p>Defaults match the chart's {@code /stores} layout so a stock in-cluster pod
 * needs no extra config beyond {@code hugmesh.gateway.mtls.enabled=true}; the
 * passwords default empty (a passwordless PKCS12 still loads).
 *
 * <p>TODO: {@code application-tls.properties} is a Spring Boot PROFILE-SPECIFIC
 * document ({@code application-<profile>}) — an additional-location directory only
 * auto-loads it when a profile literally named {@code tls} is ACTIVE, which merely
 * adding it as a search directory does not do. This is the same fleet-wide gap
 * already found (and, as of this writing, still unfixed pending a chart-side design
 * decision) for the {@code server.ssl.*} binding on other Spring services sharing
 * this exact {@code build-keystore} + {@code application-tls.properties} pattern.
 * Unverified here whether the chart activates a {@code tls} profile for this
 * gateway's pods — if it does not, the real random password the initContainer
 * generates never binds and {@link #keyStorePassword}/{@link #trustStorePassword}
 * stay at their empty default, so {@code KeyStore.load(...)} in
 * {@link DownstreamMtlsConfig#load} throws on the real (non-passwordless) PKCS12
 * store and the pod fails to start whenever {@code hugmesh.gateway.mtls.enabled=true}
 * (documented on {@link DownstreamMtlsConfig} as already set on the be/fe-gateway
 * ArgoCD apps). Fail-fast rather than silently-wrong, but still worth confirming
 * against the chart before relying on downstream mTLS in production.
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
