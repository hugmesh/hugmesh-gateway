package net.hugmesh.gateway.config;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.gateway.config.HttpClientCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;

/**
 * DOWNSTREAM (gateway -> API) mutual-TLS client identity for the proxy leg.
 *
 * <p>When the in-cluster backends enforce mTLS ({@code server.ssl.client-auth=need},
 * wired by the hugmesh-generator deployment manifests), the gateway must (a)
 * PRESENT a client certificate that chains to the cluster CA and (b) VALIDATE the
 * backend server certificate against that same CA. This config builds a
 * reactor-netty {@link SslContext} from the in-pod-assembled PKCS12 stores — the
 * SAME {@code /stores/keystore.p12} (this gateway's Vault-PKI identity) +
 * {@code /stores/truststore.p12} (cluster CA) that the chart's {@code build-keystore}
 * initContainer produces — and registers an {@link HttpClientCustomizer} so the
 * gateway's reactor-netty {@code HttpClient} uses it on every downstream call.
 *
 * <p><b>GATED OFF BY DEFAULT.</b> The whole config (and any filesystem access) is
 * {@link ConditionalOnProperty @ConditionalOnProperty} on
 * {@code hugmesh.gateway.mtls.enabled=true}. With the property unset (local,
 * dev, CI, and the unit smoke test) nothing here is created, the stores are never
 * opened, and the gateway proxies plain {@code http://} backends exactly as before.
 * In-cluster, the be/fe-gateway ArgoCD apps set {@code HUGMESH_GATEWAY_MTLS_ENABLED=true}.
 *
 * <p><b>UPSTREAM (public) callers are unaffected.</b> This only configures the
 * gateway's OUTBOUND HttpClient. Browsers / Cloudflare reaching the gateway are
 * NOT asked for a client cert — the inbound server side is untouched here.
 *
 * <p>The store passwords are NOT in git or the pod spec: the initContainer writes
 * them into {@code /stores/application-tls.properties} (loaded via
 * {@code SPRING_CONFIG_ADDITIONAL_LOCATION=file:/stores/}) as
 * {@code hugmesh.tls.key-store-password} / {@code hugmesh.tls.trust-store-password},
 * which bind to the fields below.
 */
@Configuration
@ConditionalOnProperty(name = "hugmesh.gateway.mtls.enabled", havingValue = "true")
@EnableConfigurationProperties(DownstreamMtlsProperties.class)
public class DownstreamMtlsConfig {

    private static final Logger log = LoggerFactory.getLogger(DownstreamMtlsConfig.class);

    /**
     * Build the downstream client {@link SslContext} (client identity keystore +
     * cluster-CA truststore) and apply it to the gateway's reactor-netty HttpClient.
     *
     * <p>Registered as an {@link HttpClientCustomizer} bean — Spring Cloud Gateway's
     * {@code HttpClientFactory} applies every such bean to the shared HttpClient,
     * so this is the supported hook for customizing the proxy leg's TLS.
     *
     * @param props the (gated) mTLS store coordinates, bound from {@code hugmesh.tls.*}
     * @return a customizer that calls {@code .secure(spec -> spec.sslContext(ctx))}
     * @throws Exception if the stores cannot be read/loaded — fail fast, never fall
     *                   back to plaintext or an insecure trust manager
     */
    @Bean
    public HttpClientCustomizer downstreamMtlsHttpClientCustomizer(DownstreamMtlsProperties props) throws Exception {
        final SslContext sslContext = buildClientSslContext(props);
        log.info("Downstream mTLS ENABLED: gateway will present client cert from {} and validate "
                        + "backend server certs against {}",
                props.getKeyStore(), props.getTrustStore());
        return httpClient -> httpClient.secure(spec -> spec.sslContext(sslContext));
    }

    /** Assemble a Netty client SslContext: keyManager = identity, trustManager = cluster CA. */
    private SslContext buildClientSslContext(DownstreamMtlsProperties p) throws Exception {
        // Client IDENTITY — the cert/key the gateway PRESENTS to mTLS backends.
        KeyStore keyStore = load(p.getKeyStore(), p.getKeyStoreType(), p.getKeyStorePassword());
        KeyManagerFactory kmf =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        char[] kpw = chars(p.getKeyStorePassword());
        kmf.init(keyStore, kpw);

        // TRUST — the cluster CA we validate backend server certs against.
        KeyStore trustStore = load(p.getTrustStore(), p.getTrustStoreType(), p.getTrustStorePassword());
        TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        return SslContextBuilder.forClient()
                .keyManager(kmf)
                .trustManager(tmf)
                .build();
    }

    private static KeyStore load(String location, String type, String password) throws Exception {
        Path path = Path.of(location);
        if (!Files.isReadable(path)) {
            throw new IllegalStateException(
                    "hugmesh.gateway.mtls.enabled=true but the store is not readable: " + location
                            + " (expected the build-keystore initContainer to have assembled it into /stores)");
        }
        KeyStore ks = KeyStore.getInstance(type);
        try (InputStream in = Files.newInputStream(path)) {
            ks.load(in, chars(password));
        }
        return ks;
    }

    private static char[] chars(String s) {
        return s == null ? new char[0] : s.toCharArray();
    }
}
