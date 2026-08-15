package net.hugmesh.gateway.config;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.webclient.WebClientCustomizer;
import org.springframework.cloud.gateway.config.HttpClientCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

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
    public SslContext downstreamMtlsSslContext(DownstreamMtlsProperties props) throws Exception {
        SslContext ctx = buildClientSslContext(props);
        log.info("Downstream mTLS ENABLED: gateway will present client cert from {} and validate "
                        + "backend server certs against {}",
                props.getKeyStore(), props.getTrustStore());
        return ctx;
    }

    @Bean
    public HttpClientCustomizer downstreamMtlsHttpClientCustomizer(SslContext downstreamMtlsSslContext) {
        return httpClient -> httpClient.secure(spec -> spec.sslContext(downstreamMtlsSslContext));
    }

    /**
     * The SAME SslContext, applied to every {@link WebClient} built from Boot's
     * auto-configured {@link WebClient.Builder}.
     *
     * <p><b>Why this is a SEPARATE bean and not covered by the one above.</b>
     * {@link HttpClientCustomizer} is a <em>Spring Cloud Gateway</em> interface;
     * SCG's {@code HttpClientFactory} applies it to the shared HttpClient that
     * forwards ROUTED traffic. Boot's {@code WebClient.Builder} knows nothing about
     * it — it consults {@link WebClientCustomizer} beans instead. So a WebClient
     * built from the auto-configured builder got the DEFAULT JDK trust, which holds
     * public roots and never the cluster CA.
     *
     * <p>{@code BffSessionConfig.bffIntrospectWebClient} is exactly such a client,
     * and its javadoc asserted the opposite — "customized by e.g. DownstreamMtlsConfig
     * when mTLS is enabled". That sentence was false, and it is the reason the session
     * bridge could not work against a TLS backend. Live on kind 2026-08-06, after the
     * generator fixed BFF_BASE_URL from http:// to https://, the failure moved from
     *
     *     Connection prematurely closed BEFORE response          (plaintext into a TLS port)
     * to
     *     (certificate_unknown) PKIX path building failed        (TLS, but default trust)
     *
     * and every /bff/session read still answered 503
     * {@code {"error":"session_backend_unavailable"}} for a freshly minted, valid
     * session. Both errors are this one bean's absence.
     *
     * <p>Safe for plain-http peers: a reactor-netty SslContext engages only for
     * {@code https://} URLs, so WebClients addressing http:// backends are unaffected.
     */
    @Bean
    public WebClientCustomizer downstreamMtlsWebClientCustomizer(SslContext downstreamMtlsSslContext) {
        return builder -> builder.clientConnector(new ReactorClientHttpConnector(
                HttpClient.create().secure(spec -> spec.sslContext(downstreamMtlsSslContext))));
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
