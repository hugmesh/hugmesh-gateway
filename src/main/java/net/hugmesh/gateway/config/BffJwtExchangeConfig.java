package net.hugmesh.gateway.config;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
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
 * Builds the back-channel {@link WebClient} the {@link
 * net.hugmesh.gateway.filter.BffJwtExchangeWebFilter} uses to swap an opaque
 * {@code bff_} session for an internal custody JWT against the admin-bff
 * ({@code POST /bff/internal/session/exchange}).
 *
 * <p><b>GATED OFF BY DEFAULT.</b> The whole config (and the WebClient bean) is
 * {@link ConditionalOnProperty @ConditionalOnProperty} on
 * {@code hugmesh.gateway.bff-exchange.enabled=true} — the SAME flag the filter is
 * gated on, so with the flag unset NEITHER the filter NOR its WebClient exist and the
 * chain is byte-identical to today.
 *
 * <p><b>mTLS reuse.</b> The admin-bff exchange endpoint requires the gateway to present
 * the cluster-CA client identity AND stamp the {@code X-Internal-Token} header (its
 * {@code InternalTokenWebFilter} fails closed otherwise). When
 * {@code hugmesh.gateway.mtls.enabled=true} this builds the WebClient on a
 * reactor-netty {@link HttpClient} secured by the SAME {@code /stores} client-cert
 * {@link SslContext} pattern as {@link DownstreamMtlsConfig} — bound from the same
 * {@code hugmesh.tls.*} {@link DownstreamMtlsProperties} so the cert path can never
 * diverge between the proxy leg and this back-channel. With mTLS off (local/dev/CI) the
 * WebClient uses the default connector (plain {@code http://}), exactly like the proxy
 * leg, so the unit gate needs no stores.
 */
@Configuration
@ConditionalOnProperty(name = "hugmesh.gateway.bff-exchange.enabled", havingValue = "true")
@EnableConfigurationProperties(DownstreamMtlsProperties.class)
public class BffJwtExchangeConfig {

    private static final Logger log = LoggerFactory.getLogger(BffJwtExchangeConfig.class);

    /** Base URI of the admin-bff (the custody-swap target). */
    private final String adminBffUri;
    /** Whether the gateway-&gt;admin-bff back-channel must present a client cert. Reuses
     *  the existing dark {@code hugmesh.gateway.mtls.enabled} flag so the back-channel
     *  and the proxy leg are mTLS-secured together (never one without the other). */
    private final boolean mtlsEnabled;

    public BffJwtExchangeConfig(
            @Value("${hugmesh.gateway.bff-exchange.admin-bff-uri:http://admin-bff:8080}")
                    String adminBffUri,
            @Value("${hugmesh.gateway.mtls.enabled:false}") boolean mtlsEnabled) {
        this.adminBffUri = adminBffUri;
        this.mtlsEnabled = mtlsEnabled;
    }

    /**
     * The custody-swap {@link WebClient}. When mTLS is enabled it is built on a
     * reactor-netty {@link HttpClient} secured with the cluster-CA client identity
     * (same stores as {@link DownstreamMtlsConfig}); otherwise it uses the default
     * connector. The {@code X-Internal-Token} header + request timeout are stamped by
     * the filter on each call (it owns the per-request shape).
     *
     * @param props the (shared) mTLS store coordinates, bound from {@code hugmesh.tls.*}
     * @throws Exception if mTLS is enabled but the stores cannot be read/loaded — fail
     *                   fast, never fall back to plaintext on a back-channel that
     *                   carries a session-exchanging internal token
     */
    @Bean
    public WebClient bffExchangeWebClient(DownstreamMtlsProperties props) throws Exception {
        WebClient.Builder builder = WebClient.builder().baseUrl(adminBffUri);
        if (mtlsEnabled) {
            SslContext sslContext = buildClientSslContext(props);
            HttpClient httpClient = HttpClient.create().secure(spec -> spec.sslContext(sslContext));
            builder.clientConnector(new ReactorClientHttpConnector(httpClient));
            log.info("[bff-exchange] WebClient -> {} with mTLS client cert from {} (validated against {})",
                    adminBffUri, props.getKeyStore(), props.getTrustStore());
        } else {
            log.info("[bff-exchange] WebClient -> {} WITHOUT mTLS (hugmesh.gateway.mtls.enabled=false)",
                    adminBffUri);
        }
        return builder.build();
    }

    /** Assemble a Netty client SslContext: keyManager = gateway identity, trustManager =
     *  cluster CA. Identical assembly to {@link DownstreamMtlsConfig} (kept local rather
     *  than shared to avoid coupling this dark config to the dark mTLS config's bean
     *  graph — both read the SAME {@code hugmesh.tls.*} properties, so the cert paths
     *  cannot diverge). */
    private SslContext buildClientSslContext(DownstreamMtlsProperties p) throws Exception {
        KeyStore keyStore = load(p.getKeyStore(), p.getKeyStoreType(), p.getKeyStorePassword());
        KeyManagerFactory kmf =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, chars(p.getKeyStorePassword()));

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
                    "hugmesh.gateway.bff-exchange.enabled + mtls.enabled=true but the store is not "
                            + "readable: " + location
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
