package net.hugmesh.gateway.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;
import net.hugmesh.gateway.filter.BffSessionAuthFilter;

/**
 * Wires the {@link BffSessionAuthFilter} and its dedicated {@link WebClient}
 * when the BFF session bridge is enabled.
 *
 * <p>The entire configuration (properties binding, WebClient, filter bean) is
 * gated by {@code @ConditionalOnProperty} on {@code app.bff-session.enabled=true}.
 * {@code application.yml} resolves this to {@code true} by default
 * ({@code APP_BFF_SESSION_ENABLED:true}, PR #70), so this bridge is LIVE unless
 * explicitly disabled; only with {@code APP_BFF_SESSION_ENABLED=false} is nothing
 * here created and the gateway falls back to the JWT-only resource-server path.
 *
 * <p>A DEDICATED {@link WebClient} is created for the introspection calls so its
 * base URL, timeout (set at the call site via {@code .timeout(...)}) and codec
 * configuration are isolated from the gateway's shared routing client and from the
 * standard {@link WebClient.Builder} auto-configuration bean. This prevents an
 * operator accidentally changing the shared builder's base URL from affecting the
 * introspection leg.
 */
@Configuration
@ConditionalOnProperty(name = "app.bff-session.enabled", havingValue = "true")
@EnableConfigurationProperties(BffSessionProperties.class)
public class BffSessionConfig {

    /**
     * Dedicated WebClient for BFF introspection calls.
     *
     * <p>Uses the auto-configured {@link WebClient.Builder} as the starting point
     * (inheriting any reactor-netty TLS / codec customizations already applied by
     * Boot) but sets the base URL from {@link BffSessionProperties#getBffBaseUrl()}.
     *
     * <p>The mTLS leg reaches this client through {@code DownstreamMtlsConfig}'s
     * {@code WebClientCustomizer} — NOT its {@code HttpClientCustomizer}, which is a
     * Spring Cloud Gateway hook that only touches the routed-proxy HttpClient. This
     * javadoc previously claimed the builder was "customized by DownstreamMtlsConfig",
     * which was false: no such customizer existed for WebClients, so this client used
     * the JDK default trust and every introspection call against a TLS backend failed
     * with PKIX path building failed → 503 session_backend_unavailable.
     *
     * @param builder the Spring Boot auto-configured builder
     * @param props   the BFF session properties
     * @return a fully configured WebClient ready to call {@code /bff/me}
     */
    @Bean("bffIntrospectWebClient")
    WebClient bffIntrospectWebClient(WebClient.Builder builder,
                                     BffSessionProperties props) {
        return builder
                .baseUrl(props.getBffBaseUrl())
                .build();
    }

    /**
     * The BFF session introspection filter bean.
     *
     * <p>Registered with order {@code HIGHEST_PRECEDENCE + 50} — before the OAuth2
     * resource server's {@code BearerTokenAuthenticationWebFilter} (AUTHENTICATION
     * slot) so that when a {@code bff_} token is present the
     * {@code ReactiveSecurityContextHolder} is already populated before the JWT
     * filter runs its own authentication attempt. The JWT filter then finds an
     * existing authentication and short-circuits.
     *
     * @param bffIntrospectWebClient the dedicated introspection WebClient
     * @param props                  the BFF session properties
     * @return the configured filter
     */
    @Bean
    BffSessionAuthFilter bffSessionAuthFilter(
            WebClient bffIntrospectWebClient,
            BffSessionProperties props) {
        return new BffSessionAuthFilter(bffIntrospectWebClient, props);
    }
}
