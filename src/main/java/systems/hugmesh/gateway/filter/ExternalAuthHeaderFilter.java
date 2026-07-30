package systems.hugmesh.gateway.filter;

import org.springframework.core.Ordered;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * If the incoming request carries an external-OAuth token (GitHub /
 * Google / etc.) in addition to the internal Casdoor JWT — OR if the
 * request is authenticated purely via an external provider — append
 * normalized {@code External-Authorization} + {@code External-Auth-Provider}
 * + {@code External-Auth-Id} headers so downstream services see the
 * outside identity without each having to re-decode the token.
 *
 * <p>Two source channels:
 *
 * <ol>
 *   <li>Custom {@code X-External-Token} + {@code X-External-Provider}
 *       request headers — the federated registration remote forwards
 *       the user's external OAuth credentials this way after a sign-up
 *       handshake.</li>
 *   <li>Casdoor JWT claims — when Casdoor proxies a GitHub login it
 *       embeds the upstream provider name in {@code identityProvider}
 *       and the external user id in {@code identityProviderUserId};
 *       the gateway mirrors those into the External-* headers so
 *       downstreams have one place to look.</li>
 * </ol>
 *
 * <p>The {@code External-Authorization} value is the SAME opaque
 * external token the gateway received — downstreams use it to call
 * the external provider directly (e.g. GitHub's /user/repos endpoint
 * to enumerate the user's repositories at sign-up time, per the org-
 * admin auto-grant flow).
 *
 * <p><b>Trust boundary (channel 1).</b> {@code X-External-Token} /
 * {@code X-External-Provider} are CLIENT-SUPPLIED request headers — anyone
 * who can reach the gateway can set them. They are therefore honoured ONLY
 * when the request also carries a cryptographically-validated Casdoor JWT
 * whose {@code identityProvider} claim MATCHES the supplied
 * {@code X-External-Provider} (case-insensitive). That binds the forwarded
 * external token to the same upstream OAuth identity Casdoor already minted
 * the JWT through, so an attacker cannot smuggle an arbitrary
 * {@code External-Authorization} for a provider/identity that isn't theirs.
 * Unauthenticated requests, requests whose JWT was not minted via an external
 * provider, and requests whose {@code X-External-Provider} disagrees with the
 * JWT's {@code identityProvider} get the inbound X-* headers DROPPED (never
 * forwarded). Channel 2 (the JWT claims themselves) is already trusted because
 * it derives from the validated token, so it is unaffected.
 */
@Component
public class ExternalAuthHeaderFilter implements WebFilter, Ordered {

    private static final String X_EXT_TOKEN    = "X-External-Token";
    private static final String X_EXT_PROVIDER = "X-External-Provider";

    private static final String OUT_AUTH     = "External-Authorization";
    private static final String OUT_PROVIDER = "External-Auth-Provider";
    private static final String OUT_ID       = "External-Auth-Id";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        // CLIENT-SUPPLIED — untrusted until proven bound to a validated JWT below.
        String rawExternalToken    = exchange.getRequest().getHeaders().getFirst(X_EXT_TOKEN);
        String rawExternalProvider = exchange.getRequest().getHeaders().getFirst(X_EXT_PROVIDER);

        // Resolve the exchange we will forward, then forward it EXACTLY ONCE.
        // (Computing the exchange separately from forwarding avoids the
        // switchIfEmpty-on-a-Void-chain double-invocation footgun: chain.filter
        // returns an empty Mono<Void>, so a switchIfEmpty wrapped directly around
        // it would fire a second time.)
        return exchange.getPrincipal()
            .cast(AbstractAuthenticationToken.class)
            .map(auth -> {
                String claimProvider = null;
                String claimId       = null;
                if (auth.getPrincipal() instanceof Jwt jwt) {
                    // Casdoor claims (identityProvider + identityProviderUserId)
                    // when the JWT was minted via an upstream OAuth provider.
                    Object cp = jwt.getClaim("identityProvider");
                    Object ci = jwt.getClaim("identityProviderUserId");
                    if (cp != null) claimProvider = cp.toString();
                    if (ci != null) claimId       = ci.toString();
                }

                // Channel 1 (client-supplied X-* headers) is honoured ONLY when it
                // is BOUND to the validated JWT: the JWT must itself have been minted
                // via an external provider AND that provider must match the supplied
                // X-External-Provider (case-insensitive). Otherwise the inbound token
                // is a forgery attempt and is DROPPED, never forwarded. This prevents
                // header injection of an arbitrary External-Authorization identity.
                boolean headerBound =
                        rawExternalProvider != null
                        && claimProvider != null
                        && rawExternalProvider.equalsIgnoreCase(claimProvider);

                final String token = headerBound ? rawExternalToken : null;
                // Provider/id are sourced from the VALIDATED JWT claims — never from
                // the raw header — so a forged X-External-Provider can neither
                // override the claim nor stand on its own.
                final String provider   = claimProvider;
                final String externalId = claimId;

                if (token == null && provider == null && externalId == null) {
                    // No (trusted) external auth involved. Still strip any inbound
                    // X-* and forged canonical External-* headers so they can never
                    // leak downstream.
                    return stripInbound(exchange);
                }

                return exchange.mutate()
                    .request(b -> {
                        // The gateway is the SOLE authority on the canonical
                        // External-* headers: drop any client-supplied copies first
                        // (an attacker can otherwise inject these output names
                        // directly), then stamp only the gateway-derived values.
                        b.headers(h -> {
                            h.remove(X_EXT_TOKEN);
                            h.remove(X_EXT_PROVIDER);
                            h.remove(OUT_AUTH);
                            h.remove(OUT_PROVIDER);
                            h.remove(OUT_ID);
                        });
                        if (token       != null) b.header(OUT_AUTH,     token);
                        if (provider    != null) b.header(OUT_PROVIDER, provider);
                        if (externalId  != null) b.header(OUT_ID,       externalId);
                    })
                    .build();
            })
            // Unauthenticated traffic: no JWT to bind the X-* headers to, so they
            // are untrusted by definition — strip them (and any forged canonical
            // External-* headers) before forwarding so a downstream can never
            // receive an attacker-forged External-* identity.
            .defaultIfEmpty(stripInbound(exchange))
            .flatMap(chain::filter);
    }

    /** Drop any client-supplied X-External-* AND canonical External-* headers so
     *  they never reach a downstream (or the revocation filter) that would
     *  otherwise trust them as a gateway-stamped identity. */
    private static ServerWebExchange stripInbound(ServerWebExchange exchange) {
        var headers = exchange.getRequest().getHeaders();
        if (headers.getFirst(X_EXT_TOKEN) == null
                && headers.getFirst(X_EXT_PROVIDER) == null
                && headers.getFirst(OUT_AUTH) == null
                && headers.getFirst(OUT_PROVIDER) == null
                && headers.getFirst(OUT_ID) == null) {
            return exchange;
        }
        return exchange.mutate()
                .request(b -> b.headers(h -> {
                    h.remove(X_EXT_TOKEN);
                    h.remove(X_EXT_PROVIDER);
                    h.remove(OUT_AUTH);
                    h.remove(OUT_PROVIDER);
                    h.remove(OUT_ID);
                }))
                .build();
    }

    @Override
    public int getOrder() {
        // Run AFTER Spring Security's WebFilterChainProxy (order -100) so
        // exchange.getPrincipal() resolves — see the ordering note on
        // RevocationGatewayFilter#getOrder. A positive order keeps this filter after
        // the security chain (principal visible to bind the X-* headers to the
        // validated JWT) and after the revocation filter (10) so a revoked external
        // identity is rejected first, but before the routing filter so the downstream
        // sees the appended headers.
        return 20;
    }
}
