package systems.hugmesh.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.Ordered;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Cookie-mode bridge: synthesise an {@code Authorization: Bearer bff_…} header from the
 * {@code bff_session} cookie so a pure cookie-mode browser request can be picked up by
 * the {@link BffJwtExchangeWebFilter} (which inspects the {@code Authorization} header
 * ONLY). A browser holds the opaque {@code bff_} session as an {@code httpOnly} cookie
 * that JavaScript cannot read, so the SPA cannot place it in an {@code Authorization}
 * header itself — without this synth the exchange filter never fires for a cookie-only
 * request and the bff_ session would 401 at the JWT decoder downstream.
 *
 * <p><b>Ordering — runs BEFORE the exchange filter.</b> {@link #getOrder()} is
 * {@code HIGHEST_PRECEDENCE + 4}, one slot ahead of
 * {@link BffJwtExchangeWebFilter#getOrder()} ({@code +5}). Flow for a cookie-only request:
 * <ol>
 *   <li>{@code +4} (this filter): {@code Cookie: bff_session=bff_…} → set
 *       {@code Authorization: Bearer bff_…} on the mutated request;</li>
 *   <li>{@code +5} ({@link BffJwtExchangeWebFilter}): swaps the {@code bff_} bearer for the
 *       internal custody JWT;</li>
 *   <li>the resource server validates the swapped-in JWT, exactly as for a header-carried
 *       bff_ (the legacy programmatic / Angular-in-memory carrier).</li>
 * </ol>
 *
 * <p><b>Header wins.</b> If the request already carries an {@code Authorization} header
 * (a real Casdoor JWT, an in-memory bff_ bearer, or anything else) this filter is a no-op
 * — it never overwrites a client-sent credential, so the legacy header path is
 * byte-identical. It only acts when there is NO Authorization header AND a {@code bff_}
 * value is present in the {@code bff_session} cookie.
 *
 * <p><b>Ships dark with the exchange.</b> Gated behind the SAME
 * {@code hugmesh.gateway.bff-exchange.enabled} flag as {@link BffJwtExchangeWebFilter}
 * — with the flag unset this bean is absent and the chain is byte-identical to today
 * (cookie-mode bff_ has no swap path, so it 401s as before). Synthesising the header is
 * only meaningful when there is a swap filter behind it to consume it.
 */
@Component
@ConditionalOnProperty(name = "hugmesh.gateway.bff-exchange.enabled", havingValue = "true")
public class BffCookieToBearerWebFilter implements WebFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(BffCookieToBearerWebFilter.class);

    /** Cookie name the cookie-terminating BFF mints (mirrors {@link BffSessionAuthFilter#SESSION_COOKIE}). */
    static final String SESSION_COOKIE = "bff_session";

    /** Opaque-session bearer prefix (mirrors {@link BffJwtExchangeWebFilter}). */
    private static final String BFF_PREFIX = "bff_";

    public BffCookieToBearerWebFilter() {
        log.info("[bff-cookie-bridge] ENABLED — synthesising Authorization from {} cookie for cookie-mode SSO",
                SESSION_COOKIE);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        // Never overwrite a client-sent Authorization header — the legacy header path is untouched.
        String existing = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (existing != null && !existing.isBlank()) {
            return chain.filter(exchange);
        }
        HttpCookie cookie = exchange.getRequest().getCookies().getFirst(SESSION_COOKIE);
        if (cookie == null || cookie.getValue() == null || !cookie.getValue().startsWith(BFF_PREFIX)) {
            // No bff_ session cookie — nothing to synthesise; flows exactly as today.
            return chain.filter(exchange);
        }
        String token = cookie.getValue();
        // Synthesise the bearer AND CONSUME the bff_session cookie from the forwarded request.
        // Consuming it is load-bearing: with bff-exchange ON, the swap filter ({@link
        // BffJwtExchangeWebFilter}) turns this bearer into a custody JWT and the resource server
        // installs a JwtAuthenticationToken. If we LEFT the cookie in place, the sibling
        // BffSessionAuthFilter would ALSO resolve it (via introspect) into a NON-JWT
        // UsernamePasswordAuthenticationToken that pre-empts the JWT context — and the downstream
        // JWT-expecting authorizers (GatewayRouteAccessFilter privileged-floor / ResourceAccessFilter)
        // would then see no JWT and 401. One carrier, one identity: the custody-JWT path.
        String strippedCookies = cookieHeaderWithout(exchange, SESSION_COOKIE);
        log.debug("[bff-cookie-bridge] synthesising bearer + consuming {} cookie for path={}",
                SESSION_COOKIE, exchange.getRequest().getPath().value());
        ServerWebExchange mutated = exchange.mutate()
                .request(b -> b.headers(h -> {
                    h.set(HttpHeaders.AUTHORIZATION, "Bearer " + token);
                    if (strippedCookies == null) {
                        h.remove(HttpHeaders.COOKIE);
                    } else {
                        h.set(HttpHeaders.COOKIE, strippedCookies);
                    }
                }))
                .build();
        return chain.filter(mutated);
    }

    /**
     * Rebuild the inbound {@code Cookie} header with the named cookie removed (other cookies —
     * e.g. a CSRF token — are preserved). Returns {@code null} when no cookies remain so the
     * caller can drop the header entirely.
     */
    private static String cookieHeaderWithout(ServerWebExchange exchange, String name) {
        java.util.List<String> headers = exchange.getRequest().getHeaders().get(HttpHeaders.COOKIE);
        if (headers == null || headers.isEmpty()) {
            return null;
        }
        String prefix = name + "=";
        String kept = headers.stream()
                .flatMap(h -> java.util.Arrays.stream(h.split(";")))
                .map(String::trim)
                .filter(pair -> !pair.isEmpty() && !pair.startsWith(prefix))
                .reduce((a, b) -> a + "; " + b)
                .orElse(null);
        return (kept == null || kept.isBlank()) ? null : kept;
    }

    @Override
    public int getOrder() {
        // One slot AHEAD of BffJwtExchangeWebFilter (HIGHEST_PRECEDENCE + 5) so the
        // synthesised Authorization header exists by the time the swap filter inspects it,
        // and BEFORE Spring Security's WebFilterChainProxy (-100) like the swap filter.
        return HIGHEST_PRECEDENCE + 4;
    }
}
