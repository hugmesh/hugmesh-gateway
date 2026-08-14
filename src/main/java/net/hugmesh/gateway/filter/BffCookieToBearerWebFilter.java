package net.hugmesh.gateway.filter;

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
        // Synthesise the bearer and KEEP the bff_session cookie on the forwarded request.
        //
        // An earlier revision CONSUMED the cookie here ("one carrier, one identity"),
        // reasoning that the sibling BffSessionAuthFilter would otherwise resolve the
        // cookie into a second, non-JWT identity. It cannot: with bff-exchange ON the
        // Authorization header carries the swapped-in custody JWT by the time that
        // filter runs (bridge +4 -> swap +5 -> session filter +50), and its
        // extractToken() consults the Authorization header FIRST and skips outright on
        // a non-bff_ value — the cookie is never consulted. So consumption bought
        // nothing gateway-side, while DOWNSTREAM it starved every cookie-terminated
        // BFF surface: user-bff's GET /bff/session (permitAll, cookie-read at the app
        // layer — the login-ui hydrate path) answered 401 "no session" for every
        // logged-in browser, so onboarding hung at the register/nav race and the
        // whole UI e2e family failed. Verified live 2026-08-13: front door
        // /bff/session 401 with the cookie consumed; user-bff direct with the same
        // cookie 200. The custody JWT still replaces the bearer for the pure JWT
        // resource servers (forum/wiki/tube/owncast/forge) — both carriers describe
        // the SAME session, minted seconds apart from the same introspection.
        log.debug("[bff-cookie-bridge] synthesising bearer (cookie retained) for path={}",
                exchange.getRequest().getPath().value());
        ServerWebExchange mutated = exchange.mutate()
                .request(b -> b.headers(h -> h.set(HttpHeaders.AUTHORIZATION, "Bearer " + token)))
                .build();
        return chain.filter(mutated);
    }

    @Override
    public int getOrder() {
        // One slot AHEAD of BffJwtExchangeWebFilter (HIGHEST_PRECEDENCE + 5) so the
        // synthesised Authorization header exists by the time the swap filter inspects it,
        // and BEFORE Spring Security's WebFilterChainProxy (-100) like the swap filter.
        return HIGHEST_PRECEDENCE + 4;
    }
}
