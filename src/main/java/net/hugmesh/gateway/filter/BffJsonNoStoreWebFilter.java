package net.hugmesh.gateway.filter;

import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * DEFENSE-IN-DEPTH: force {@code Cache-Control: no-store} on every {@code /bff/**}
 * JSON response that crosses this gateway, INCLUDING responses whose upstream set a
 * weaker policy of its own.
 *
 * <p><b>Why the Spring Security default is not enough.</b> Spring Security's
 * {@code CacheControlServerHttpHeadersWriter} (kept enabled in
 * {@link net.hugmesh.gateway.config.SecurityConfig}) only writes its
 * {@code no-cache, no-store, …} trio when the response carries NO cache header at
 * all — an upstream BFF that explicitly opts into caching sails through untouched.
 * That is exactly how the 2026-08-19 operator report ("need to clear cache every
 * time after log out") escaped: an owner-scoped byte serve sent
 * {@code private, max-age=300} on a URL that is the SAME for every user, and the
 * browser HTTP cache — which is keyed by URL alone, does not vary on the session
 * cookie, and is not emptied by sign-out — kept serving the PREVIOUS user's
 * response after logout, across full page reloads, until the operator manually
 * cleared the cache. The offending route is fixed at its owner
 * (hugmesh-user-bff-api), and this filter pins the invariant at the single
 * choke-point every brand and every lane (compose test stack + cluster) shares, so
 * no future BFF endpoint can quietly reintroduce the class.
 *
 * <p><b>Scope: {@code /bff/**} responses with a JSON content type</b>
 * ({@code application/json} and any {@code *+json} variant — the session/identity/
 * role surfaces a browser could replay into a signed-out or account-switched UI).
 * Non-JSON {@code /bff} bodies (image serves, SSE streams, binary exports) keep
 * their upstream's header: media cacheability is the OWNING BFF's decision — a
 * blanket override here would strip legitimate caching from high-traffic proxied
 * media (e.g. the Matrix/Mastodon hsproxy thumbnails) and is deliberately NOT done.
 * Other paths ({@code /_fragments/**} content-addressed immutable bundles, remote
 * UI assets, homeserver passthrough) are untouched.
 *
 * <p>The forced value is byte-identical to Spring Security's default trio
 * ({@code Cache-Control} + {@code Pragma} + {@code Expires}), so a hardened
 * response is indistinguishable from the platform's default posture and the
 * override is idempotent regardless of filter/writer ordering — whichever of the
 * two runs last leaves the same bytes.
 *
 * <p>Implemented as a {@link ServerHttpResponse#beforeCommit(java.util.function.Supplier)}
 * hook rather than an inline header write: for PROXIED responses the upstream's
 * headers are copied onto this response long after the WebFilter chain's inbound
 * pass, so only a commit-time hook sees (and can win over) the upstream value.
 */
@Component
public class BffJsonNoStoreWebFilter implements WebFilter, Ordered {

    /** The {@code /bff} namespace — every BFF surface the SPA session rides on. */
    private static final String BFF_PREFIX = "/bff/";

    /** Spring Security's default cache-bust trio (byte-identical, see class doc). */
    static final String CACHE_CONTROL_VALUE = "no-cache, no-store, max-age=0, must-revalidate";
    static final String PRAGMA_VALUE = "no-cache";
    static final String EXPIRES_VALUE = "0";

    @Override
    public int getOrder() {
        // Ordering is NOT load-bearing (see class doc: the forced value is identical
        // to the security writer's, so last-writer-wins is idempotent); registered
        // early only so the beforeCommit hook exists for every downstream outcome,
        // including security-chain 401/403 short-circuits.
        return Ordered.HIGHEST_PRECEDENCE + 3;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getURI().getRawPath();
        if (path.startsWith(BFF_PREFIX)) {
            ServerHttpResponse response = exchange.getResponse();
            response.beforeCommit(() -> {
                HttpHeaders headers = response.getHeaders();
                if (isJson(headers.getContentType())) {
                    headers.set(HttpHeaders.CACHE_CONTROL, CACHE_CONTROL_VALUE);
                    headers.set(HttpHeaders.PRAGMA, PRAGMA_VALUE);
                    headers.set(HttpHeaders.EXPIRES, EXPIRES_VALUE);
                }
                return Mono.empty();
            });
        }
        return chain.filter(exchange);
    }

    /** {@code application/json} or any {@code *+json} structured-syntax variant
     *  (problem+json, hal+json, …). A null content type (headerless 401s and other
     *  bodyless short-circuits) is NOT treated as JSON — those responses already get
     *  the identical trio from the kept Spring Security defaults. */
    private static boolean isJson(MediaType contentType) {
        if (contentType == null) {
            return false;
        }
        return MediaType.APPLICATION_JSON.isCompatibleWith(contentType)
                || contentType.getSubtype().endsWith("+json");
    }
}
