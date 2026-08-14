package net.hugmesh.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Pre-security {@code bff_} → custody-JWT exchange (the SSO opaque-session bridge).
 * The browser only ever holds an opaque {@code bff_}-prefixed session bearer (minted
 * by the cookie-terminating admin-bff); the internal Casdoor custody JWT never leaves
 * the mesh. This filter swaps an inbound {@code Authorization: Bearer bff_…} for the
 * custody JWT — by asking the admin-bff over an mTLS+internal-token back-channel — so
 * the gateway's JWT-only OAuth2 resource server (which cannot validate an opaque
 * {@code bff_} value) sees a real JWT and the rest of the (unchanged) authz chain
 * proceeds exactly as for a native-JWT caller.
 *
 * <p><b>Header-only, runs BEFORE Spring Security.</b> Unlike the five principal-reading
 * sibling gateway filters (which deliberately run at POSITIVE orders, AFTER
 * {@code WebFilterChainProxy(-100)}, because they need a populated {@code SecurityContext}
 * — see {@link RevocationGatewayFilter#getOrder()}), this filter inspects and rewrites
 * the raw {@code Authorization} header ONLY. It must run BEFORE the resource server's
 * JWT decoder so the decoder validates the swapped-in custody JWT, never the opaque
 * {@code bff_} value. See {@link #getOrder()} for the load-bearing ordering rationale.
 *
 * <p><b>Fail-CLOSED.</b> On ANY exchange failure (admin-bff non-2xx, timeout, empty
 * body, WebClient exception) the request is short-circuited with {@code 401} and the
 * {@code Authorization} header is overwritten so the raw {@code bff_} can NEVER leak
 * downstream or reach the JWT decoder. The error path maps to a 401 {@code Mono<Void>}
 * — it never resolves to {@code chain.filter(...)} (that would forward the raw bff_ and
 * is the fail-OPEN regression this filter exists to avoid).
 *
 * <p><b>Cache (and the suspension-staleness window it bounds).</b> A successful swap is
 * cached for ≤TTL keyed on {@code sha256(bff_)} (never the raw value), bounded by
 * {@code maximumSize}, so a burst of requests on the same session does not stampede the
 * admin-bff. <b>NEGATIVE/failed swaps are NEVER cached</b> — a transient admin-bff blip
 * must not pin a session to 401 for the rest of the TTL, and an attacker cannot poison the
 * cache by forcing a failure.
 *
 * <p><b>The TTL IS the suspension-bypass window.</b> admin-bff's {@code /session/exchange}
 * carries the fail-closed suspension gate (a suspended/banned account's swap is refused
 * 403) — but a CACHE HIT skips that round-trip, so a session suspended AFTER its swap was
 * cached keeps authorizing until the entry expires. The TTL therefore bounds the staleness
 * of a just-suspended session, so the default is a small {@code 5000}ms (≈ the cluster's
 * revocation poll cadence) rather than the old 60s, which left a full minute of bypass. The
 * value is clamped to a 60s hard ceiling. Set {@code cache-ttl-ms} to {@code 0} (or any
 * non-positive value) to DISABLE the positive cache entirely — every request then
 * re-consults the admin-bff exchange gate, giving a ZERO suspension-bypass window at the
 * cost of one in-cluster swap call per request (ban-critical deployments).
 *
 * <p>The perf-preserving alternative for production is to have the admin-bff suspend path
 * write a {@code subject:<custody-sub>} key to the gateway {@code RevocationListService} so
 * {@code RevocationGatewayFilter} denies even a cached custody JWT (the key shape matches:
 * that filter checks {@code subject:<jwt.sub>} and the custody JWT's {@code sub} is the
 * custody subject) — it runs on BOTH the cached and fresh exchange paths. <b>That alternative
 * REQUIRES {@code app.revocation.enabled=true} + a wired Cassandra</b>; where revocation is
 * disabled (e.g. the single-tenant/dev cluster) {@code RevocationGatewayFilter} is inert, so
 * the exchange gate plus this TTL — or {@code cache-ttl-ms=0} — are the ONLY suspension
 * enforcement on this path.
 *
 * <p><b>Ships dark.</b> Gated behind {@code hugmesh.gateway.bff-exchange.enabled}
 * (default false ⇒ this bean is ABSENT ⇒ the legacy chain is byte-identical: a
 * {@code bff_} bearer simply 401s at the JWT decoder as an invalid token, exactly as
 * today).
 */
@Component
@ConditionalOnProperty(name = "hugmesh.gateway.bff-exchange.enabled", havingValue = "true")
public class BffJwtExchangeWebFilter implements WebFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(BffJwtExchangeWebFilter.class);

    /** The opaque-session bearer prefix the cookie-terminating admin-bff mints. Only a
     *  bearer carrying this prefix is exchanged; everything else (a native Casdoor JWT,
     *  an opaque homeserver token, or no bearer at all) flows through untouched. */
    private static final String BFF_PREFIX = "bff_";

    /** The admin-bff custody-swap endpoint (guarded by its InternalTokenWebFilter on the
     *  {@code /bff/internal/} prefix — requires the X-Internal-Token header + mTLS). */
    private static final String EXCHANGE_PATH = "/bff/internal/session/exchange";

    private final WebClient exchangeClient;
    private final String internalTokenHeader;
    private final String internalToken;
    private final Duration requestTimeout;
    /** Positive-swap cache (sha256(bff_) -> custody JWT) with per-entry expiry and a
     *  bounded size. A {@link ConcurrentHashMap} (no Caffeine dependency on the gateway
     *  classpath) with manual TTL + size eviction — successful swaps only. */
    private final long cacheTtlMillis;
    private final int cacheMaxSize;
    /** False when {@code cache-ttl-ms <= 0}: the positive swap cache is disabled entirely
     *  and EVERY request re-consults the admin-bff exchange gate (zero suspension-bypass
     *  window). Keeps the read/write hot path from even touching the map when off. */
    private final boolean cacheEnabled;
    private final ConcurrentHashMap<String, CachedSwap> cache = new ConcurrentHashMap<>();

    public BffJwtExchangeWebFilter(
            WebClient bffExchangeWebClient,
            @Value("${hugmesh.gateway.bff-exchange.internal-token-header:X-Internal-Token}")
                    String internalTokenHeader,
            @Value("${hugmesh.gateway.bff-exchange.internal-token:}") String internalToken,
            @Value("${hugmesh.gateway.bff-exchange.cache-ttl-ms:5000}") long cacheTtlMillis,
            @Value("${hugmesh.gateway.bff-exchange.cache-max-size:10000}") int cacheMaxSize,
            @Value("${hugmesh.gateway.bff-exchange.request-timeout-ms:3000}") long requestTimeoutMillis) {
        this.exchangeClient = bffExchangeWebClient;
        this.internalTokenHeader = internalTokenHeader;
        this.internalToken = internalToken;
        // The TTL IS the suspension-bypass window (a cache hit skips admin-bff's exchange
        // suspension gate), so:
        //   * <= 0 DISABLES the cache entirely — every request re-consults the gate, zero
        //     bypass window (ban-critical deployments accept the per-request swap cost);
        //   * otherwise clamp to the 60s hard ceiling so a misconfiguration can never cache
        //     a swap (and thus stale a just-suspended session) for longer than a minute.
        // The default (5s, on the @Value above) matches the cluster's revocation poll cadence.
        this.cacheEnabled = cacheTtlMillis > 0;
        this.cacheTtlMillis = this.cacheEnabled ? Math.min(cacheTtlMillis, 60_000L) : 0L;
        this.cacheMaxSize = Math.max(cacheMaxSize, 1);
        this.requestTimeout = Duration.ofMillis(requestTimeoutMillis);
        log.info("[bff-exchange] filter ENABLED (hugmesh.gateway.bff-exchange.enabled) — "
                        + "cache={} cache-ttl={}ms max-size={} timeout={}ms",
                this.cacheEnabled ? "on" : "OFF (zero suspension-bypass window)",
                this.cacheTtlMillis, this.cacheMaxSize, requestTimeoutMillis);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String bearer = bearerOf(exchange);
        // Pure-JWT + anonymous traffic flows EXACTLY as today: no bearer, or a bearer
        // that is not an opaque bff_ session, is left for the JWT decoder / coarse gate.
        if (bearer == null || !bearer.startsWith(BFF_PREFIX)) {
            return chain.filter(exchange);
        }

        String hash = sha256(bearer);
        // When the cache is disabled (ttl <= 0) we never read or write it — every request
        // re-consults the admin-bff exchange gate, so a suspension takes effect immediately.
        String cached = cacheEnabled ? cachedJwt(hash) : null;
        if (cached != null) {
            return chain.filter(forwardWithJwt(exchange, cached));
        }

        // Resolve the swap to a SINGLE outcome: a custody JWT (success) or REJECT
        // (failure). The fail-closed operators (switchIfEmpty/onErrorResume) are scoped
        // to the SWAP ONLY — they must NEVER wrap chain.filter(...). Wrapping the
        // forward would re-trigger this onErrorResume on ANY downstream error AFTER the
        // response committed (the Mono<Void>-chain double-execution footgun documented
        // on RevocationGatewayFilter): a late downstream error would re-enter reject()
        // and try to mutate an already-committed response. Emitting an explicit
        // sentinel (REJECT) makes the swap stream emit EXACTLY ONE element, so the
        // terminal flatMap decides forward-vs-reject once, unambiguously.
        return exchangeForJwt(bearer)
                // FAIL CLOSED: empty completion (no/blank bearer) OR any error (non-2xx,
                // timeout, WebClient exception) becomes the REJECT sentinel — a failed
                // swap is intentionally NOT cached (negative-never-cached).
                .switchIfEmpty(Mono.just(REJECT))
                .onErrorReturn(REJECT)
                .flatMap(outcome -> {
                    if (REJECT.equals(outcome)) {
                        return reject(exchange, "exchange-failed-or-empty");
                    }
                    if (cacheEnabled) {
                        putCached(hash, outcome);
                    }
                    return chain.filter(forwardWithJwt(exchange, outcome));
                });
    }

    /** Sentinel emitted by the swap stage when the exchange failed or yielded no JWT.
     *  Distinct from any real custody JWT (a JWT never equals this literal). */
    private static final String REJECT = " bff-exchange-reject ";

    /** Call the admin-bff custody-swap endpoint; emit the custody JWT on 2xx with a
     *  non-blank {@code bearer}, otherwise error (4xx/5xx) or complete empty (blank). */
    private Mono<String> exchangeForJwt(String rawBffBearer) {
        // CONTRACT: reconcile field names with admin-bff /bff/internal/session/exchange
        return exchangeClient.post()
                .uri(EXCHANGE_PATH)
                .header(internalTokenHeader, internalToken)
                .bodyValue(Map.of("token", rawBffBearer))
                .retrieve()
                .bodyToMono(ExchangeResponse.class)
                .timeout(requestTimeout)
                .flatMap(resp -> {
                    String jwt = resp == null ? null : resp.bearer();
                    return (jwt == null || jwt.isBlank()) ? Mono.empty() : Mono.just(jwt);
                });
    }

    /** Mutate the request so the Authorization header carries the custody JWT — the
     *  raw bff_ is fully replaced (never appended) before the chain proceeds. */
    private static ServerWebExchange forwardWithJwt(ServerWebExchange exchange, String custodyJwt) {
        return exchange.mutate()
                .request(b -> b.headers(h -> h.set(HttpHeaders.AUTHORIZATION, "Bearer " + custodyJwt)))
                .build();
    }

    /** Fail-closed short-circuit: complete the response with a 401 and DO NOT forward.
     *  The raw bff_ never leaks downstream precisely BECAUSE chain.filter(...) is never
     *  called on this path — the request is never mutated or routed. (We deliberately do
     *  NOT touch the response Authorization header: the inbound bff_ lives on the REQUEST,
     *  which we never forward, and the committed response headers may be read-only.) This
     *  is the load-bearing fail-CLOSED contract — NEVER a chain.filter(). */
    private Mono<Void> reject(ServerWebExchange exchange, String reason) {
        log.warn("[bff-exchange] denied request fail-CLOSED — reason={} path={}",
                reason, exchange.getRequest().getPath().value());
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    // ── positive-only TTL cache ─────────────────────────────────────────────────

    private String cachedJwt(String hash) {
        CachedSwap entry = cache.get(hash);
        if (entry == null) return null;
        if (entry.isExpired()) {
            // Lazy eviction: a TTL-elapsed entry forces a fresh swap (so a revoked
            // session stops working within one TTL of the swap).
            cache.remove(hash, entry);
            return null;
        }
        return entry.custodyJwt();
    }

    private void putCached(String hash, String custodyJwt) {
        // Crude bound: if the cache is at capacity, drop one expired entry (or, failing
        // that, refuse to grow) so a flood of distinct sessions cannot grow it without
        // limit. Successful swaps only ever land here — failures are never cached.
        if (cache.size() >= cacheMaxSize) {
            cache.entrySet().removeIf(e -> e.getValue().isExpired());
            if (cache.size() >= cacheMaxSize) return;
        }
        cache.put(hash, new CachedSwap(custodyJwt, System.currentTimeMillis() + cacheTtlMillis));
    }

    /** A cached positive swap: the custody JWT and the wall-clock millis after which it
     *  is stale. Negative/failed swaps are NEVER represented here. */
    private record CachedSwap(String custodyJwt, long expiresAtMillis) {
        boolean isExpired() {
            return System.currentTimeMillis() >= expiresAtMillis;
        }
    }

    /** Response body of the admin-bff custody-swap endpoint. CONTRACT: reconcile field
     *  names with admin-bff /bff/internal/session/exchange (placeholder shape).
     *  Package-private (NOT private) so the JSON decoder's reflection can construct it
     *  via the canonical constructor. */
    record ExchangeResponse(String bearer) {}

    // ── bearer extraction + hashing (mirrors HomeserverTokenRevocationFilter) ────

    private static String bearerOf(ServerWebExchange exchange) {
        String auth = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (auth == null) return null;
        String trimmed = auth.trim();
        if (trimmed.regionMatches(true, 0, "Bearer ", 0, 7)) {
            String token = trimmed.substring(7).trim();
            return token.isEmpty() ? null : token;
        }
        return null;
    }

    /** SHA-256 of the bearer, lower-case hex — the raw bff_ value is NEVER used as a
     *  cache key or logged. Same shape as {@code HomeserverTokenRevocationFilter#sha256}. */
    static String sha256(String value) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated by the JLS-required provider set; unreachable.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    @Override
    public int getOrder() {
        // RUN BEFORE Spring Security's WebFilterChainProxy (order -100) — the LONE
        // justified exception to the gateway's "filters run POSITIVE, after security"
        // rule. The five principal-reading siblings (RevocationGatewayFilter,
        // ExternalAuthHeaderFilter, GatewayRouteAccessFilter, ResourceAccessFilter,
        // HomeserverTokenRevocationFilter) sit at POSITIVE orders ON PURPOSE: they read
        // exchange.getPrincipal(), and at HIGHEST_PRECEDENCE they ran before the
        // SecurityContext was populated and FAILED OPEN (see
        // RevocationGatewayFilter#getOrder + PrincipalFilterChainOrderingSpringBootTest).
        //
        // This filter is the OPPOSITE shape: it reads NOTHING from the SecurityContext.
        // It only inspects/rewrites the raw Authorization header, which the resource
        // server's JWT decoder (inside WebFilterChainProxy at -100) then validates. The
        // decoder CANNOT validate an opaque bff_ value, so the swap MUST happen BEFORE
        // -100 — otherwise the resource server 401s the bff_ before we ever see it.
        // HIGHEST_PRECEDENCE + 5 keeps us comfortably before -100 (and before every
        // other WebFilter) while leaving a few slots below us for any future
        // pre-security header rewriter.
        //
        // DO NOT "fix" this to a positive order to match its siblings: that would run
        // the swap AFTER the JWT decoder has already rejected the bff_, silently
        // breaking the SSO opaque-session bridge. The contrast is the whole point.
        return HIGHEST_PRECEDENCE + 5;
    }
}
