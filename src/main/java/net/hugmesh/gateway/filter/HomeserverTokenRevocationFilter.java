package net.hugmesh.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import net.hugmesh.gateway.cache.RevocationListService;
import net.hugmesh.gateway.cache.RevocationListService.HsToken;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Enforces the revocation list against HOMESERVER bearer tokens — the channel the
 * JWT-keyed {@link RevocationGatewayFilter} can never see. Native clients
 * (Element / Tusky / Ivory) and our own UIs talk to {@code /_matrix/**},
 * {@code /api/v1/**} and {@code /oauth/**} with an opaque Matrix
 * {@code access_token} / Mastodon OAuth token in the {@code Authorization} header;
 * that token carries no Casdoor subject and no roles, so a platform ban or an
 * external-client-role removal would otherwise do nothing to a live homeserver
 * session. This filter closes that gap.
 *
 * <p><b>Resolution is O(1), no homeserver round-trip.</b> The incoming bearer is
 * SHA-256 hashed and looked up in {@link RevocationListService#hsTokenFor(String)}
 * — a local snapshot of the {@code hs_tokens} table refreshed on the same poll as
 * the revocation list (PREREQ layer P1). The mint side (admin-bff brokered,
 * user-bff personal) records {@code token_hash → {localpart, platform, kind,
 * app/device id}} at mint time, so the gateway never has to ask the homeserver
 * "who is this token".
 *
 * <p><b>Deny conditions.</b> For a resolved token the request is denied 403 if ANY
 * of these keys is on the revocation list:
 * <ul>
 *   <li>{@code hs:<platform>:<localpart>} — coarse (a ban kills everything);</li>
 *   <li>{@code hs:<platform>:<localpart>:<deviceId|appId>} — per-credential (a
 *       single connected app / device dropped, the user's others survive);</li>
 *   <li>{@code external-client:<localpart>:<platform>} — checked ONLY when
 *       {@code kind=personal}, so removing the external-client role denies native
 *       clients while the user's {@code kind=brokered} our-UI token keeps working.</li>
 * </ul>
 *
 * <p><b>Fail-CLOSED on the gated paths.</b> Once enabled, a request to a gated
 * path that presents a bearer the gateway cannot resolve (no {@code hs_tokens}
 * row) is DENIED — a token we never recorded a mint for is, by construction, not
 * one we can vouch for. The PUBLIC discovery surface ({@code GET
 * /_matrix/client/versions}, {@code /.well-known/**}) is exempted so first-run
 * client discovery is never blocked by the issuance gate, and a request that
 * carries no bearer at all is left to the coarse {@code SecurityConfig} gate /
 * route-access layer (this filter only adjudicates presented homeserver tokens).
 *
 * <p><b>Gated by {@code app.hs-revocation.enabled} (default false).</b> The table,
 * cache, filter and route rules ship as a documented, inert STRUCTURE; flipping
 * the seam on is config-only once the mint side is writing {@code hs_tokens} rows.
 * While disabled the filter forwards untouched — it never hard-fails homeserver
 * traffic that predates the registry.
 */
@Component
public class HomeserverTokenRevocationFilter implements WebFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(HomeserverTokenRevocationFilter.class);
    private static final AntPathMatcher MATCHER = new AntPathMatcher();

    /** The token-bearing homeserver surfaces this filter adjudicates. */
    private static final String[] GATED_PATHS = {
            "/_matrix/**",
            "/api/v1/**",
            // The Mastodon v2 API is permitAll at the resource-server layer
            // (HOMESERVER_PASSTHROUGH_PATHS includes /api/v2/**), so a revoked
            // homeserver bearer would otherwise escape revocation on every v2
            // endpoint (e.g. /api/v2/search, /api/v2/instance, /api/v2/filters).
            // Gate it alongside v1 so a ban / per-credential / external-client
            // revocation reaches the v2 surface too.
            "/api/v2/**",
            "/oauth/**",
    };

    /** Public discovery surface that must stay reachable WITHOUT a recorded token
     *  so a native client can bootstrap before it has been issued one. */
    private static final String[] DISCOVERY_EXEMPT = {
            "/_matrix/client/versions",
            "/.well-known/**",
    };

    private final RevocationListService revocations;
    private final boolean enabled;

    public HomeserverTokenRevocationFilter(
            RevocationListService revocations,
            @Value("${app.hs-revocation.enabled:false}") boolean enabled) {
        this.revocations = revocations;
        this.enabled = enabled;
        log.info("[hs-revocation] filter {} (app.hs-revocation.enabled)",
                enabled ? "ENABLED" : "disabled");
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if (!enabled) return chain.filter(exchange);

        String path = exchange.getRequest().getPath().value();
        if (!isGated(path) || isDiscoveryExempt(path)) {
            return chain.filter(exchange);
        }

        String bearer = bearerOf(exchange);
        if (bearer == null) {
            // No homeserver token presented — not this filter's concern; the
            // coarse SecurityConfig gate + route-access layer already decide
            // whether an anonymous request may reach this path.
            return chain.filter(exchange);
        }

        String hash = sha256(bearer);
        HsToken token = revocations.hsTokenFor(hash);
        if (token == null) {
            // FAIL-CLOSED: a bearer on a gated path that the gateway has no
            // recorded mint for cannot be vouched for.
            return reject(exchange, path, "unrecognized-homeserver-token");
        }

        String revokedKey = firstRevokedKey(token);
        if (revokedKey != null) {
            return reject(exchange, path, revokedKey);
        }
        return chain.filter(exchange);
    }

    /** The first revocation key that denies this token, or {@code null} if none. */
    private String firstRevokedKey(HsToken token) {
        String platform = token.platform();
        String localpart = token.localpart();
        if (platform == null || localpart == null) {
            // A row missing its identity fields is unusable — fail closed.
            return "incomplete-token-record";
        }
        String coarse = "hs:" + platform + ":" + localpart;
        if (revocations.isRevoked(coarse)) return coarse;

        String id = token.appOrDeviceId();
        if (id != null && !id.isBlank()) {
            String perCredential = coarse + ":" + id;
            if (revocations.isRevoked(perCredential)) return perCredential;
        }

        // external-client:* applies ONLY to personal (native-client) tokens, so
        // removing the external-client role never disturbs the brokered our-UI
        // token the same localpart also holds.
        if ("personal".equalsIgnoreCase(token.kind())) {
            String externalClient = "external-client:" + localpart + ":" + platform;
            if (revocations.isRevoked(externalClient)) return externalClient;
        }
        return null;
    }

    private boolean isGated(String path) {
        for (String p : GATED_PATHS) if (MATCHER.match(p, path)) return true;
        return false;
    }

    private boolean isDiscoveryExempt(String path) {
        for (String p : DISCOVERY_EXEMPT) if (MATCHER.match(p, path)) return true;
        return false;
    }

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

    /** SHA-256 of the bearer, lower-case hex — matches what the mint side stores
     *  as {@code token_hash} so a raw token is never persisted or compared. */
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

    private Mono<Void> reject(ServerWebExchange exchange, String path, String key) {
        log.warn("[hs-revocation] denied homeserver request — key={} path={}", key, path);
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        exchange.getResponse().getHeaders().add("X-HS-Revoked", revocations.reasonFor(key));
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        // Run AFTER Spring Security's WebFilterChainProxy (order -100), alongside the
        // JWT-keyed RevocationGatewayFilter (order 10) — see the ordering note on
        // RevocationGatewayFilter#getOrder. This filter reads the opaque bearer from
        // the Authorization header directly (NOT exchange.getPrincipal()), so it does
        // not strictly depend on the SecurityContext; but the gated homeserver paths
        // are permitAll at the resource-server layer anyway, and running after the
        // security chain keeps a single, coherent post-security ordering for all the
        // gateway filters. Order 11 keeps it adjacent to its JWT sibling (10) and
        // before the routing filter, so a revoked homeserver token never reaches
        // akkoma/tuwunel, without colliding on the same value.
        return 11;
    }
}
