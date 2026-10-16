package net.hugmesh.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferLimitException;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.gateway.cache.RevocationListService;
import net.hugmesh.gateway.cache.RevocationListService.HsToken;
import net.hugmesh.gateway.security.CanonicalPath;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

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
 * <p><b>Every credential channel.</b> A homeserver can take its bearer from more than
 * the first {@code Authorization} header: a later header line, an
 * {@code access_token} query parameter, or (on the Mastodon-API surface) an
 * {@code access_token} member of a form or JSON body. Each one presented is
 * adjudicated and the request is refused unless every one passes, so a revoked token
 * cannot ride beside a good one or move to a channel this filter does not read. See
 * {@link PresentedCredentials}.
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

    /** Gated prefixes whose server parses form / JSON / multipart bodies into the
     *  same parameter map it reads {@code access_token} from (the Mastodon API). The
     *  Matrix client-server API takes a token from the header or query only. */
    private static final String[] BODY_PARAM_PATHS = {
            "/api/v1/**",
            "/api/v2/**",
            "/oauth/**",
    };

    /** Largest form / JSON body read to look for a token. A larger one on the
     *  Mastodon-API surface is refused rather than forwarded unread. */
    static final int MAX_INSPECTED_BODY_BYTES = 1 << 20;

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
        // Decide on every spelling a downstream hop could read, not the raw string
        // alone: the router and the homeserver decode the path, so an encoded,
        // dotted, parameterised or re-cased variant of a gated prefix is the same
        // request. RequestPathForms enumerates the readings; CanonicalPath is the
        // single reading the route-access layer routes on, and a path it cannot give
        // one meaning to is adjudicated as gated.
        RequestPathForms forms = RequestPathForms.of(path);
        var canonical = CanonicalPath.of(exchange.getRequest());
        boolean ambiguous = forms.isAmbiguous();
        // A path nested too deep to read cannot be shown to be OUTSIDE the gated
        // surface, so it is adjudicated like a gated one. Any other ambiguity
        // (encoded NUL, bad UTF-8, malformed escape) only matters on a gated path.
        boolean adjudicate = isGated(forms) || forms.isNestedTooDeep()
                || canonical.isEmpty()
                || RequestPathForms.of(canonical.get()).anyMatches(GATED_PATHS);
        // Discovery is exempt only when the path has one reading and that reading is
        // a discovery path: a dot segment or an encoding that climbs out of
        // /.well-known/** resolves to the gated path it really names.
        boolean exempt = !ambiguous && !forms.isNestedTooDeep() && canonical.isPresent()
                && RequestPathForms.of(canonical.get()).allMatch(DISCOVERY_EXEMPT);
        if (!adjudicate || exempt) {
            return chain.filter(exchange);
        }

        PresentedCredentials creds = PresentedCredentials.of(exchange.getRequest());
        BodyKind body = bodyKind(exchange.getRequest());
        boolean bodyParams = body != BodyKind.NONE
                && (canonical.isEmpty() || forms.anyMatches(BODY_PARAM_PATHS)
                    || RequestPathForms.of(canonical.get()).anyMatches(BODY_PARAM_PATHS));
        if (!bodyParams) {
            return adjudicate(exchange, chain, path, ambiguous, creds);
        }
        if (body == BodyKind.AMBIGUOUS) {
            return reject(exchange, path, "unreadable-credential");
        }
        if (body == BodyKind.MULTIPART) {
            // A multipart body is not buffered (media uploads). Its fields reach the
            // server's parameter map, so with no credential in the header or query
            // the only token would be one this filter cannot see: refuse it.
            if (creds.isEmpty()) return reject(exchange, path, "unread-body-credential");
            return adjudicate(exchange, chain, path, ambiguous, creds);
        }
        return DataBufferUtils.join(exchange.getRequest().getBody(), MAX_INSPECTED_BODY_BYTES)
                .map(buf -> {
                    try {
                        byte[] bytes = new byte[buf.readableByteCount()];
                        buf.read(bytes);
                        return bytes;
                    } finally {
                        DataBufferUtils.release(buf);
                    }
                })
                .defaultIfEmpty(new byte[0])
                .map(Optional::of)
                // Too large to read: no reading of its parameters, refused below.
                .onErrorResume(DataBufferLimitException.class, e -> Mono.just(Optional.empty()))
                .flatMap(read -> {
                    if (read.isEmpty()) {
                        return reject(exchange, path, "body-too-large-to-inspect", HttpStatus.PAYLOAD_TOO_LARGE);
                    }
                    byte[] bytes = read.get();
                    if (body == BodyKind.FORM) {
                        creds.addFormEncoded(new String(bytes, StandardCharsets.UTF_8), false);
                    } else {
                        creds.addJson(bytes);
                    }
                    return adjudicate(withBody(exchange, bytes), chain, path, ambiguous, creds);
                });
    }

    private Mono<Void> adjudicate(ServerWebExchange exchange, WebFilterChain chain, String path,
                                  boolean ambiguous, PresentedCredentials creds) {
        if (creds.malformed()) {
            // FAIL-CLOSED: a credential we could not read is one we cannot vouch for.
            return reject(exchange, path, "unreadable-credential");
        }
        if (creds.tokens().isEmpty()) {
            // No homeserver token presented — not this filter's concern; the
            // coarse SecurityConfig gate + route-access layer already decide
            // whether an anonymous request may reach this path.
            return chain.filter(exchange);
        }

        if (ambiguous) {
            // FAIL-CLOSED: a path with no single reading (malformed escape, encoded
            // NUL, non-UTF-8 bytes, nesting deeper than we follow) cannot be proven
            // to be outside the gated surface, so a presented bearer is refused.
            return reject(exchange, path, "ambiguous-path");
        }

        // Every presented token must pass: which one the downstream honours is its
        // choice, not ours.
        for (String bearer : creds.tokens()) {
            HsToken token = revocations.hsTokenFor(sha256(bearer));
            if (token == null) {
                // FAIL-CLOSED: a bearer on a gated path that the gateway has no
                // recorded mint for cannot be vouched for.
                return reject(exchange, path, "unrecognized-homeserver-token");
            }
            String revokedKey = firstRevokedKey(token);
            if (revokedKey != null) {
                return reject(exchange, path, revokedKey);
            }
        }
        return chain.filter(exchange);
    }

    private enum BodyKind { NONE, FORM, JSON, MULTIPART, AMBIGUOUS }

    /** Which body parser a Plug/Rails-style server would run, judged loosely
     *  (case-insensitive, any parameters) so a spelling variant is not missed. */
    private static BodyKind bodyKind(ServerHttpRequest request) {
        List<String> types = request.getHeaders().get(HttpHeaders.CONTENT_TYPE);
        if (types == null || types.isEmpty()) return BodyKind.NONE;
        String ct = String.join(",", types).toLowerCase(Locale.ROOT);
        if (ct.contains("multipart/")) return BodyKind.MULTIPART;
        boolean form = ct.contains("x-www-form-urlencoded");
        boolean json = ct.contains("json");
        if (form && json) return BodyKind.AMBIGUOUS;   // two parsers could claim it
        if (form) return BodyKind.FORM;
        if (json) return BodyKind.JSON;
        return BodyKind.NONE;
    }

    /** The exchange with its already-read body replayed for the routing filter. */
    private static ServerWebExchange withBody(ServerWebExchange exchange, byte[] bytes) {
        ServerHttpRequest replay = new ServerHttpRequestDecorator(exchange.getRequest()) {
            @Override
            public Flux<DataBuffer> getBody() {
                if (bytes.length == 0) return Flux.empty();
                return Flux.defer(() -> Flux.just(exchange.getResponse().bufferFactory().wrap(bytes)));
            }
        };
        return exchange.mutate().request(replay).build();
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

    /** Gated if ANY spelling of the path is under a gated prefix (case-insensitive). */
    private boolean isGated(RequestPathForms forms) {
        return forms.anyMatches(GATED_PATHS);
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
        return reject(exchange, path, key, HttpStatus.FORBIDDEN);
    }

    private Mono<Void> reject(ServerWebExchange exchange, String path, String key, HttpStatus status) {
        log.warn("[hs-revocation] denied homeserver request — key={} path={}", key, path);
        exchange.getResponse().setStatusCode(status);
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
