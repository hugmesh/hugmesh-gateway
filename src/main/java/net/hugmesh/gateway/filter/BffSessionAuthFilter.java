package net.hugmesh.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import net.hugmesh.gateway.config.BffSessionProperties;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * BFF session introspection filter — bridges opaque {@code bff_} session tokens
 * into Spring Security's {@link ReactiveSecurityContextHolder} so that
 * cookie-mode UIs (and any API client that carries the opaque token in the
 * {@code Authorization: Bearer} header) can be authenticated by the gateway
 * without the downstream JWT-resource-server filter ever seeing or attempting
 * to validate a non-JWT token.
 *
 * <h2>Token resolution</h2>
 * <p>The filter extracts a {@code bff_*} token from two locations, in priority order:
 * <ol>
 *   <li>{@code Authorization: Bearer bff_...} header — API clients / Angular
 *       carrying the token in-memory.</li>
 *   <li>{@code bff_session} cookie — cookie-mode UIs.</li>
 * </ol>
 * If the extracted value does not start with {@code bff_} the filter skips
 * immediately, leaving the Casdoor JWT path entirely undisturbed.
 *
 * <h2>Introspection</h2>
 * <p>A resolved {@code bff_} token is validated by calling
 * {@code GET {bff-base-url}/bff/internal/session/introspect} with the token in the
 * {@code Authorization: Bearer} header. The BFF performs a DB lookup on the
 * {@code bff_session} table; the gateway never sees the raw session DB.
 * The internal surface is {@code permitAll()} at the Spring layer, guarded in depth
 * by {@code InternalTokenWebFilter} (mTLS + {@code X-Internal-Token} in enforcing
 * mode). Using the internal surface avoids the JWT-auth requirement of {@code /bff/me}:
 * bff_ tokens are inert to the admin-bff JWT resource server, so a call to {@code /bff/me}
 * with a bff_ Bearer would get a 401 before the controller is reached.
 *
 * <h2>Authority mapping</h2>
 * <p>From the BFF response the filter constructs a
 * {@link UsernamePasswordAuthenticationToken} (three-arg authenticated form):
 * <ul>
 *   <li>Each role {@code r} from the {@code roles} array → {@code ROLE_<UPPER>}.</li>
 *   <li>{@code ROLE_USER} floor (always added, mirrors the JWT converter).</li>
 *   <li>{@code MFA_SATISFIED} when {@code mfaSatisfied} is {@code true}.</li>
 *   <li>If {@code registrationComplete} is {@code false}: only {@code ROLE_USER}
 *       (restricted authority set — prevents a partially-registered account
 *       from reaching admin surfaces while still allowing the registration
 *       completion flow).</li>
 * </ul>
 *
 * <h2>Fail-closed posture</h2>
 * <ul>
 *   <li>BFF unreachable / 5xx → {@code 503 Service Unavailable} (fail-closed;
 *       a bff_ token that cannot be validated is never treated as authenticated).</li>
 *   <li>BFF returns 401 (expired/unknown token) → pass-through unauthenticated
 *       (the downstream {@code anyExchange().authenticated()} rule produces the 401
 *       for paths that require auth; public paths succeed).</li>
 *   <li>BFF returns 403 → 403 forwarded to the browser.</li>
 *   <li>{@code status: "suspended"} or {@code "banned"} in the response body →
 *       403 (even if BFF returned 200, which some code paths do for suspended
 *       accounts).</li>
 * </ul>
 *
 * <h2>Ordering</h2>
 * <p>Order {@code HIGHEST_PRECEDENCE + 50} — runs BEFORE
 * {@link ExternalAuthHeaderFilter} (order {@code 20}), before
 * {@link GatewayRouteAccessFilter} (order {@code 25}), and critically before the
 * OAuth2 resource server's {@code BearerTokenAuthenticationWebFilter} (which sits
 * at {@code SecurityWebFiltersOrder.AUTHENTICATION}, i.e. around {@code +100}).
 * Once this filter populates the {@code SecurityContext}, the downstream JWT filter
 * finds an existing authentication and short-circuits.
 *
 * <h2>Feature flag</h2>
 * <p>Gated by {@code app.bff-session.enabled=true}. The Java-level default on
 * {@link BffSessionProperties#isEnabled()} is {@code false} (fail-safe if the
 * property is ever entirely unbound), but {@code application.yml} resolves
 * {@code APP_BFF_SESSION_ENABLED} to {@code true} when unset — so this bridge is
 * LIVE by default in a real deployment (PR #70); set
 * {@code APP_BFF_SESSION_ENABLED=false} to dark-disable it.
 * See {@link BffSessionProperties} and
 * {@link net.hugmesh.gateway.config.BffSessionConfig}.
 */
public class BffSessionAuthFilter implements WebFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(BffSessionAuthFilter.class);
    private static final AntPathMatcher MATCHER = new AntPathMatcher();

    /** Cookie name as defined by SessionCookieWebFilter in admin-bff. */
    static final String SESSION_COOKIE = "bff_session";

    /** Token prefix that uniquely identifies opaque BFF session tokens. */
    static final String BFF_PREFIX = "bff_";

    /** Authority granted when the MFA challenge has been satisfied for this session. */
    static final String MFA_SATISFIED = "MFA_SATISFIED";

    private final WebClient bffClient;
    private final BffSessionProperties props;
    /** The X-Internal-Token value to authenticate against InternalTokenWebFilter on the BFF.
     *  Blank by default (non-enforcing dev mode). Set via app.bff-session.internal-token in prod. */
    private final String internalToken;
    /** The header name to carry the internal token. Default: X-Internal-Token. */
    private final String internalTokenHeader;

    public BffSessionAuthFilter(WebClient bffClient, BffSessionProperties props) {
        this.bffClient = bffClient;
        this.props = props;
        this.internalToken = props.getInternalToken();
        this.internalTokenHeader = props.getInternalTokenHeader();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        // Skip paths that are already permitAll or irrelevant (no BFF call needed).
        if (isSkipped(path)) {
            return chain.filter(exchange);
        }

        String token = extractToken(exchange);
        if (token == null) {
            // No bff_ token present — leave the JWT path undisturbed.
            return chain.filter(exchange);
        }

        // Forward the original client IP so BFF audit logs record the real address.
        String clientIp = remoteAddress(exchange);

        return introspect(token, clientIp)
                .flatMap(me -> {
                    // Suspended or banned — explicit status check (BFF may return 200
                    // with status:"suspended" in some code paths; never trust 200 alone).
                    String status = me.status();
                    if ("suspended".equalsIgnoreCase(status) || "banned".equalsIgnoreCase(status)) {
                        log.warn("[bff-session] denied — account status={} id={}", status, me.id());
                        return rejectForbidden(exchange, "account-" + status.toLowerCase());
                    }

                    List<GrantedAuthority> authorities = buildAuthorities(me);
                    String principalName = me.id();
                    UsernamePasswordAuthenticationToken auth =
                            new UsernamePasswordAuthenticationToken(principalName, null, authorities);
                    // A5 part-B: carry the introspect-supplied Casdoor sub UUID to the
                    // route-access filter (which folds it into the casdoor_user pin-match
                    // identity set) via the token's details slot. ONLY when present and
                    // non-blank — a legacy/absent field leaves details null, so the token
                    // is byte-identical to the pre-field one (no behavior change).
                    if (me.casdoorSub() != null && !me.casdoorSub().isBlank()) {
                        auth.setDetails(new SessionDetails(me.casdoorSub().trim()));
                    }

                    log.debug("[bff-session] authenticated id={} roles={} mfa={}",
                            me.id(), me.roles(), me.mfaSatisfied());

                    return chain.filter(exchange)
                            .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
                })
                .onErrorResume(WebClientResponseException.class, ex -> {
                    int status = ex.getStatusCode().value();
                    if (status == 401) {
                        // Token expired or not found — pass through unauthenticated.
                        // The downstream authenticated() rule produces a 401 for
                        // protected paths; public paths succeed.
                        log.debug("[bff-session] token not found or expired (BFF 401) — passing through unauthenticated");
                        return chain.filter(exchange);
                    }
                    if (status == 403) {
                        log.warn("[bff-session] BFF returned 403 for token — rejecting");
                        return rejectForbidden(exchange, "bff-forbidden");
                    }
                    // 5xx or unexpected — fail-closed: do NOT allow unauthenticated through.
                    log.error("[bff-session] BFF introspection error (status={}) — returning 503", status);
                    return rejectServiceUnavailable(exchange);
                })
                .onErrorResume(ex -> {
                    // Connection refused, timeout, codec error, etc. — fail-closed.
                    log.error("[bff-session] BFF introspection call failed: {} — returning 503", ex.getMessage());
                    return rejectServiceUnavailable(exchange);
                });
    }

    // ── token extraction ──────────────────────────────────────────────────────

    /**
     * Extracts the {@code bff_} token from the exchange. Checks the
     * {@code Authorization: Bearer} header first, then the {@code bff_session}
     * cookie. Returns {@code null} if no {@code bff_} token is present (the
     * value is present but does not start with {@code bff_}).
     */
    static String extractToken(ServerWebExchange exchange) {
        // Priority 1: Authorization header.
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader != null) {
            String trimmed = authHeader.trim();
            if (trimmed.regionMatches(true, 0, "Bearer ", 0, 7)) {
                String candidate = trimmed.substring(7).trim();
                if (candidate.startsWith(BFF_PREFIX)) {
                    return candidate;
                }
                // Present but not a bff_ token (e.g. a Casdoor JWT) — skip immediately.
                return null;
            }
        }

        // Priority 2: bff_session cookie.
        var cookies = exchange.getRequest().getCookies();
        var cookieList = cookies.get(SESSION_COOKIE);
        if (cookieList != null && !cookieList.isEmpty()) {
            String value = cookieList.get(0).getValue();
            if (value != null && !value.isBlank()) {
                return value; // Cookie values are always the raw bff_ token string.
            }
        }

        return null;
    }

    // ── BFF call ──────────────────────────────────────────────────────────────

    private Mono<MeResponse> introspect(String token, String clientIp) {
        WebClient.RequestHeadersSpec<?> req = bffClient.get()
                .uri("/bff/internal/session/introspect")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .accept(MediaType.APPLICATION_JSON);

        // Authenticate against InternalTokenWebFilter (non-enforcing when blank in dev).
        if (internalToken != null && !internalToken.isBlank()) {
            req = req.header(internalTokenHeader, internalToken);
        }

        if (clientIp != null) {
            req = req.header("X-Forwarded-For", clientIp);
        }

        return req.retrieve()
                .bodyToMono(MeResponse.class)
                .timeout(Duration.ofMillis(props.getTimeoutMs()));
    }

    // ── authority mapping ─────────────────────────────────────────────────────

    /**
     * Build the Spring authority list from the BFF /bff/me response.
     *
     * <p>If {@code registrationComplete} is false, only {@code ROLE_USER} is
     * returned — the registration flow endpoints are {@code permitAll()} anyway,
     * so the incomplete account can complete registration, but it cannot satisfy
     * any admin-role route-access rules.
     */
    static List<GrantedAuthority> buildAuthorities(MeResponse me) {
        var authorities = new ArrayList<GrantedAuthority>();
        // ROLE_USER floor — always present, mirrors the JWT converter.
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        // Incomplete registration → restricted set (only the floor).
        if (!me.registrationComplete()) {
            return authorities;
        }

        // Map each role to ROLE_<UPPER>.
        if (me.roles() != null) {
            for (String role : me.roles()) {
                if (role != null && !role.isBlank()) {
                    String authority = "ROLE_" + role.trim().toUpperCase();
                    // Deduplicate ROLE_USER (already added as floor).
                    if (!"ROLE_USER".equals(authority)) {
                        authorities.add(new SimpleGrantedAuthority(authority));
                    }
                }
            }
        }

        // MFA gate — required by GatewayRouteAccessFilter on mfa_required routes.
        if (me.mfaSatisfied()) {
            authorities.add(new SimpleGrantedAuthority(MFA_SATISFIED));
        }

        return authorities;
    }

    // ── path matching ─────────────────────────────────────────────────────────

    private boolean isSkipped(String path) {
        for (String pattern : props.getSkipPaths()) {
            if (MATCHER.match(pattern, path)) return true;
        }
        return false;
    }

    // ── response helpers ──────────────────────────────────────────────────────

    private static String remoteAddress(ServerWebExchange exchange) {
        var addr = exchange.getRequest().getRemoteAddress();
        if (addr == null) return null;
        return addr.getAddress().getHostAddress();
    }

    private static Mono<Void> rejectForbidden(ServerWebExchange exchange, String reason) {
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        exchange.getResponse().getHeaders().add("X-BFF-Denied", reason);
        return exchange.getResponse().setComplete();
    }

    private static Mono<Void> rejectServiceUnavailable(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        byte[] body = "{\"error\":\"session_backend_unavailable\"}".getBytes(StandardCharsets.UTF_8);
        var buffer = exchange.getResponse().bufferFactory().wrap(body);
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        // HIGHEST_PRECEDENCE + 50:
        //   before ExternalAuthHeaderFilter (order 20)
        //   before GatewayRouteAccessFilter (order 25)
        //   before Spring Security AUTHENTICATION slot (BearerTokenAuthenticationWebFilter)
        //   so the SecurityContext is populated before the JWT resource-server filter runs.
        return HIGHEST_PRECEDENCE + 50;
    }

    // ── response record ───────────────────────────────────────────────────────

    /**
     * Projection of the {@code /bff/me} response body. Only the fields this
     * filter needs are declared; Jackson's default deserialization ignores
     * unknown properties, so additions to the BFF response are harmless.
     *
     * <p>All fields have safe defaults so a partial response (missing optional
     * fields) does not produce a NullPointerException.
     *
     * <p>{@code casdoorSub} (admin-bff changeset 292 — the A5 part-B cross-carrier
     * route-pin fix) is the raw Casdoor {@code sub} UUID stamped on the account row
     * at the native-login mint. NULLABLE by contract: null from an admin-bff that
     * predates the field (Jackson leaves an absent property null), or for a legacy
     * account row not yet re-stamped by a native login. It is deliberately NOT
     * defaulted in the compact constructor — null means "unknown", and every
     * consumer must degrade to the pre-field behavior on null/blank, never guess.
     */
    public record MeResponse(
            String id,
            String provider,
            List<String> roles,
            boolean registrationComplete,
            String status,
            boolean mfaSatisfied,
            String casdoorSub
    ) {
        /** Compact constructor: safe defaults for optional fields ({@code casdoorSub}
         *  intentionally excluded — see the record doc). */
        public MeResponse {
            if (id == null) id = "";
            if (provider == null) provider = "";
            if (roles == null) roles = List.of();
            if (status == null) status = "active";
        }

        /** Pre-casdoorSub shape (the legacy introspect contract) — keeps the many
         *  existing positional construction sites compiling and pins "absent field
         *  == null" in one place. */
        public MeResponse(String id, String provider, List<String> roles,
                          boolean registrationComplete, String status, boolean mfaSatisfied) {
            this(id, provider, roles, registrationComplete, status, mfaSatisfied, null);
        }
    }

    /**
     * The details object stamped onto the bff_ session's {@link
     * UsernamePasswordAuthenticationToken} — the carrier that hands the
     * introspect-supplied Casdoor {@code sub} UUID from this filter to {@link
     * GatewayRouteAccessFilter}'s bff_ branch WITHOUT changing the principal type
     * (the String account id, which several consumers key on with {@code
     * instanceof String}) and without polluting the authorities list that
     * route-access {@code decide()} matches role rows against. Only set when the
     * introspect response carried a present, non-blank {@code casdoorSub}; a
     * legacy/absent field leaves the token's details null — byte-identical to the
     * pre-field token.
     */
    public record SessionDetails(String casdoorSub) {
    }
}
