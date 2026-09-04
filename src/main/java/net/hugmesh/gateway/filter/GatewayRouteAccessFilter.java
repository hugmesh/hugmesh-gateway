package net.hugmesh.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import net.hugmesh.gateway.cache.GatewayRouteAccessService;
import net.hugmesh.gateway.cache.GatewayRouteAccessService.Decision;
import net.hugmesh.gateway.security.DomainRegistry;
import net.hugmesh.gateway.security.Roles;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Per-gateway external-access gate. Enforces the admin-managed
 * "which roles/users may reach which URLs from outside THIS gateway" rules
 * (see {@link GatewayRouteAccessService}). Sits between the
 * External-Authorization header injection ({@link ExternalAuthHeaderFilter},
 * order 20) and the hugmesh.games resource-access filter
 * ({@link ResourceAccessFilter}, order 30).
 *
 * <p>Decision chain (short-circuits on first match):
 * <ol>
 *   <li>{@code ROLE_SUPERADMIN} — the ONLY cross-domain bypass. Reaches every
 *       surface in every brand (the infra control plane) without a domain
 *       match.</li>
 *   <li><b>Domain mismatch → HARD-DENY.</b> Any non-superadmin principal whose
 *       own domain does NOT equal the request's target domain (derived from
 *       {@code Host}) is rejected OUTRIGHT, before the route-access grant layer is
 *       even consulted. This closes the cross-tenant hole where a domain-BLIND
 *       route-access GRANT (a brand-Y {@code /api/admin/** -> ROLE_ADMIN allow=true}
 *       row matched on the role string alone) would otherwise re-grant a brand-X
 *       admin on brand-Y's surface. The check is applied to EVERY authenticated
 *       principal, not just Casdoor JWTs: for a JWT the principal domain is the
 *       validated {@code iss}; for a non-JWT principal (an opaque {@code bff_}
 *       session bridged to a {@code UsernamePasswordAuthenticationToken} by
 *       {@link BffSessionAuthFilter}) it is the {@code DOMAIN_<x>} authority, which
 *       fails closed (null) when absent or ambiguous — so a bff_ session cannot
 *       skip this gate and ride an unscoped admin row onto another brand. The
 *       non-JWT cross-domain enforcement engages ONLY in multi-issuer mode
 *       ({@link DomainRegistry#isMultiIssuer()}); single-issuer clusters always
 *       match ({@code default} vs {@code default}), so this is a no-op on
 *       single-tenant deployments.</li>
 *   <li>{@code ROLE_ADMIN} / {@code ROLE_GAME-MASTER} on the internal Casdoor
 *       JWT — forwards (reaching here means the domain already matched), so the
 *       current "admin works on the internal token alone" contract is unchanged
 *       within the principal's OWN domain.</li>
 *   <li>{@link Decision#DENY} → 403 + {@code X-Route-Denied: <gateway>:<path>}
 *       (no leak of which rule or subject set caused it). The route-access grant
 *       is itself domain-scoped (per-row {@code domain} column) for the
 *       multi-brand architecture tier that legitimately serves several brands.</li>
 *   <li>{@link Decision#ALLOW} / {@link Decision#NO_RULE} → forward. NO_RULE
 *       means the path isn't governed by any rule at this gateway, so the
 *       coarse SecurityConfig gate (already passed) is the authority.</li>
 * </ol>
 *
 * <p>Anonymous requests forward without a route-access decision — SecurityConfig
 * already decided whether an unauthenticated path is reachable, exactly as the
 * resource-access filter does.
 *
 * <p><b>Inbound {@code X-Domain} is always stripped; the outbound stamp is
 * opt-in.</b> {@code X-Domain} is the canonical gateway-stamped brand header. On
 * the way IN it is client-supplied and therefore untrusted, so it is removed
 * UNCONDITIONALLY at the top of {@link #filter} — ahead of every short-circuit
 * above, anonymous traffic included, and in BOTH flag states. On the way OUT the
 * gateway stamps the registry-validated target brand only when
 * {@code app.domain-header.forward} is on; that flag defaults {@code false}, so the
 * producer half SHIPS INERT and the filter is byte-identical to its strip-only
 * behaviour until an operator flips it. Same posture
 * {@code ExternalAuthHeaderFilter} holds for the {@code External-*} trio: drop the
 * client copy first, then stamp only a gateway-derived value.
 *
 * <p><b>Why the stamp sits with the strip and not at the route-access decision.</b>
 * The header exists for public-read domain partitioning — a downstream scoping
 * <i>anonymous</i> reads to the requesting brand (hugmesh-games decision 026). An
 * anonymous request returns {@code chain.filter()} from the FIRST branch of
 * {@link #filter} and never reaches the decision, so a stamp placed there would be
 * missing from exactly the traffic that needs it (and from both privileged
 * bypasses). One call site at the top covers every path with one value, derived
 * from the {@code Host} through {@link DomainRegistry} — never read back off the
 * request.
 */
@Component
public class GatewayRouteAccessFilter implements WebFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(GatewayRouteAccessFilter.class);

    private final GatewayRouteAccessService routeAccess;
    private final DomainRegistry domainRegistry;

    /**
     * D8 PRIVILEGED-FLOOR sub-flag ({@code app.mfa.enforce-privileged-floor},
     * default {@code false} — ships dark, SEPARATE from {@code app.mfa.enabled}).
     * When {@code true} a HARD MFA check runs ABOVE the SUPERADMIN cross-domain
     * bypass and the ADMIN/GAME-MASTER own-domain bypass: any privileged principal
     * reaching an {@code mfa_required} surface MUST carry the {@code MFA_SATISFIED}
     * marker or be DENIED (403) — SUPERADMIN is NOT exempt. The bypasses return
     * {@code chain.filter()} BEFORE {@link GatewayRouteAccessService#decide}, so
     * this floor MUST sit above them or the very roles whose MFA default is
     * REQUIRED would never be gated. Default off => byte-identical legacy chain.
     */
    private final boolean enforcePrivilegedFloor;

    /** D8 MFA freshness window in millis — {@code app.mfa.freshness-window}
     *  (default 10m). The privileged floor re-validates the JWT's
     *  {@code mfa_satisfied_at} freshness directly (it does NOT rely on the
     *  converter-derived authority, since a privileged principal short-circuits
     *  before the route-access decide() that consults authorities). */
    private final long mfaFreshnessWindowMillis;

    /**
     * OUTBOUND brand stamp — {@code app.domain-header.forward}, default
     * {@code false}, so the producer half SHIPS INERT.
     *
     * <p>When {@code true} every forwarded request carries
     * {@code X-Domain: <targetDomain>} — the brand this request's {@code Host}
     * resolves to through {@link DomainRegistry} ({@code "default"} on a
     * single-tenant cluster, so the header is always present and a downstream can
     * tell "came through the gateway" from "reached me directly"). When
     * {@code false} nothing is stamped. The inbound strip is NOT flag-gated in
     * either state, so a downstream can never receive a client-forged value.
     *
     * <p><b>Why a flag rather than an unconditional stamp.</b> No service reads this
     * header today (verified org-wide: the only {@code X-Domain}-ish header in the
     * org is hugmesh-games' {@code X-Domain-Denied} RESPONSE header, and its
     * {@code DomainGuardFilter} scopes off the JWT's {@code DOMAIN_} authority, not
     * a forwarded request header). The gateway also fronts third-party servers
     * (tuwunel, Akkoma, Ollama, Casdoor) that have no reason to receive a new header
     * until something asks. The named consumer — hugmesh-games decision 026, whose
     * "public/anonymous catalog reads … stay global" section says a brand-partitioned
     * public catalog "needs the gateway to forward a Host-derived brand (e.g.
     * {@code X-Domain}), which it does not today" — lands in ITS repo; an operator
     * then flips this one property. Landing the producer this way changes no byte of
     * current behaviour and, crucially, fixes the SHAPE of the implementation before
     * anyone writes it at the decision fall-through, where it would silently miss
     * every anonymous request.
     *
     * <p>Enabling it changes no authorization decision in this gateway: the
     * {@code route_access} table remains the enforcement surface. It only makes the
     * already-validated brand legible to services behind the gateway.
     */
    private final boolean forwardDomainHeader;

    @Autowired
    public GatewayRouteAccessFilter(GatewayRouteAccessService routeAccess,
                                    DomainRegistry domainRegistry,
                                    @Value("${app.mfa.enforce-privileged-floor:false}")
                                            boolean enforcePrivilegedFloor,
                                    @Value("${app.mfa.freshness-window:600000}")
                                            long mfaFreshnessWindowMillis,
                                    @Value("${app.domain-header.forward:false}")
                                            boolean forwardDomainHeader) {
        this.routeAccess = routeAccess;
        this.domainRegistry = domainRegistry;
        this.enforcePrivilegedFloor = enforcePrivilegedFloor;
        this.mfaFreshnessWindowMillis = mfaFreshnessWindowMillis;
        this.forwardDomainHeader = forwardDomainHeader;
    }

    /** Pre-{@code domain-header} 4-arg convenience (stamp OFF) — keeps the D8 test
     *  call sites compiling and pins that the new flag's default leaves the filter
     *  unchanged. */
    public GatewayRouteAccessFilter(GatewayRouteAccessService routeAccess,
                                    DomainRegistry domainRegistry,
                                    boolean enforcePrivilegedFloor,
                                    long mfaFreshnessWindowMillis) {
        this(routeAccess, domainRegistry, enforcePrivilegedFloor,
                mfaFreshnessWindowMillis, false);
    }

    /** Legacy 2-arg convenience (privileged floor OFF, default 10m window, stamp
     *  OFF) — keeps the pre-D8 test call sites compiling and proves the dark
     *  defaults are the byte-identical legacy filter. Production wiring uses the
     *  {@code @Autowired} constructor above. */
    public GatewayRouteAccessFilter(GatewayRouteAccessService routeAccess,
                                    DomainRegistry domainRegistry) {
        this(routeAccess, domainRegistry, false, 600_000L, false);
    }

    /**
     * The canonical gateway-stamped brand header. The gateway is the SOLE authority
     * on its value: the inbound copy is dropped unconditionally, and the outbound
     * value — when {@link #forwardDomainHeader} is on — comes only from
     * {@link #targetDomain}. See {@link #normalizeDomainHeader}.
     */
    static final String X_DOMAIN = "X-Domain";

    @Override
    public Mono<Void> filter(ServerWebExchange inbound, WebFilterChain chain) {
        // TRUST BOUNDARY, applied UNCONDITIONALLY and FIRST — before the anonymous
        // fast-path, before the SUPERADMIN cross-domain bypass, before the
        // ADMIN/GAME-MASTER own-domain bypass, before decide(). `X-Domain` is a
        // CLIENT-SUPPLIED request header on the way in: anyone who can reach the
        // gateway can set it. Every one of the branches below reaches
        // `chain.filter(exchange)` on its own, so acting anywhere further down would
        // leave whole classes of request (anonymous traffic and every privileged
        // bypass) forwarding an attacker's value verbatim — and would leave the
        // OPT-IN stamp missing from exactly the anonymous traffic the header exists
        // for. Stripping here means a downstream can NEVER receive a client-forged
        // X-Domain, which is the precondition for stamping a validated one at all —
        // same trust posture ExternalAuthHeaderFilter holds for the External-* trio,
        // established BEFORE any consumer exists so the forwarding half can never
        // land on a spoofable header.
        final ServerWebExchange exchange = normalizeDomainHeader(inbound);
        String path = exchange.getRequest().getPath().value();
        // Wrap the principal in Optional + defaultIfEmpty so the stream emits
        // exactly one element: a present auth, or an explicit "absent". A bare
        // flatMap(...).switchIfEmpty(chain.filter(...)) is WRONG here — the
        // flatMap body returns Mono<Void> (always empty on the onNext channel),
        // so switchIfEmpty would fire even after a reject and forward downstream
        // anyway. The Optional makes present-vs-anonymous unambiguous.
        return exchange.getPrincipal()
            .cast(AbstractAuthenticationToken.class)
            .map(Optional::of)
            .defaultIfEmpty(Optional.empty())
            .flatMap(maybeAuth -> {
                if (maybeAuth.isEmpty()) {
                    // Anonymous — SecurityConfig already decided this path is
                    // reachable without auth, so forward untouched.
                    return chain.filter(exchange);
                }
                AbstractAuthenticationToken auth = maybeAuth.get();
                // Target brand for this request (Host -> registry suffix; "default"
                // on single-tenant). Computed once and threaded both into the
                // cross-domain hard-deny below AND the route-access fall-through, so
                // the GRANT layer can no longer re-grant a foreign-brand principal.
                String targetDomain = targetDomain(exchange);
                if (auth.getPrincipal() instanceof Jwt jwt) {
                    // ── D8 PRIVILEGED MFA FLOOR (HARD, PRE-BYPASS) ────────────────
                    // This MUST sit ABOVE the SUPERADMIN and ADMIN/GAME-MASTER
                    // bypasses below — those return chain.filter() BEFORE decide()
                    // ever consults authorities, so a naive mfa_required check in
                    // decide() would NEVER gate the very privileged roles whose MFA
                    // default is REQUIRED. Ships DARK behind its OWN sub-flag
                    // (app.mfa.enforce-privileged-floor, default false), so the
                    // legacy chain is byte-identical until an operator flips it.
                    if (enforcePrivilegedFloor) {
                        // COLD-START FAIL-CLOSED. Before route-access is primed the
                        // gateway can't know whether this path is an mfa_required
                        // surface (mfa_required rows live ONLY in the datastore, never
                        // the seed). Holding privileged principals with a 503 mirrors
                        // RevocationGatewayFilter.failClosedUntilPrimed rather than
                        // letting a privileged bypass slip through the unknown window.
                        // isPrimed() is TRUE when no datastore is wired (seed-only /
                        // dev) or route-access is disabled, so this never holds those.
                        if (!routeAccess.isPrimed()) {
                            return notPrimed(exchange, path);
                        }
                        // Only privileged principals (the ones that bypass below) are
                        // subject to the HARD floor here; everyone else is gated by the
                        // route-access decide() MFA check (G2). On an mfa_required
                        // surface a privileged principal lacking a FRESH second factor
                        // is DENIED — SUPERADMIN included.
                        boolean privileged = Roles.isSuperadmin(jwt)
                                || Roles.isAdmin(jwt) || Roles.isGameMaster(jwt);
                        if (privileged
                                && routeAccess.isMfaRequiredSurface(path, targetDomain)
                                && !Roles.isMfaSatisfied(jwt, System.currentTimeMillis(),
                                        mfaFreshnessWindowMillis)) {
                            return reject(exchange, path);
                        }
                    }
                    // SUPERADMIN — the ONLY cross-domain bypass. Reaches every
                    // surface in every brand without a domain match (infra
                    // control plane); short-circuits before route evaluation so
                    // it never has to satisfy any per-surface or AND-composite row.
                    if (Roles.isSuperadmin(jwt)) {
                        return chain.filter(exchange);
                    }
                    // HARD-DENY ON DOMAIN MISMATCH. A non-superadmin Casdoor
                    // principal whose own domain (DOMAIN_<x> authority, "default"
                    // for single-issuer) does NOT match the request's target domain
                    // is rejected OUTRIGHT — it never reaches the route-access GRANT
                    // layer. This closes the cross-tenant hole where a brand-Y
                    // `/api/admin/** -> ROLE_ADMIN allow=true` row (domain-blind on
                    // the role string alone) would otherwise RE-GRANT a brand-X
                    // admin denied the bypass. Superadmin already short-circuited
                    // above; default==default is exempt (single-tenant unaffected),
                    // so this is a no-op on single-Host gateway instances and the
                    // primary isolation for per-brand single-Host instances.
                    // SECURITY: derive principalDomain from the cryptographically-
                    // VALIDATED JWT ISSUER (via the registry), NOT from the
                    // authorities list. The authorities list is influenceable by
                    // claims the user can set (e.g. a forged permissions entry); the
                    // issuer is the trustworthy tenant discriminator (per-brand
                    // Casdoor => distinct, signature-validated iss). Using the issuer
                    // closes the authority-injection escalation where a brand-X token
                    // carrying permissions:["DOMAIN_brandy"] would otherwise present a
                    // forged DOMAIN_brandy and pass this gate onto brand-Y's surface.
                    String principalDomain = Roles.domainOf(jwt, domainRegistry);
                    if (!domainMatches(principalDomain, targetDomain)) {
                        return reject(exchange, path);
                    }
                    // ADMIN / GAME-MASTER — bypass within their OWN domain (the
                    // mismatch case is already rejected above, so reaching here
                    // means principalDomain == targetDomain). Single-tenant clusters
                    // match (default==default), so this is the current admin bypass
                    // unchanged.
                    if (Roles.isAdmin(jwt) || Roles.isGameMaster(jwt)) {
                        return chain.filter(exchange);
                    }
                } else {
                    // NON-JWT principal (e.g. an opaque bff_ session bridged by
                    // BffSessionAuthFilter to a UsernamePasswordAuthenticationToken).
                    // This MIRRORS the Jwt branch above, deriving the privileged questions
                    // from the AUTHORITY SET instead of the token: the authorities here are
                    // set by the gateway itself from admin-bff's introspect response (never
                    // from user-supplied claims), so they are trustworthy for the SAME
                    // SUPERADMIN / ADMIN / GAME-MASTER bypasses + MFA floor a Casdoor JWT
                    // gets. Without this, a native-login SUPERADMIN — which relies ENTIRELY
                    // on the bypass (there are no ROLE_SUPERADMIN route_access rows on
                    // admin/mod surfaces; superadmin ⊃ admin only via the bypass) — fell
                    // through to decide() and was DENIED every admin route (403 at the front
                    // door), even though admin-bff's own RoleHierarchy grants it.
                    Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();

                    // ── D8 PRIVILEGED MFA FLOOR (HARD, PRE-BYPASS) — mirrors the Jwt path.
                    // Same dark sub-flag; same cold-start fail-closed. MFA freshness is the
                    // MFA_SATISFIED authority's presence (admin-bff applies the window before
                    // stamping it — see Roles.isMfaSatisfied(Collection)).
                    if (enforcePrivilegedFloor) {
                        if (!routeAccess.isPrimed()) {
                            return notPrimed(exchange, path);
                        }
                        boolean privileged = Roles.isSuperadmin(authorities)
                                || Roles.isAdmin(authorities) || Roles.isGameMaster(authorities);
                        if (privileged
                                && routeAccess.isMfaRequiredSurface(path, targetDomain)
                                && !Roles.isMfaSatisfied(authorities)) {
                            return reject(exchange, path);
                        }
                    }

                    // SUPERADMIN — the ONLY cross-domain bypass, BEFORE the domain check
                    // (mirrors the Jwt branch: superadmin reaches every surface in every
                    // brand and never has to satisfy a per-surface row).
                    if (Roles.isSuperadmin(authorities)) {
                        return chain.filter(exchange);
                    }

                    // Cross-domain HARD-DENY (multi-issuer only). A non-JWT principal carries
                    // no validated issuer; its tenant is derived ONLY from a DOMAIN_<x>
                    // authority (Roles.domainOf(authorities), fail-closed -> null on ZERO or
                    // >1 DOMAIN_). On a single-issuer cluster every Host resolves to "default"
                    // and bff_ sessions carry no DOMAIN_ authority, so this is a no-op there
                    // (byte-identical) while failing CLOSED the instant a per-brand registry
                    // is configured — never re-granted by an unscoped admin seed row.
                    if (domainRegistry.isMultiIssuer()) {
                        String principalDomain = Roles.domainOf(authorities);
                        if (!domainMatches(principalDomain, targetDomain)) {
                            return reject(exchange, path);
                        }
                    }

                    // ADMIN / GAME-MASTER — bypass within their OWN domain (the cross-domain
                    // mismatch is already rejected above), mirroring the Jwt branch. A
                    // native-login admin whose surface has an explicit ROLE_ADMIN row would
                    // also pass decide() below; this additionally grants the admin/game-master
                    // OWN-domain bypass for surfaces without an explicit row, matching the JWT
                    // path exactly so the two carriers authorize identically.
                    if (Roles.isAdmin(authorities) || Roles.isGameMaster(authorities)) {
                        return chain.filter(exchange);
                    }
                }
                var userIds = new ArrayList<String>();
                if (auth.getPrincipal() instanceof Jwt jwt) {
                    addIfPresent(userIds, Roles.casdoorIdOf(jwt));
                    addIfPresent(userIds, Roles.usernameOf(jwt));
                    // MIRROR of the bff_ branch below: ALSO derive the durable-account
                    // identity forms a native-login session for this SAME user presents,
                    // so a pin written in the account-id form ("casdoor:<handle>" — e.g.
                    // a targeted deny copied verbatim from the account row) can no longer
                    // be dodged by carrier-shopping to a Casdoor JWT. Deny-wins semantics
                    // make every added identity strictly safe (it can only make a matching
                    // pin APPLY, never remove an existing deny).
                    addNativeAccountIdForms(userIds, jwt);
                } else if (auth.getPrincipal() instanceof String accountId) {
                    // Native-login (bff_) carrier: the principal is the account id
                    // (BffSessionAuthFilter sets me.id() = "<provider>:<handle>"). Populate
                    // userIds so a per-user casdoor_user route pin (targeted allow/deny)
                    // applies to a native-login session too — WITHOUT this a bff_ session
                    // had EMPTY userIds, so a pinned deny (targeted ban) silently degraded
                    // to a no-op and the user reached the surface simply by logging in
                    // natively instead of with a JWT. Add both the full account id and the
                    // bare handle (id with the "<provider>:" prefix stripped, matching the
                    // JWT branch's username identity) so a pin written as either form matches.
                    addIfPresent(userIds, accountId);
                    int sep = accountId == null ? -1 : accountId.indexOf(':');
                    if (sep >= 0 && sep + 1 < accountId.length()) {
                        addIfPresent(userIds, accountId.substring(sep + 1));
                    }
                    // A5 part-B (closes the previously-documented residual): admin-bff now
                    // persists the raw Casdoor `sub` UUID on the account row (changeset 292,
                    // stamped at the native-login mint) and surfaces it on introspect;
                    // BffSessionAuthFilter carries it here on the token's details slot. Add
                    // it in the SAME identity forms the JWT branch derives from the sub (the
                    // raw claim via casdoorIdOf, plus addNativeAccountIdForms' lowercased
                    // "casdoor:<sub>" and bare forms), so a UUID-form pin — an ALLOW grant
                    // or a targeted-ban DENY — now matches this user on BOTH carriers.
                    // ABSENT/BLANK (an admin-bff predating the field, or a legacy account
                    // row not yet re-stamped by a native login) adds NOTHING — byte-identical
                    // to the pre-field behavior. Deny-wins semantics keep every added id
                    // strictly safe (it can only make a matching pin APPLY, never remove a
                    // deny).
                    if (auth.getDetails() instanceof BffSessionAuthFilter.SessionDetails details
                            && details.casdoorSub() != null && !details.casdoorSub().isBlank()) {
                        String sub = details.casdoorSub().trim();
                        addUnique(userIds, sub);
                        String lower = sub.toLowerCase(Locale.ROOT);
                        addUnique(userIds, CASDOOR_ACCOUNT_PREFIX + lower);
                        addUnique(userIds, lower);
                    }
                }
                // Pass the full Spring authority strings (ROLE_USER, ROLE_ADMIN,
                // bare permissions) — exactly what the route_access.role column
                // holds; the service normalizes the ROLE_ prefix when matching.
                var authorities = new ArrayList<String>();
                for (var ga : auth.getAuthorities()) {
                    if (ga.getAuthority() != null) authorities.add(ga.getAuthority());
                }
                if (routeAccess.decide(path, targetDomain, userIds, authorities) == Decision.DENY) {
                    return reject(exchange, path);
                }
                // NOTE (issue #4, TODO 2): the X-Domain producer is NOT here. Both
                // halves live at the top of filter() in normalizeDomainHeader — the
                // strip unconditionally, the stamp behind app.domain-header.forward.
                // This line looks like the natural home for it (targetDomain is in
                // hand) and it is the WRONG one: the consumer the header exists for
                // scopes ANONYMOUS reads, and an anonymous request returns from the
                // first branch above without ever reaching this statement, as do both
                // privileged bypasses. What remains open is the CONSUMER, not the
                // producer — no service in the org reads an inbound X-Domain request
                // header yet (hugmesh-games' DomainGuardFilter SETS an
                // X-Domain-Denied RESPONSE header and scopes off the JWT's DOMAIN_
                // authority), so the stamp stays default-off until games decision
                // 026's public-catalog brand filter lands.
                return chain.filter(exchange);
            });
    }

    /**
     * Make the gateway the SOLE authority on {@code X-Domain}: drop any
     * CLIENT-supplied copy, then — only when {@link #forwardDomainHeader} is on —
     * stamp the registry-validated brand this request's {@code Host} resolves to.
     *
     * <p>Mirrors {@code ExternalAuthHeaderFilter.stripInbound} + stamp: the inbound
     * copy is dropped unconditionally, on EVERY path and for every principal
     * (anonymous included) and in BOTH flag states, so a downstream can never
     * receive a caller-forged value — and the value that may replace it is computed
     * here from {@link #targetDomain}, never read back off the request.
     *
     * <p><b>Order matters inside the mutation.</b> The remove runs BEFORE the add on
     * the same {@link HttpHeaders}, so a request arriving with
     * {@code X-Domain: brandy} leaves carrying exactly one {@code X-Domain} — the
     * gateway's — and not two values, where a downstream reading {@code getFirst}
     * could pick up the attacker's.
     *
     * <p>With the stamp OFF and no inbound header this returns the exchange
     * UNCHANGED, so the overwhelmingly common request allocates no mutated exchange
     * and the filter is byte-identical to its pre-flag behaviour.
     */
    private ServerWebExchange normalizeDomainHeader(ServerWebExchange exchange) {
        // get(), not getFirst(): presence is the question, not the value. getFirst
        // answers null for BOTH "absent" and "present with an empty value list", so
        // it would leave that second case forwarded; get() only answers null when
        // the header name is genuinely absent. Case-insensitivity comes from
        // HttpHeaders itself, so `x-domain:` is caught by the same lookup.
        boolean inboundPresent = exchange.getRequest().getHeaders().get(X_DOMAIN) != null;
        if (!inboundPresent && !forwardDomainHeader) return exchange;
        // The SAME derivation the route-access decision uses below, so a downstream
        // scoping on this header and this gateway gating on the table can never
        // disagree about which brand the request is for.
        final String stamped = forwardDomainHeader ? targetDomain(exchange) : null;
        return exchange.mutate()
                .request(b -> b.headers(h -> {
                    h.remove(X_DOMAIN);
                    if (stamped != null) h.add(X_DOMAIN, stamped);
                }))
                .build();
    }

    private static void addIfPresent(List<String> list, String value) {
        if (value != null && !value.isBlank()) list.add(value);
    }

    /** The account-id prefix admin-bff mints for Casdoor-verified identities
     *  ({@code AccountStore.idFor("casdoor", handle)}) — every JWT reaching this
     *  filter is Casdoor-issued, so this is the only provider a JWT can map to. */
    private static final String CASDOOR_ACCOUNT_PREFIX = "casdoor:";

    /**
     * Native-login account identity forms derivable from a validated Casdoor JWT.
     *
     * <p>admin-bff mints the durable account as {@code id = "casdoor:" +
     * lowercase(handle)} with the handle drawn from the id_token as
     * {@code email > preferred_username > sub}
     * ({@code InternalAccountController.SUBJECT_CLAIMS} + {@code AccountStore.idFor});
     * a bare-handle ensure call passes the Casdoor username through verbatim. The
     * gateway cannot know which claim was present at account-mint time, so it adds
     * EVERY candidate — in both the prefixed account-id form and the bare-handle
     * form the bff_ branch emits — lowercased to match the mint (the pin match is
     * exact equality). A candidate the account was NOT minted from is inert
     * (matches no row), so a wrong guess fails safe.
     */
    private static void addNativeAccountIdForms(List<String> userIds, Jwt jwt) {
        String[] candidates = {
                jwt.getClaimAsString("email"),
                jwt.getClaimAsString("preferred_username"),
                Roles.casdoorIdOf(jwt),
                Roles.usernameOf(jwt),
        };
        for (String candidate : candidates) {
            if (candidate == null || candidate.isBlank()) continue;
            String handle = candidate.trim().toLowerCase(Locale.ROOT);
            addUnique(userIds, CASDOOR_ACCOUNT_PREFIX + handle);
            addUnique(userIds, handle);
        }
    }

    private static void addUnique(List<String> list, String value) {
        if (!list.contains(value)) list.add(value);
    }

    /**
     * Target brand for this request, from the {@code Host} header (falling back
     * to the request URI host) mapped through the registry's host-suffix table.
     * Returns {@code "default"} when single-issuer OR the host is unmapped, so
     * single-tenant clusters always match. The Host check is defense-in-depth:
     * per-brand gateway INSTANCES (each serving only its own Host + selecting only
     * its own rows {@code WHERE gateway=:gw}) are the primary isolation; this
     * denies a token minted for brand-Y presented to brand-X's gateway even if
     * instance isolation is misconfigured. The target domain comes from a
     * registry-validated host suffix, never a raw substring of an attacker-set
     * Host.
     */
    private String targetDomain(ServerWebExchange exchange) {
        String host = exchange.getRequest().getHeaders().getFirst(HttpHeaders.HOST);
        if (host == null) {
            URI uri = exchange.getRequest().getURI();
            host = uri == null ? null : uri.getHost();
        }
        if (host != null) {
            int c = host.indexOf(':');
            if (c >= 0) host = host.substring(0, c);   // strip port
        }
        String d = domainRegistry.domainForHost(host);
        return d == null ? DomainRegistry.DEFAULT_DOMAIN : d;
    }

    /** Single-tenant ({@code "default"}) matches everything (back-compat).
     *  Otherwise the principal's domain must equal the target's. A null principal
     *  domain fails closed. */
    private static boolean domainMatches(String principalDomain, String targetDomain) {
        if (principalDomain == null) return false;                              // fail-closed
        if (DomainRegistry.DEFAULT_DOMAIN.equals(principalDomain)
                && DomainRegistry.DEFAULT_DOMAIN.equals(targetDomain)) {
            return true;                                                        // single-issuer cluster
        }
        return principalDomain.equals(targetDomain);
    }

    private Mono<Void> reject(ServerWebExchange exchange, String path) {
        log.warn("[route-access] denied — gateway={} path={}", routeAccess.gatewayName(), path);
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        exchange.getResponse().getHeaders().add("X-Route-Denied",
                routeAccess.gatewayName() + ":" + path);
        return exchange.getResponse().setComplete();
    }

    /** D8 cold-start fail-CLOSED hold for the privileged MFA floor: route-access has
     *  not been primed from the datastore yet, so the gateway cannot tell whether
     *  this path is an mfa_required surface. Respond 503 + short Retry-After so the
     *  caller backs off until the first load lands — intentionally NOT a 403 (the
     *  surface is not known-gated, the floor is simply not yet authoritative).
     *  Mirrors {@code RevocationGatewayFilter.notPrimed}. */
    private Mono<Void> notPrimed(ServerWebExchange exchange, String path) {
        log.warn("[route-access] holding privileged request fail-CLOSED — route-access not yet primed, "
                + "gateway={} path={}", routeAccess.gatewayName(), path);
        exchange.getResponse().setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
        exchange.getResponse().getHeaders().add(HttpHeaders.RETRY_AFTER, "5");
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        // Run AFTER Spring Security's WebFilterChainProxy (order -100) so
        // exchange.getPrincipal() resolves — see the ordering note on
        // RevocationGatewayFilter#getOrder. Before the ordering fix this filter ran
        // at Integer.MIN_VALUE+250 (far before -100), saw no principal, and forwarded
        // every authenticated request through its anonymous branch — so the
        // cross-tenant domain HARD-DENY, the SUPERADMIN bypass and the route-access
        // DENY all failed OPEN. A positive order keeps it after External-Authorization
        // header injection (20) and before the games resource-access filter (30).
        return 25;
    }
}
