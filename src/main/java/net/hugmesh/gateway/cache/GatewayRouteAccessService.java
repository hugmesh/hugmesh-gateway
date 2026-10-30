package net.hugmesh.gateway.cache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.client.circuitbreaker.ReactiveCircuitBreaker;
import org.springframework.cloud.client.circuitbreaker.ReactiveCircuitBreakerFactory;
import org.springframework.data.cassandra.core.ReactiveCassandraTemplate;
import org.springframework.data.cassandra.core.cql.ReactiveCqlOperations;
import org.springframework.lang.Nullable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;
import reactor.core.publisher.Mono;
import net.hugmesh.gateway.security.DomainRegistry;

import jakarta.annotation.PostConstruct;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Per-gateway external-access enforcement — the missing layer that turns the
 * static route config into a role-checked front door. For THIS gateway
 * ({@code spring.application.name}) it answers "may this principal reach this
 * URL pattern from outside?" against the admin-managed
 * {@code gateway_route_access} rule set.
 *
 * <p><b>Source of truth vs. read-cache (the route-access contract).</b>
 * <ul>
 *   <li><b>Postgres</b> ({@code ROUTE_ACCESS_R2DBC_URL}) is the SOURCE OF TRUTH —
 *       the admin-api CRUDs the canonical rows
 *       ({@code id, gateway, url_pattern, role, casdoor_user, allow}; schema at
 *       {@code cluster/manifests/route-access/schema.sql}). The gateway SELECTs
 *       ONLY its own gateway's rows, reactively, on startup and on every refresh
 *       tick.</li>
 *   <li><b>Cassandra</b> ({@code hugmesh_gateway.gateway_route_access}) is the
 *       cluster READ-CACHE. After each successful Postgres load the gateway
 *       write-through-mirrors the rows into Cassandra; if Postgres is briefly
 *       unreachable the gateway falls back to the Cassandra snapshot so the last
 *       known rules keep being enforced (no fail-open).</li>
 *   <li>If neither is configured (pure unit test / minimal dev) the in-memory
 *       canonical seed (the contract's seed for this gateway) is used so the
 *       enforcement is never silently absent.</li>
 * </ul>
 *
 * <p><b>An EMPTY load is never authoritative (hugmesh-gateway#61).</b> A refresh
 * result with zero rows for this gateway, from EITHER source, never replaces the
 * current snapshot: the {@link CanonicalSeed} floor at cold start, or the last
 * non-empty load after that. The seed is never empty for any gateway name (the
 * baked pki/be/fe tiers carry 3/32/44 rows, the route-access database seed
 * 4/60/95, and an unknown name gets a closed {@code /** -> ROLE_ADMIN} floor),
 * so a gateway with zero rules is never an intended state. It is what a fresh
 * Cassandra cache returns while Postgres rejects the gateway's login, and
 * installing it made every path {@code NO_RULE}, so the gate failed OPEN. A NON-empty load is installed in
 * full, so an admin deleting some rows still takes effect on the next tick;
 * deleting EVERY row of a gateway is refused and reported.
 *
 * <p><b>Degraded state.</b> While a datastore is wired but the authoritative one
 * (Postgres when wired, else the Cassandra cache) did not supply this tick's
 * snapshot, {@link #degradedReason()} is non-null, the transition is logged at
 * ERROR, and {@code RouteAccessHealthIndicator} reports {@code DOWN}.
 *
 * <p><b>Role derivation.</b> The {@code role} column holds Casdoor roles in the
 * Spring authority form ({@code ROLE_USER}, {@code ROLE_ADMIN}, …) — exactly the
 * authorities the {@code casdoorAuthoritiesConverter} derives from the JWT
 * (every principal floors to {@code ROLE_USER}; each {@code roles} claim entry
 * becomes {@code ROLE_<UPPER>}; {@code permissions} stay non-prefixed; legacy
 * {@code isAdmin} ⇒ {@code ROLE_ADMIN}). The {@code public} role (and the
 * built-in public-floor patterns) permit anonymous traffic.
 *
 * <p><b>Decision = longest-matching pattern.</b> For a request path the rule
 * whose {@code url_pattern} matches AND is the most specific (longest pattern)
 * decides — so {@code /api/admin/**=ROLE_ADMIN} overrides a broader
 * {@code /api/**=ROLE_USER} on the same path. Among rules sharing the longest
 * pattern, the principal is allowed iff an {@code allow} rule's role is held
 * (with the optional {@code casdoor_user} pin) and no {@code allow=false} rule
 * for a held role/pinned user denies it (explicit deny wins). A governed path
 * with no granting rule ⇒ DENY (default-deny). An ungoverned path ⇒ NO_RULE
 * (the coarse SecurityConfig gate already authenticated it).
 */
@Service
public class GatewayRouteAccessService {

    private static final Logger log = LoggerFactory.getLogger(GatewayRouteAccessService.class);
    private static final AntPathMatcher MATCHER = new AntPathMatcher();

    /** Role value meaning "no authentication required" for a pattern. */
    private static final String PUBLIC_ROLE = "PUBLIC";

    /** The implicit floor every authenticated principal carries. */
    public static final String ROLE_USER = "ROLE_USER";

    /** Outcome of evaluating a request path against this gateway's rules. */
    public enum Decision { ALLOW, DENY, NO_RULE }

    /**
     * A route-access rule in the canonical contract shape
     * ({@code gateway_route_access}). {@code role} is a Spring authority
     * ({@code ROLE_USER}, {@code ROLE_ADMIN}, or {@code PUBLIC}). {@code casdoorUser}
     * is an optional pin: when set, the rule applies ONLY to that Casdoor user
     * (id or username) in addition to the role check.
     *
     * <p>{@code domain} is the per-row BRAND scope (multi-brand architecture tier).
     * {@code null} or {@code "default"} means the row applies to ANY target domain
     * (back-compat — single-tenant + the canonical seed never set it); a per-brand
     * row carries its own domain so a brand-Y {@code /api/admin/** -> ROLE_ADMIN}
     * grant can NEVER be re-granted to a brand-X admin. The filter passes the
     * request's target domain (derived from {@code Host}) into {@link #decide} and
     * {@link #appliesTo} requires the rule's domain to be unscoped OR equal it.
     *
     * <p>{@code mfaRequired} (D8 gateway MFA floor) is the per-row second-factor
     * gate: {@code true} means the DECIDING longest-pattern rule additionally
     * requires the principal to carry the {@code MFA_SATISFIED} marker (a fresh
     * BFF-stamped second factor); {@code false} (the {@code NOT NULL DEFAULT false}
     * column default — every pre-existing row, the canonical seed and single-tenant
     * rows) leaves behaviour byte-identical. See {@link #decide}.
     */
    public record Rule(String id, String gateway, String urlPattern,
                       String role, @Nullable String casdoorUser, boolean allow,
                       @Nullable String domain, boolean mfaRequired) {}

    private final ReactiveCqlOperations cql;
    /** Reactive route-access SOURCE-OF-TRUTH repository (Postgres). {@code null}
     *  when {@code app.route-access.r2dbc-url} is unset (Cassandra-cache-only /
     *  dev / unit-test wiring). */
    private final GatewayRouteAccessRepository routeAccessRepository;
    private final String gatewayName;
    private final boolean enabled;
    /** D8 gateway MFA floor — {@code app.mfa.enabled} (default {@code false}, ships
     *  dark). When {@code false} the {@code mfa_required} per-row gate is INERT
     *  (decide() ignores it) so behaviour is byte-identical to legacy; when
     *  {@code true} a deciding rule with {@code mfa_required=true} additionally
     *  requires the {@code MFA_SATISFIED} authority (fail-closed). */
    private final boolean mfaEnabled;
    /** Guards the refresh-path datastore reads; {@code null} in minimal/test wiring. */
    private final ReactiveCircuitBreaker refreshBreaker;

    /** Snapshot of the rules scoped to THIS gateway. Atomically swapped. */
    private volatile List<Rule> rules = List.of();
    private volatile Instant lastRefreshAt = Instant.EPOCH;
    private volatile String source = "seed";
    /** Why the gateway is NOT enforcing a fresh load from its authoritative source,
     *  or {@code null} when it is (or when no datastore is wired, so the seed IS the
     *  authority). Read by {@code RouteAccessHealthIndicator}. */
    private volatile String degradedReason = null;
    private volatile Instant degradedSince = null;
    /** The snapshot source last logged as degraded (log-on-change bookkeeping). */
    private volatile String degradedEnforcing = null;

    public GatewayRouteAccessService(
            @Nullable ReactiveCassandraTemplate template,
            @Nullable GatewayRouteAccessRepository routeAccessRepository,
            @Value("${spring.application.name:hugmesh-gateway}") String gatewayName,
            @Value("${app.route-access.enabled:true}") boolean enabled,
            @Value("${app.mfa.enabled:false}") boolean mfaEnabled,
            @Nullable ReactiveCircuitBreakerFactory<?, ?> circuitBreakerFactory) {
        this.cql = template != null ? template.getReactiveCqlOperations() : null;
        this.routeAccessRepository = routeAccessRepository;
        this.gatewayName = gatewayName;
        this.enabled = enabled;
        this.mfaEnabled = mfaEnabled;
        // Dedicated breaker instance (tuned by GatewayResilienceConfig). Absent in
        // minimal/test wiring, where reads run unguarded.
        this.refreshBreaker = circuitBreakerFactory != null
                ? circuitBreakerFactory.create("routeAccess")
                : null;
    }

    @PostConstruct
    void init() {
        if (!enabled) {
            log.info("[route-access] disabled (app.route-access.enabled=false) — DENY is never enforced");
            return;
        }
        // Seed the in-memory snapshot synchronously so the gate is never
        // fail-open even before the first Postgres/Cassandra round-trip.
        this.rules = CanonicalSeed.forGateway(gatewayName);
        this.source = "seed";
        if (datastoreWired()) {
            // Not yet loaded: the seed is a floor, not the configured authority.
            this.degradedReason = authoritativeSource() + " not loaded yet; enforcing the seed floor";
            this.degradedSince = Instant.now();
        }
        refreshNow().subscribe();
    }

    /**
     * Evaluate a request path for a principal. {@code targetDomain} is the BRAND
     * the request is addressed to (derived from {@code Host} by the filter;
     * {@code "default"} on single-tenant clusters) — a per-brand rule only applies
     * when its {@code domain} is unscoped OR equals this; an unscoped rule applies
     * to any domain (back-compat). {@code userIdentifiers} carries every id the
     * {@code casdoor_user} pin might match (Casdoor id AND username);
     * {@code authorities} are the Spring authority strings the principal holds
     * (e.g. {@code ROLE_USER}, {@code ROLE_ADMIN}) — exactly what the JWT
     * converter derived. Cache-only — constant-time longest-pattern walk.
     */
    public Decision decide(String path, String targetDomain,
                           Collection<String> userIdentifiers,
                           Collection<String> authorities) {
        Outcome o = evaluate(path, targetDomain, userIdentifiers, authorities);
        return o == Outcome.DENY_MFA ? Decision.DENY : Decision.valueOf(o.name());
    }

    /**
     * True iff {@link #decide} DENIES this request and the ONLY thing missing is a
     * fresh second factor: the principal is otherwise granted by a deciding
     * {@code mfa_required} row (no explicit deny, a granting rule is held) but lacks
     * {@code MFA_SATISFIED}. A role denial, an explicit deny, an ungranted governed
     * path and every non-DENY outcome answer {@code false} — so a caller who cannot be
     * helped by an MFA challenge is never told to start one. Same evaluation as
     * {@link #decide}, never a second rule walk with its own semantics.
     */
    public boolean isMfaStepUpDenial(String path, String targetDomain,
                                     Collection<String> userIdentifiers,
                                     Collection<String> authorities) {
        return evaluate(path, targetDomain, userIdentifiers, authorities) == Outcome.DENY_MFA;
    }

    /** {@link Decision} plus the one deny flavour a client can fix by satisfying MFA. */
    private enum Outcome { ALLOW, DENY, DENY_MFA, NO_RULE }

    private Outcome evaluate(String path, String targetDomain,
                             Collection<String> userIdentifiers,
                             Collection<String> authorities) {
        if (path == null) return Outcome.NO_RULE;
        List<Rule> snapshot = rules;

        // 1) Find the longest url_pattern that matches the path. The most
        //    specific rule wins, so /api/admin/** beats /api/** for an admin URL.
        int bestLen = -1;
        for (Rule r : snapshot) {
            if (r.urlPattern() == null || !MATCHER.match(r.urlPattern(), path)) continue;
            int len = r.urlPattern().length();
            if (len > bestLen) bestLen = len;
        }
        if (bestLen < 0) return Outcome.NO_RULE;   // ungoverned path

        // 2) Among the rules at that longest pattern, apply deny-wins over the
        //    principal's held authorities (respecting the casdoor_user pin AND the
        //    per-row domain scope).
        boolean allowed = false;
        boolean explicitDeny = false;
        // D8 MFA floor: does the DECIDING grant (the longest-pattern allow row the
        // principal actually satisfies) require a fresh second factor? Tracked only
        // when app.mfa.enabled — otherwise the column is inert (legacy behaviour).
        boolean mfaRequiredOnGrant = false;
        for (Rule r : snapshot) {
            if (r.urlPattern() == null || r.urlPattern().length() != bestLen
                    || !MATCHER.match(r.urlPattern(), path)) continue;
            if (!domainApplies(r, targetDomain)) continue;
            if (isPublic(r)) {
                allowed = true;
                if (mfaEnabled && r.mfaRequired()) mfaRequiredOnGrant = true;
                continue;
            }
            if (!appliesTo(r, userIdentifiers, authorities)) continue;
            if (r.allow()) {
                allowed = true;
                // The principal SATISFIES this allow row; if it carries mfa_required
                // the deciding grant demands the MFA_SATISFIED marker. (Only the rows
                // that actually grant the principal can pull the floor up — a foreign
                // brand / unheld-role mfa_required row that never grants here is
                // irrelevant; longest-pattern-match already scoped the set.)
                if (mfaEnabled && r.mfaRequired()) mfaRequiredOnGrant = true;
            } else {
                explicitDeny = true;
            }
        }
        if (explicitDeny) return Outcome.DENY;
        if (!allowed) return Outcome.DENY;                // governed-but-ungranted ⇒ deny
        // D8 fail-closed: a deciding grant that demands MFA but the principal lacks
        // the MFA_SATISFIED marker is DENIED (absent marker => not satisfied; a
        // client_credentials / no-MFA / stale-stamp principal never carries it).
        if (mfaRequiredOnGrant
                && (authorities == null || !authorities.contains(net.hugmesh.gateway.security.Roles.MFA_SATISFIED))) {
            return Outcome.DENY_MFA;
        }
        return Outcome.ALLOW;
    }

    /**
     * True iff the rule's per-row {@code domain} scope admits the request's
     * {@code targetDomain}. A {@code null}/blank/{@code "default"} rule domain is
     * UNSCOPED and applies to any target (back-compat: single-tenant + the
     * canonical seed never set it); otherwise the rule applies ONLY to its own
     * domain. This is what stops a brand-Y {@code /api/admin/** -> ROLE_ADMIN
     * allow=true} row from re-granting a brand-X admin on brand-Y's surface.
     */
    private static boolean domainApplies(Rule r, String targetDomain) {
        String rd = r.domain();
        if (rd == null || rd.isBlank()
                || DomainRegistry.DEFAULT_DOMAIN.equalsIgnoreCase(rd.trim())) {
            return true;   // unscoped rule — applies to any brand
        }
        return rd.trim().equalsIgnoreCase(targetDomain == null ? null : targetDomain.trim());
    }

    private static boolean isPublic(Rule r) {
        return r.allow() && r.role() != null && PUBLIC_ROLE.equalsIgnoreCase(r.role().trim());
    }

    /**
     * True iff the rule's role is held by the principal AND (if the rule pins a
     * {@code casdoor_user}) one of the principal's identifiers matches that pin.
     *
     * <p><b>ROLE-typed match only (authority-injection defense; CWE-863).</b> A
     * route-access {@code role} column ALWAYS names a Casdoor role (the canonical
     * {@code ROLE_<X>} authority, or the legacy bare-name seed shape {@code admin} —
     * both mean "the role X"). It is therefore satisfied ONLY by a held authority
     * that ALSO carries the canonical {@code ROLE_} prefix. A held authority WITHOUT
     * the prefix is a verbatim Casdoor PERMISSION (the {@code casdoorAuthoritiesConverter}
     * passes {@code permissions} entries through non-prefixed) and MUST NOT be
     * treated as role-equivalent — otherwise a token carrying
     * {@code permissions:["admin"]} / {@code permissions:["superadmin"]} would
     * normalize to {@code ADMIN}/{@code SUPERADMIN} and satisfy a
     * {@code ROLE_ADMIN}/{@code ROLE_SUPERADMIN} route rule, bypassing the role
     * gate PAST the converter's reserved-prefix guard (which only blocks a
     * permission from forging the {@code ROLE_}/{@code DOMAIN_} prefix, not from
     * carrying a bare role NAME). The match stays case-insensitive and tolerant of
     * the rule being stored bare ({@code admin}): we canonicalize the rule to its
     * role name and require the held side to be a genuine {@code ROLE_*} authority
     * for that name.
     */
    private static boolean appliesTo(Rule r, Collection<String> userIdentifiers,
                                     Collection<String> authorities) {
        if (r.role() == null || authorities == null) return false;
        String want = normalizeRole(r.role());
        boolean roleHeld = false;
        for (String a : authorities) {
            // A role rule is satisfied ONLY by a ROLE_-prefixed held authority.
            // Skip bare permissions so they can never inject role-equivalence.
            if (a != null && isRolePrefixed(a) && normalizeRole(a).equals(want)) {
                roleHeld = true;
                break;
            }
        }
        if (!roleHeld) return false;
        String pin = r.casdoorUser();
        if (pin == null || pin.isBlank()) return true;   // role-only rule
        if (userIdentifiers == null) return false;
        for (String id : userIdentifiers) {
            if (id != null && id.equals(pin)) return true;
        }
        return false;
    }

    /** Strip a {@code ROLE_} prefix and upper-case, so {@code ROLE_ADMIN},
     *  {@code role_admin} and {@code ADMIN} all compare equal. */
    private static String normalizeRole(String s) {
        String t = s.trim();
        if (t.regionMatches(true, 0, "ROLE_", 0, 5)) t = t.substring(5);
        return t.toUpperCase();
    }

    /** True iff a HELD authority carries the canonical {@code ROLE_} prefix (the
     *  marker that distinguishes a genuine role authority from a verbatim Casdoor
     *  permission). Only such authorities may satisfy a route-access role rule —
     *  see {@link #appliesTo}. Case-insensitive ({@code role_admin} counts). */
    private static boolean isRolePrefixed(String authority) {
        return authority != null && authority.trim().regionMatches(true, 0, "ROLE_", 0, 5);
    }

    public Instant lastRefreshAt() {
        return lastRefreshAt;
    }

    /** Where the current snapshot came from: {@code postgres}, {@code cassandra} or {@code seed}. */
    public String source() {
        return source;
    }

    public int ruleCount() {
        return rules.size();
    }

    /** {@code false} when {@code app.route-access.enabled=false} (the gate is off). */
    public boolean isEnabled() {
        return enabled;
    }

    /** Why the current snapshot is not a fresh load from the authoritative source
     *  ({@code null} when it is, or when no datastore is wired). See the class doc. */
    @Nullable
    public String degradedReason() {
        return degradedReason;
    }

    /** When the current degraded spell began ({@code null} when not degraded). */
    @Nullable
    public Instant degradedSince() {
        return degradedSince;
    }

    /** The source this gateway treats as authoritative: {@code postgres} when the
     *  source of truth is wired (including a set-but-invalid URL, which
     *  {@code RouteAccessR2dbcConfig} wires as an always-failing repository),
     *  {@code cassandra} when only the cache is, else {@code seed}. */
    public String authoritativeSource() {
        if (routeAccessRepository != null) return "postgres";
        if (cql != null) return "cassandra";
        return "seed";
    }

    private boolean datastoreWired() {
        return routeAccessRepository != null || cql != null;
    }

    /** This gateway's instance name ({@code spring.application.name}). */
    public String gatewayName() {
        return gatewayName;
    }

    /**
     * True once the route-access snapshot is AUTHORITATIVE for MFA decisions — i.e.
     * a datastore load has actually succeeded, OR no external datastore is wired so
     * the baked-in {@link CanonicalSeed} floor IS the authority. Mirrors
     * {@link RevocationListService#isPrimed}.
     *
     * <p>Before decision 56 (hugmesh-generator#347, 2026-09-18) the seed floor
     * NEVER carried {@code mfa_required=true} at all, so "no datastore wired"
     * trivially meant "no mfa_required rows to discover". Decision 56 gives
     * {@link CanonicalSeed#MFA_REQUIRED_FALLBACK_ROWS} true on the SEED itself —
     * this method's safety property still holds, for a different reason: when NO
     * datastore is wired the seed is never superseded by anything, so it is
     * authoritative from the first request with no discovery lag, and its declared
     * rows already answer {@link #isMfaRequiredSurface} correctly. The case this
     * method still guards is a datastore that IS wired but has not yet loaded —
     * THERE the seed's mfa_required=false default (every row outside the declared
     * set, and every row before decision 56) could understate a Postgres row's
     * true mfa_required=true, so the {@code GatewayRouteAccessFilter} holds the
     * request fail-CLOSED (503) until {@code lastRefreshAt} moves. When NO
     * datastore is wired (route-access disabled, or pure seed/dev) this returns
     * {@code true} and the floor is never a 503 on single-tenant/dev — the seed's
     * own mfa_required rows (declared-set ones included) are enforced immediately,
     * not skipped.
     */
    public boolean isPrimed() {
        if (!enabled) return true;                 // gate never enforced -> nothing to prime
        boolean datastoreWired = datastoreWiredOverrideForTest != null
                ? datastoreWiredOverrideForTest
                : datastoreWired();
        if (!datastoreWired) return true;          // seed IS authoritative (no mfa_required rows)
        return lastRefreshAt.isAfter(Instant.EPOCH);
    }

    /** Test-only override forcing {@link #isPrimed} to treat a datastore as WIRED
     *  even with no live client (no datastore in a unit test), so the never-primed
     *  cold-start window the privileged floor fails closed on can be exercised.
     *  {@code null} in production — {@link #isPrimed} uses the real client state. */
    private volatile Boolean datastoreWiredOverrideForTest = null;

    /**
     * True iff the DECIDING longest-pattern rule(s) for this path/domain carry
     * {@code mfa_required=true} — i.e. reaching this surface demands a fresh second
     * factor. Used by the {@code GatewayRouteAccessFilter} HARD privileged-floor
     * check that sits ABOVE the SUPERADMIN / ADMIN bypasses (those return
     * {@code chain.filter()} BEFORE {@link #decide}, so a privileged principal would
     * otherwise never be MFA-gated). Same longest-pattern + domain-scope semantics
     * as {@link #decide} so the floor and the grant agree on which rule decides.
     */
    public boolean isMfaRequiredSurface(String path, String targetDomain) {
        if (path == null) return false;
        List<Rule> snapshot = rules;
        int bestLen = -1;
        for (Rule r : snapshot) {
            if (r.urlPattern() == null || !MATCHER.match(r.urlPattern(), path)) continue;
            if (!domainApplies(r, targetDomain)) continue;
            int len = r.urlPattern().length();
            if (len > bestLen) bestLen = len;
        }
        if (bestLen < 0) return false;             // ungoverned path — no floor
        for (Rule r : snapshot) {
            if (r.urlPattern() == null || r.urlPattern().length() != bestLen
                    || !MATCHER.match(r.urlPattern(), path)) continue;
            if (!domainApplies(r, targetDomain)) continue;
            if (r.mfaRequired()) return true;
        }
        return false;
    }

    @Scheduled(fixedDelayString = "${app.route-access.refresh-interval-ms:5000}")
    void refresh() {
        if (!enabled) return;
        refreshNow().subscribe();
    }

    /**
     * Refresh order: Postgres (source of truth) → on success mirror into
     * Cassandra; on Postgres failure (or absence) fall back to the Cassandra
     * read-cache; if both are unavailable keep the current snapshot (the
     * canonical seed at worst). Never fail-open.
     *
     * <p>A load that returns ZERO rows is treated like a failed one: it is never
     * installed (hugmesh-gateway#61). An empty Postgres result therefore also falls
     * through to the Cassandra cache, and an empty Cassandra result keeps the
     * current snapshot. Package-private so tests can block on one tick.
     */
    Mono<Void> refreshNow() {
        Tick tick = new Tick();
        Mono<List<Rule>> fromPostgres = (routeAccessRepository == null)
                ? Mono.empty()
                : guarded(loadFromPostgres(), "postgres", tick)
                    .filter(loaded -> nonEmpty(loaded, "postgres", tick))
                    .doOnNext(loaded -> {
                        swap(loaded, "postgres");
                        tick.installed = "postgres";
                        mirrorToCassandra(loaded).subscribe();
                    })
                    .onErrorResume(e -> {
                        tick.fail("postgres", "load failed: " + e.getMessage());
                        log.warn("[route-access] Postgres load failed ({}), trying Cassandra cache",
                                e.getMessage());
                        return Mono.empty();
                    });

        Mono<List<Rule>> fromCassandra = guarded(loadFromCassandra(), "cassandra", tick)
                .filter(loaded -> nonEmpty(loaded, "cassandra", tick))
                .doOnNext(loaded -> {
                    swap(loaded, "cassandra");
                    tick.installed = "cassandra";
                })
                .onErrorResume(e -> {
                    tick.fail("cassandra", "load failed: " + e.getMessage());
                    log.warn("[route-access] Cassandra cache load failed ({}), keeping current snapshot",
                            e.getMessage());
                    return Mono.empty();
                });

        // switchIfEmpty so Cassandra is only consulted when Postgres yields nothing.
        return fromPostgres.switchIfEmpty(fromCassandra)
                .then(Mono.fromRunnable(() -> assess(tick)));
    }

    /** What one refresh tick did: which source (if any) it installed, and why the
     *  others did not count. Confined to a single tick's reactive chain. */
    private static final class Tick {
        volatile String installed;          // "postgres" | "cassandra" | null
        volatile String postgresProblem;
        volatile String cassandraProblem;

        void fail(String src, String why) {
            if ("postgres".equals(src)) {
                if (postgresProblem == null) postgresProblem = why;
            } else if (cassandraProblem == null) {
                cassandraProblem = why;
            }
        }
    }

    /** {@code true} iff {@code loaded} may replace the current snapshot. An empty
     *  list never may (hugmesh-gateway#61): it is recorded as this tick's problem
     *  for {@code src} and the caller's fallback chain takes over. */
    private boolean nonEmpty(List<Rule> loaded, String src, Tick tick) {
        if (!loaded.isEmpty()) return true;
        tick.fail(src, "returned 0 rows for " + gatewayName);
        return false;
    }

    /** Recompute {@link #degradedReason} after a tick. Logs at ERROR when the gateway
     *  BECOMES degraded or starts enforcing a different snapshot source, and at INFO
     *  on recovery, so a long outage does not emit one line per refresh interval. */
    private void assess(Tick tick) {
        String auth = authoritativeSource();
        if ("seed".equals(auth) || auth.equals(tick.installed)) {
            // Only a degraded state that was LOGGED gets a recovery line; the
            // "not loaded yet" placeholder set by init() clears silently on a
            // normal boot.
            if (degradedEnforcing != null) {
                log.info("[route-access] recovered for {}: enforcing {} rules from {} (degraded since {})",
                        gatewayName, rules.size(), source, degradedSince);
            }
            degradedReason = null;
            degradedSince = null;
            degradedEnforcing = null;
            return;
        }
        String problem = "postgres".equals(auth) ? tick.postgresProblem : tick.cassandraProblem;
        String enforcing = source;
        String reason = auth + " " + (problem != null ? problem : "unavailable")
                + "; enforcing the " + ("seed".equals(enforcing)
                        ? "seed floor" : "last-known-good " + enforcing + " snapshot")
                + " (" + rules.size() + " rules)";
        if (degradedSince == null) degradedSince = Instant.now();
        if (!enforcing.equals(degradedEnforcing)) {
            log.error("[route-access] DEGRADED for {}: {}", gatewayName, reason);
        }
        degradedEnforcing = enforcing;
        degradedReason = reason;
    }

    /**
     * Run a refresh-path datastore read through the {@code routeAccess} circuit
     * breaker when one is wired ({@link net.hugmesh.gateway.config.GatewayResilienceConfig}).
     * When the breaker is OPEN — or the read times out / errors — it completes
     * empty so the caller's existing fallback chain takes over: a slow or
     * partitioned datastore can no longer pile reads up on the scheduler, and the
     * gateway keeps enforcing its last-good snapshot (never fail-open). With no
     * breaker (minimal/test wiring) the read is returned unwrapped.
     */
    private Mono<List<Rule>> guarded(Mono<List<Rule>> read, String src, Tick tick) {
        if (refreshBreaker == null) return read;
        return refreshBreaker.run(read, t -> {
            tick.fail(src, "read fast-failed by the routeAccess breaker: " + t);
            log.warn("[route-access] routeAccess breaker fast-failed a refresh read: {}", t.toString());
            return Mono.empty();
        });
    }

    private void swap(List<Rule> next, String src) {
        this.rules = List.copyOf(next);
        this.lastRefreshAt = Instant.now();
        this.source = src;
        log.debug("[route-access] refreshed {} rules for {} from {}", next.size(), gatewayName, src);
    }

    private Mono<List<Rule>> loadFromPostgres() {
        // Same semantics as the legacy SELECT ... WHERE gateway = :gw: every row
        // for THIS gateway, mapped 1:1 into the in-memory Rule shape. The id uuid
        // is flattened to its String form (legacy `id::text AS id`); booleans
        // default to false when the (NOT NULL) column round-trips absent.
        return routeAccessRepository.findByGateway(gatewayName)
            .map(r -> new Rule(
                    r.id() == null ? null : r.id().toString(),
                    r.gateway(),
                    r.urlPattern(),
                    r.role(),
                    r.casdoorUser(),
                    r.allow(),
                    r.domain(),
                    r.mfaRequired()))
            .collectList();
    }

    private Mono<List<Rule>> loadFromCassandra() {
        if (cql == null) return Mono.empty();
        var next = new ArrayList<Rule>();
        return cql.queryForRows(
                "SELECT id, gateway, url_pattern, role, casdoor_user, \"allow\", domain, mfa_required " +
                "FROM gateway_route_access")
            .doOnNext(row -> {
                String gateway = row.getString("gateway");
                // Each pod caches only the rules for its own instance — a be
                // gateway never enforces fe rules even though they share a table.
                if (gateway == null || !gateway.equals(gatewayName)) return;
                next.add(new Rule(
                        row.getString("id"), gateway,
                        row.getString("url_pattern"),
                        row.getString("role"),
                        row.getString("casdoor_user"),
                        Boolean.TRUE.equals(row.getBoolean("allow")),
                        row.getString("domain"),
                        Boolean.TRUE.equals(row.getBoolean("mfa_required"))));
            })
            .then(Mono.fromCallable(() -> (List<Rule>) next));
    }

    /** Write-through the authoritative Postgres rows into the Cassandra cache. */
    private Mono<Void> mirrorToCassandra(List<Rule> loaded) {
        if (cql == null) return Mono.empty();
        // Deferred: building the chain calls cql.execute(...) per row, and a
        // synchronous throw there must surface as THIS Mono's error (caught below),
        // never inside the Postgres load's doOnNext, where it would be misreported
        // as a failed Postgres load.
        return Mono.defer(() -> {
            Mono<Void> chain = Mono.empty();
            for (Rule r : loaded) {
                chain = chain.then(Mono.from(cql.execute(
                        "INSERT INTO gateway_route_access " +
                        "(id, gateway, url_pattern, role, casdoor_user, \"allow\", domain, mfa_required, updated_at) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, toTimestamp(now()))",
                        r.id(), r.gateway(), r.urlPattern(), r.role(), r.casdoorUser(), r.allow(),
                        r.domain(), r.mfaRequired()))
                    .then());
            }
            return chain;
        }).onErrorResume(e -> {
            log.warn("[route-access] Cassandra mirror failed (cache may lag Postgres): {}", e.getMessage());
            return Mono.empty();
        });
    }

    /** Test seam — prime the in-memory snapshot without a live datastore.
     *  Public so the cross-package filter test can drive the REAL service (the
     *  de-stubbed cross-tenant DENY) rather than a Mockito stub. */
    public void primeForTest(List<Rule> testRules) {
        this.rules = List.copyOf(testRules);
    }

    /** Test seam — simulate a datastore being WIRED (so {@link #isPrimed} reflects
     *  the never-primed cold-start window the privileged MFA floor fails CLOSED on)
     *  WITHOUT a live client. With {@code wired=true} and no successful refresh,
     *  {@link #isPrimed} returns {@code false}. */
    public void simulateDatastoreWiredButUnprimedForTest(boolean wired) {
        this.datastoreWiredOverrideForTest = wired;
    }
}
