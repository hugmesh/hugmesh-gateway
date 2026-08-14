package net.hugmesh.gateway.cache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.cassandra.core.ReactiveCassandraTemplate;
import org.springframework.data.cassandra.core.cql.ReactiveCqlOperations;
import org.springframework.lang.Nullable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.gateway.security.DomainRegistry;

import jakarta.annotation.PostConstruct;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Cluster-wide revocation list backed by a single Cassandra table
 * ({@code hugmesh_gateway.revocations}). Every Spring API pod that
 * sits behind this gateway refreshes its local view periodically (the
 * "background poll" the cross-pod design calls for) so a block /
 * revocation on one pod propagates to all of them within one tick.
 *
 * <p>Key types tracked on the revocation list:
 *
 * <ul>
 *   <li>{@code subject:<casdoor-id>} — internal-auth revocation. Any
 *       JWT carrying this subject is denied at the gateway filter
 *       regardless of validity.</li>
 *   <li>{@code external:<provider>:<external-id>} — external-OAuth
 *       revocation. Anyone landing at the gateway with an
 *       {@code External-Authorization} header pointing at a revoked
 *       external identity is denied.</li>
 *   <li>{@code hs:<platform>:<localpart>} — homeserver coarse revocation
 *       (a Matrix/Mastodon ban kills EVERY token for the user).</li>
 *   <li>{@code hs:<platform>:<localpart>:<deviceId|appId>} — per-credential
 *       revocation (a single connected app / device drops, others survive).</li>
 *   <li>{@code external-client:<localpart>:<platform>} — external-client-role
 *       removal. Checked by {@code HomeserverTokenRevocationFilter} only for
 *       {@code kind=personal} tokens, so removing the external-client role denies
 *       native clients while leaving the user's brokered our-UI token working.</li>
 * </ul>
 *
 * <p>These last three are evaluated against HOMESERVER bearer tokens (which carry
 * no Casdoor JWT), so the gateway also needs to resolve an opaque bearer to its
 * {localpart, platform, kind, app/device id}. That mapping is mirrored here from
 * the {@code hs_tokens} table on the SAME poll (see {@link #hsTokenFor(String)}),
 * keeping the per-request lookup O(1) with no homeserver round-trip — the design's
 * PREREQ layer P1. The mint side (admin-bff brokered, user-bff personal) writes
 * the {@code hs_tokens} row; this service is read-only on that table.
 *
 * <p>The revocation list itself was read-only historically; the account-states
 * foundation adds the WRITE primitives {@link #revoke(String, String, long)} and
 * {@link #clear(String)} so the ban / connected-app-revoke / external-client
 * reconcile paths have a single place to put a key on (or lift it off) the list.
 *
 * <p>Cassandra schema (one row per revoked key, TTL-bounded so the row
 * disappears once the JWT or the access window expires):
 *
 * <pre>{@code
 * CREATE TABLE hugmesh_gateway.revocations (
 *   revocation_key text PRIMARY KEY,
 *   reason text,
 *   revoked_at timestamp,
 *   expires_at timestamp
 * ) WITH default_time_to_live = 86400;
 * }</pre>
 *
 * <p>The local cache is a {@link ConcurrentMap}; refresh replaces it
 * atomically. Lookups are lock-free O(1) hash hits — every gateway
 * filter check costs the same regardless of cluster size.
 */
@Service
public class RevocationListService {

    private static final Logger log = LoggerFactory.getLogger(RevocationListService.class);

    /** Reactive CQL — present when Cassandra is wired (spring-data-
     *  cassandra-reactive starter on the classpath + contact points
     *  configured). Null in unit-test or when Cassandra is unreachable. */
    private final ReactiveCqlOperations cql;
    private final boolean enabled;

    /** Test-only override: forces {@link #isPrimed} to treat Cassandra as WIRED even
     *  when {@code cql == null} (no live datastore in a unit test), so the never-primed
     *  cold-start fail-CLOSED window can be driven deterministically. {@code null} in
     *  production — {@link #isPrimed} uses the real {@code cql}/{@code enabled} state. */
    private Boolean cassandraWiredOverrideForTest = null;

    /**
     * Snapshot of the revoked-keys set the gateway filter consults. {@code volatile}
     * guarantees visibility; synchronized blocks in {@link #revoke} and {@link #clear}
     * guarantee atomicity of the read-modify-write so concurrent callers cannot lose
     * each other's entries.
     */
    private volatile Set<String> revokedKeys = Collections.emptySet();

    /** Per-key reason, for log lines + 403 response body. Sized lazily
     *  so we don't carry empty maps in the hot path. */
    private final ConcurrentMap<String, String> reasons = new ConcurrentHashMap<>();

    /**
     * Per-key OWNING brand/domain — the validated-issuer domain of the admin who
     * wrote the row (mirrored from the {@code revocations.domain} column on the same
     * poll). This is the source of truth the write surface consults to enforce the
     * cross-tenant revocation gate (CWE-639): a non-SUPERADMIN admin may only clear
     * or overwrite a key OWNED by their own domain. A {@code null}/blank/"default"
     * owner is UNSCOPED (single-tenant + pre-domain-column rows) and admits any
     * caller (back-compat). Sized lazily like {@link #reasons}.
     */
    private final ConcurrentMap<String, String> keyDomains = new ConcurrentHashMap<>();

    /**
     * Resolved identity of a homeserver bearer token, mirrored from the
     * {@code hs_tokens} table. The {@code HomeserverTokenRevocationFilter} hashes
     * the incoming bearer, looks the hash up here, and derives the revocation keys
     * to test. {@code kind} ∈ {@code {brokered, personal}} — only {@code personal}
     * tokens are subject to the {@code external-client:*} key.
     */
    public record HsToken(String localpart, String platform, String kind, String appOrDeviceId) {}

    /** Snapshot of {@code token_hash → HsToken}, refreshed on the SAME poll as
     *  the revoked-keys set so a per-request lookup is a lock-free O(1) hash hit
     *  with no homeserver round-trip. Replaced atomically. */
    private volatile Map<String, HsToken> hsTokens = Collections.emptyMap();

    /** Last-successful-refresh timestamp — exposed for health checks. */
    private volatile Instant lastRefreshAt = Instant.EPOCH;

    public RevocationListService(
            @Nullable ReactiveCassandraTemplate template,
            @Value("${app.revocation.enabled:true}") boolean enabled) {
        this.cql = template != null ? template.getReactiveCqlOperations() : null;
        this.enabled = enabled;
    }

    @PostConstruct
    void init() {
        if (!enabled || cql == null) {
            log.info("[revocation] disabled (cassandra not wired or app.revocation.enabled=false)");
            return;
        }
        // Schema is now owned by CassandraSchemaMigrations — that
        // component runs migration 002-revocations-table on boot
        // before this @PostConstruct fires. We just prime the local
        // cache so the first request doesn't see an empty snapshot
        // and let a revoked subject through.
        refreshNow().subscribe();
    }

    /** True iff {@code key} is on the revocation list as of the last
     *  refresh. Constant-time after the cache is primed. */
    public boolean isRevoked(String key) {
        return key != null && revokedKeys.contains(key);
    }

    public String reasonFor(String key) {
        return reasons.getOrDefault(key, "");
    }

    /** Resolve a homeserver bearer's {@code token_hash} to its identity, or
     *  {@code null} if the gateway has never seen a mint for it. Constant-time
     *  after the cache is primed; the {@code HomeserverTokenRevocationFilter}
     *  treats a {@code null} (unknown token) as fail-closed on the gated paths. */
    public HsToken hsTokenFor(String tokenHash) {
        return tokenHash == null ? null : hsTokens.get(tokenHash);
    }

    public Instant lastRefreshAt() {
        return lastRefreshAt;
    }

    /**
     * True once the local revoked-keys snapshot has been established at least once
     * from Cassandra (i.e. a refresh has succeeded since boot — {@link #lastRefreshAt}
     * has advanced past {@link Instant#EPOCH}). Until then the cache is the empty
     * cold-start snapshot, where {@link #isRevoked} returns {@code false} for EVERY
     * key and a genuinely-revoked subject would be let through — the never-primed
     * fail-open window the {@code RevocationGatewayFilter} can now gate fail-CLOSED.
     *
     * <p>When revocation is NOT in play — Cassandra not wired or
     * {@code app.revocation.enabled=false} (single-tenant / dev) — there is no poll
     * to prime the cache and no list to enforce, so this returns {@code TRUE}
     * unconditionally: the never-primed gate must NEVER hold these deployments
     * closed. Mirrors the {@code init()} early-return that skips the priming poll.
     */
    public boolean isPrimed() {
        boolean wired = cassandraWiredOverrideForTest != null
                ? cassandraWiredOverrideForTest
                : (cql != null && enabled);
        if (!wired) return true;
        return lastRefreshAt.isAfter(Instant.EPOCH);
    }

    /** Periodic refresh — Spring's {@code @Scheduled} fires every
     *  {@code refresh-interval-ms} milliseconds. Errors are logged
     *  and the previous snapshot is retained so a transient Cassandra
     *  blip doesn't gate every request. */
    @Scheduled(fixedDelayString = "${app.revocation.refresh-interval-ms:5000}")
    void refresh() {
        if (!enabled || cql == null) return;
        refreshNow().subscribe();
    }

    private Mono<Void> refreshNow() {
        return refreshRevocations()
                .then(refreshHsTokens())
                .onErrorResume(e -> {
                    log.warn("[revocation] refresh failed: {}", e.getMessage());
                    return Mono.empty();
                })
                .then();
    }

    /** Reload the revoked-keys snapshot (subject:*, external:*, hs:*,
     *  external-client:*) from Cassandra and swap it in atomically. The per-key
     *  OWNING domain ({@code revocations.domain}) is mirrored on the SAME poll so
     *  the write surface can enforce the cross-tenant gate from the canonical
     *  source rather than this pod's transient local state. */
    private Mono<Void> refreshRevocations() {
        var next = new HashSet<String>();
        var nextReasons = new ConcurrentHashMap<String, String>();
        var nextDomains = new ConcurrentHashMap<String, String>();
        return cql.queryForRows("SELECT revocation_key, reason, domain FROM revocations")
                .doOnNext(row -> {
                    String k = row.getString("revocation_key");
                    if (k != null) {
                        next.add(k);
                        String r = row.getString("reason");
                        if (r != null) nextReasons.put(k, r);
                        String d = row.getString("domain");
                        if (d != null && !d.isBlank()) nextDomains.put(k, d);
                    }
                })
                .then(Mono.fromRunnable(() -> {
                    revokedKeys = Collections.unmodifiableSet(next);
                    reasons.clear();
                    reasons.putAll(nextReasons);
                    keyDomains.clear();
                    keyDomains.putAll(nextDomains);
                    lastRefreshAt = Instant.now();
                    log.debug("[revocation] refreshed: {} keys", next.size());
                }))
                .then();
    }

    /** Reload the homeserver-token registry ({@code token_hash → HsToken}) on the
     *  SAME poll so the {@code HomeserverTokenRevocationFilter} resolves an opaque
     *  bearer O(1) without a homeserver round-trip (PREREQ P1). A failure here is
     *  swallowed by the caller; the previous snapshot is retained (a transient
     *  Cassandra blip never silently empties the map and fails every gated request
     *  open — and the filter is fail-CLOSED on unknown tokens anyway). */
    private Mono<Void> refreshHsTokens() {
        var next = new HashMap<String, HsToken>();
        return cql.queryForRows(
                "SELECT token_hash, localpart, platform, kind, app_or_device_id FROM hs_tokens")
                .doOnNext(row -> {
                    String hash = row.getString("token_hash");
                    if (hash != null) {
                        next.put(hash, new HsToken(
                                row.getString("localpart"),
                                row.getString("platform"),
                                row.getString("kind"),
                                row.getString("app_or_device_id")));
                    }
                })
                .then(Mono.fromRunnable(() -> {
                    hsTokens = Collections.unmodifiableMap(next);
                    log.debug("[revocation] hs_tokens refreshed: {} tokens", next.size());
                }))
                .then();
    }

    /**
     * Put {@code key} on the revocation list with a per-row TTL. This is the
     * single WRITE primitive every "revoke" path (platform ban, connected-app /
     * device drop, external-client-role removal) calls — the read-cache above
     * picks the new key up within one poll tick (≈ the refresh interval). The
     * {@code ttlSeconds} is a backstop ceiling: it should be {@code >=} the
     * remaining token lifetime so the key outlives the token it gates (the
     * authoritative clock is the desired-state row in the writing service, e.g.
     * {@code access_suspension.expires_at}). A non-positive {@code ttlSeconds}
     * inserts with the table default. No-op (logged) when Cassandra is not wired.
     *
     * <p>Back-compat overload — writes the row UNSCOPED (no owning domain). Prefer
     * {@link #revoke(String, String, long, String)} from the HTTP write surface so
     * the row records the validated-issuer domain of the admin who wrote it and the
     * cross-tenant gate (CWE-639) can enforce ownership on a later clear/overwrite.
     */
    public Mono<Void> revoke(String key, String reason, long ttlSeconds) {
        return revoke(key, reason, ttlSeconds, null);
    }

    /**
     * Put {@code key} on the revocation list with a per-row TTL, stamping the
     * OWNING {@code domain} (the validated-issuer brand of the admin who wrote it).
     * The owner is what the write surface checks before letting a later caller
     * clear or overwrite the key (cross-tenant revocation gate, CWE-639): a
     * non-SUPERADMIN admin may only touch keys owned by their OWN domain. A
     * {@code null}/blank/"default" {@code domain} stores the row UNSCOPED
     * (single-tenant + back-compat). No-op (logged) when Cassandra is not wired.
     */
    public Mono<Void> revoke(String key, String reason, long ttlSeconds, @Nullable String domain) {
        if (key == null || key.isBlank()) {
            return Mono.error(new IllegalArgumentException("revocation key must be non-blank"));
        }
        if (cql == null) {
            log.warn("[revocation] revoke({}) ignored — cassandra not wired", key);
            return Mono.empty();
        }
        String owner = normalizeDomain(domain);
        Instant now = Instant.now();
        String cqlStmt = ttlSeconds > 0
                ? "INSERT INTO revocations (revocation_key, reason, revoked_at, expires_at, domain) "
                    + "VALUES (?, ?, ?, ?, ?) USING TTL " + ttlSeconds
                : "INSERT INTO revocations (revocation_key, reason, revoked_at, expires_at, domain) "
                    + "VALUES (?, ?, ?, ?, ?)";
        Instant expiresAt = ttlSeconds > 0 ? now.plusSeconds(ttlSeconds) : null;
        return Mono.from(cql.execute(cqlStmt, key, reason, now, expiresAt, owner))
                .doOnSuccess(v -> {
                    // Reflect the write locally so this pod enforces it without waiting for the
                    // next poll; other pods converge on their tick. Synchronized so concurrent
                    // revoke() calls cannot lose each other's entries via unsynchronized RMW.
                    synchronized (this) {
                        Set<String> merged = new HashSet<>(revokedKeys);
                        merged.add(key);
                        revokedKeys = Collections.unmodifiableSet(merged);
                    }
                    if (reason != null) reasons.put(key, reason);
                    if (owner != null) keyDomains.put(key, owner);
                    else keyDomains.remove(key);
                    log.info("[revocation] revoked key={} ttl={}s domain={} reason={}",
                            key, ttlSeconds, owner, reason);
                })
                .then();
    }

    /**
     * Lift {@code key} off the revocation list (DELETE). Used by the restore
     * paths (suspension expiry, un-ban, re-grant of an external-client role). The
     * other pods drop the key on their next poll; this pod drops it immediately.
     * No-op (logged) when Cassandra is not wired.
     *
     * <p><b>Authorization note.</b> This primitive does NOT itself enforce the
     * cross-tenant gate — the HTTP write surface ({@code GatewayRevocationController})
     * resolves the key's {@link #domainOfKey(String) owning domain} and 403s a
     * cross-domain non-SUPERADMIN caller BEFORE calling this. Keeping the gate in
     * the controller (where the validated JWT issuer lives) mirrors the gateway
     * filter's {@code Roles.domainOf(jwt, registry)} pattern.
     */
    public Mono<Void> clear(String key) {
        if (key == null || key.isBlank()) {
            return Mono.error(new IllegalArgumentException("revocation key must be non-blank"));
        }
        if (cql == null) {
            log.warn("[revocation] clear({}) ignored — cassandra not wired", key);
            return Mono.empty();
        }
        return Mono.from(cql.execute("DELETE FROM revocations WHERE revocation_key = ?", key))
                .doOnSuccess(v -> {
                    synchronized (this) {
                        Set<String> merged = new HashSet<>(revokedKeys);
                        merged.remove(key);
                        revokedKeys = Collections.unmodifiableSet(merged);
                    }
                    reasons.remove(key);
                    keyDomains.remove(key);
                    log.info("[revocation] cleared key={}", key);
                })
                .then();
    }

    /**
     * The OWNING brand/domain of a revocation key as of the last refresh (or a
     * local revoke on this pod), or {@code null} when the key is UNSCOPED (single-
     * tenant + pre-domain-column rows) OR unknown. The HTTP write surface uses this
     * to enforce the cross-tenant revocation gate: a non-SUPERADMIN caller whose
     * own domain differs from a key's (non-null) owner is denied. Returning
     * {@code null} for an unscoped/unknown key is intentional — back-compat single-
     * tenant rows admit any caller, exactly like an unscoped route-access row.
     */
    @Nullable
    public String domainOfKey(String key) {
        return key == null ? null : keyDomains.get(key);
    }

    /** Canonicalize an owning-domain value: {@code null}/blank/"default" -&gt;
     *  {@code null} (UNSCOPED), otherwise trimmed-lowercase. Mirrors the route-
     *  access {@code domainApplies} treatment of {@code default} as unscoped so a
     *  single-tenant write never pins a spurious owner. */
    @Nullable
    private static String normalizeDomain(@Nullable String domain) {
        if (domain == null) return null;
        String d = domain.trim();
        if (d.isEmpty() || DomainRegistry.DEFAULT_DOMAIN.equalsIgnoreCase(d)) return null;
        return d.toLowerCase();
    }

    /**
     * Returns an immutable snapshot of the currently revoked keys. Intended for the
     * SUPERADMIN observability endpoint — the returned set is a safe point-in-time
     * copy; it does not reflect subsequent {@link #revoke} or {@link #clear} calls.
     */
    public Set<String> snapshot() {
        return revokedKeys; // volatile read; already unmodifiable
    }

    /** Test seam — prime the revoked-keys snapshot without a live datastore.
     *  Public so the {@code filter}-package tests (different package) can drive
     *  the gate; not part of the production write path (use {@link #revoke}). */
    public void primeRevokedForTest(Set<String> keys) {
        this.revokedKeys = Set.copyOf(keys);
    }

    /** Test seam — simulate Cassandra being WIRED (so {@link #isPrimed} stops
     *  short-circuiting to {@code true}) without a live datastore, so the
     *  never-primed cold-start window the {@code RevocationGatewayFilter} fail-
     *  closes on can be driven in a unit test. With Cassandra wired but no refresh
     *  yet succeeded, {@code lastRefreshAt} is still {@link Instant#EPOCH} and
     *  {@link #isPrimed} returns {@code false}. */
    public void markCassandraWiredForTest() {
        this.cassandraWiredOverrideForTest = true;
    }

    /** Test seam — mark the cache as PRIMED (a refresh has succeeded) without a
     *  live datastore, by advancing {@code lastRefreshAt} past {@link Instant#EPOCH}.
     *  Used together with {@link #markCassandraWiredForTest} to assert the filter
     *  forwards once the cache is primed. */
    public void markPrimedForTest() {
        this.lastRefreshAt = Instant.now();
    }

    /** Test seam — prime the per-key OWNING-domain map without a live datastore,
     *  so the cross-tenant revocation gate ({@link #domainOfKey}) can be driven in
     *  a unit test exactly as the poll would populate it from the
     *  {@code revocations.domain} column. */
    public void primeKeyDomainsForTest(Map<String, String> domains) {
        keyDomains.clear();
        domains.forEach((k, d) -> { if (d != null && !d.isBlank()) keyDomains.put(k, d); });
    }

    /** Test seam — prime the hs_tokens snapshot without a live datastore.
     *  Public for the same cross-package reason as {@link #primeRevokedForTest}. */
    public void primeHsTokensForTest(Map<String, HsToken> tokens) {
        this.hsTokens = Map.copyOf(tokens);
    }
}
