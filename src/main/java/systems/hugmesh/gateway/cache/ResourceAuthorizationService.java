package systems.hugmesh.gateway.cache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.cassandra.core.ReactiveCassandraTemplate;
import org.springframework.data.cassandra.core.cql.ReactiveCqlOperations;
import org.springframework.lang.Nullable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import jakarta.annotation.PostConstruct;
import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Cassandra-backed per-resource access cache — the third leg of the
 * gateway's "db+cache url app federation" pattern (alongside the
 * revocation list + URL registry). Locks the cached UID/CID URLs to
 * the user's authorization at the gateway level: a JWT carrying
 * {@code ROLE_USER} doesn't get to fetch
 * {@code /api/games/abbott-village/launch} unless they ALSO have an
 * access grant for the {@code abbott-village} game resource.
 *
 * <p>Grant key shape (single Cassandra row per granted tuple):
 *
 * <pre>{@code
 *   resource_type:resource_id:user_id    e.g.
 *   game:abbott-village:tw-player-001
 *   session:abc123:tw-player-001
 *   asset:cave-bundle:tw-player-001
 * }</pre>
 *
 * <p>"All-users" rows use {@code *} as the user_id; "role-scoped"
 * rows use {@code role:<role-name>} so a single grant per role
 * dispatches to every member.
 *
 * <p>Schema:
 *
 * <pre>{@code
 * CREATE TABLE hugmesh_gateway.resource_access (
 *   grant_key text PRIMARY KEY,
 *   resource_type text,
 *   resource_id text,
 *   subject_kind text,        -- 'user' | 'role' | 'all'
 *   subject_value text,
 *   granted_by text,
 *   granted_at timestamp
 * );
 * }</pre>
 *
 * <p>Same lookup pattern as the revocation list — every gateway pod
 * polls every 5 s; lookups are constant-time hash hits against the
 * locally-cached snapshot. {@code @Scheduled} on this service drives
 * the refresh; the filter that consults it stays off the hot path.
 */
@Service
public class ResourceAuthorizationService {

    private static final Logger log = LoggerFactory.getLogger(ResourceAuthorizationService.class);

    /** Wildcard subject id — grants access to every authenticated
     *  user. Equivalent to the BFF's {@code game_access.scope='all'}. */
    public static final String SUBJECT_ALL = "*";

    /** Prefix for role-scoped grants. The cache stores
     *  {@code role:<role-name>} verbatim so a role check is just
     *  another set lookup. */
    public static final String SUBJECT_ROLE_PREFIX = "role:";

    private final ReactiveCqlOperations cql;
    private final boolean enabled;

    /** Snapshot of every active grant key. Refreshed atomically. */
    private volatile Set<String> grants = Collections.emptySet();

    private volatile Instant lastRefreshAt = Instant.EPOCH;

    public ResourceAuthorizationService(
            @Nullable ReactiveCassandraTemplate template,
            @Value("${app.resource-access.enabled:true}") boolean enabled) {
        this.cql = template != null ? template.getReactiveCqlOperations() : null;
        this.enabled = enabled;
    }

    @PostConstruct
    void init() {
        if (!enabled || cql == null) {
            log.info("[resource-access] disabled (cassandra not wired or app.resource-access.enabled=false)");
            return;
        }
        // Schema owned by CassandraSchemaMigrations (migration
        // 004-resource-access-table). This service just primes the
        // local cache.
        refreshNow().subscribe();
    }

    /**
     * Check whether {@code userId} has a grant for the given resource
     * tuple, evaluated as the union of:
     * <ul>
     *   <li>a user-specific grant ({@code <type>:<id>:<userId>})</li>
     *   <li>an all-users grant ({@code <type>:<id>:*})</li>
     *   <li>any role-scoped grant the user holds — caller passes the
     *       user's roles via {@link #hasAnyRoleGrant(String, String, Iterable)}.
     *       The single-arg variant returns false on role grants by
     *       design; the caller must opt in.</li>
     * </ul>
     * Cache-only — constant time after the cache is primed.
     */
    public boolean isGranted(String resourceType, String resourceId, String userId) {
        if (resourceType == null || resourceId == null) return false;
        Set<String> snapshot = grants;
        if (userId != null && snapshot.contains(key(resourceType, resourceId, userId))) return true;
        return snapshot.contains(key(resourceType, resourceId, SUBJECT_ALL));
    }

    /** Same as {@link #isGranted} but also union-checks every supplied
     *  role. Used when the SecurityContext has materialised the
     *  principal's authorities. */
    public boolean hasAnyRoleGrant(String resourceType, String resourceId, Iterable<String> roles) {
        if (roles == null) return false;
        Set<String> snapshot = grants;
        for (String r : roles) {
            if (r == null || r.isBlank()) continue;
            // Roles come in as plain names (no ROLE_ prefix) per
            // Roles.namesOf(...). Normalize to lowercase to match the
            // canonical grant_key shape ('role:admin' vs 'role:ADMIN').
            String roleKey = SUBJECT_ROLE_PREFIX + r.toLowerCase();
            if (snapshot.contains(key(resourceType, resourceId, roleKey))) return true;
        }
        return false;
    }

    /** Register / update an access grant. Idempotent — repeat
     *  registrations of the same tuple overwrite the row. */
    public Mono<Void> grant(String resourceType, String resourceId,
                             String subjectKind, String subjectValue,
                             String grantedBy) {
        if (!enabled || cql == null) return Mono.empty();
        String key = grantKey(resourceType, resourceId, subjectKind, subjectValue);
        return cql.execute(
                "INSERT INTO resource_access " +
                "(grant_key, resource_type, resource_id, subject_kind, subject_value, granted_by, granted_at) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                key, resourceType, resourceId, subjectKind, subjectValue,
                grantedBy == null ? "system" : grantedBy, Instant.now())
            .then();
    }

    public Instant lastRefreshAt() {
        return lastRefreshAt;
    }

    @Scheduled(fixedDelayString = "${app.resource-access.refresh-interval-ms:5000}")
    void refresh() {
        if (!enabled || cql == null) return;
        refreshNow().subscribe();
    }

    private Mono<Void> refreshNow() {
        var next = new HashSet<String>();
        return cql.queryForRows("SELECT grant_key FROM resource_access")
            .doOnNext(row -> {
                String k = row.getString("grant_key");
                if (k != null) next.add(k);
            })
            .then(Mono.fromRunnable(() -> {
                grants = Collections.unmodifiableSet(next);
                lastRefreshAt = Instant.now();
                log.debug("[resource-access] refreshed: {} grants", next.size());
            }))
            .onErrorResume(e -> {
                log.warn("[resource-access] refresh failed: {}", e.getMessage());
                return Mono.empty();
            })
            .then();
    }

    private static String key(String resourceType, String resourceId, String subjectValue) {
        return resourceType + ":" + resourceId + ":" + subjectValue;
    }

    private static String grantKey(String resourceType, String resourceId,
                                    String subjectKind, String subjectValue) {
        if (SUBJECT_ALL.equals(subjectKind) || "all".equals(subjectKind)) {
            return key(resourceType, resourceId, SUBJECT_ALL);
        }
        if ("role".equals(subjectKind)) {
            return key(resourceType, resourceId, SUBJECT_ROLE_PREFIX + subjectValue.toLowerCase());
        }
        return key(resourceType, resourceId, subjectValue);
    }
}
