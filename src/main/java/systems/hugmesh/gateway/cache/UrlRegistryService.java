package systems.hugmesh.gateway.cache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.event.RefreshRoutesEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.cassandra.core.ReactiveCassandraTemplate;
import org.springframework.data.cassandra.core.cql.ReactiveCqlOperations;
import org.springframework.lang.Nullable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import jakarta.annotation.PostConstruct;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Cassandra-backed registry of valid app federation URLs — every
 * HugMesh gateway instance (hugmesh-{pki,be,fe}-gateway, and per-brand
 * {@code ${BRAND}-{pki,be,fe}-gateway}) keeps a local snapshot of which
 * {@code /api/<prefix>/} maps to which downstream service.
 *
 * <p>This is the "db+cache url app federation pattern" the platform
 * design calls for: internal APIs can register their own URL space at
 * boot, the gateway picks it up on the next refresh tick, traffic
 * routes without a config push. A "registration of valid urls" the
 * design language refers to.
 *
 * <p>Cassandra schema:
 *
 * <pre>{@code
 * CREATE TABLE hugmesh_gateway.url_registry (
 *   path_prefix text PRIMARY KEY,
 *   downstream_uri text,
 *   service_name text,
 *   registered_at timestamp,
 *   required_role text,
 *   strip_prefix int
 * );
 * }</pre>
 *
 * <p>The {@code required_role} column lets a registrant declare its
 * own auth posture (e.g. {@code admin} for an internal control-plane
 * route). The gateway's SecurityConfig handles the broad ROLE_USER
 * gate; this is the fine-grained per-route override.
 *
 * <p>The {@code strip_prefix} column (migration 008) lets a row reproduce a
 * static YAML route's {@code StripPrefix=N} filter — the locator emits a
 * {@code StripPrefix=N} filter when it is {@code > 0}, so the seeded
 * {@code /be/**} route can strip {@code /be} exactly like the static
 * {@code be-default} route. {@code null}/{@code <= 0} means "no strip" (the
 * back-compat default; self-registering apps and admin control routes do not
 * strip).
 */
@Service
public class UrlRegistryService {

    private static final Logger log = LoggerFactory.getLogger(UrlRegistryService.class);

    /**
     * A registry route row. {@code stripPrefix} mirrors the {@code strip_prefix int}
     * column (migration 008): {@code null} or {@code <= 0} means "no StripPrefix
     * filter", a positive {@code N} makes the locator emit {@code StripPrefix=N}.
     */
    public record Route(String pathPrefix, String downstreamUri,
                        String serviceName, String requiredRole,
                        @Nullable Integer stripPrefix) {}

    private final ReactiveCqlOperations cql;
    private final boolean enabled;
    private final boolean seedDefaults;

    /** Publishes a {@link RefreshRoutesEvent} whenever the snapshot changes so
     *  Spring Cloud Gateway rebuilds its live routes from
     *  {@code UrlRegistryRouteDefinitionLocator}. Null in unit tests (no context). */
    @Nullable
    private final ApplicationEventPublisher events;

    /** path-prefix → Route. Atomically swapped on each refresh. */
    private volatile Map<String, Route> routes = Collections.emptyMap();

    private volatile Instant lastRefreshAt = Instant.EPOCH;

    public UrlRegistryService(
            @Nullable ReactiveCassandraTemplate template,
            @Value("${app.url-registry.enabled:true}") boolean enabled,
            @Value("${app.url-registry.seed-defaults.enabled:true}") boolean seedDefaults,
            @Nullable ApplicationEventPublisher events) {
        this.cql = template != null ? template.getReactiveCqlOperations() : null;
        this.enabled = enabled;
        this.seedDefaults = seedDefaults;
        this.events = events;
    }

    @PostConstruct
    void init() {
        if (!enabled || cql == null) {
            log.info("[url-registry] disabled (cassandra not wired or app.url-registry.enabled=false)");
            return;
        }
        // Schema owned by CassandraSchemaMigrations (migration
        // 003-url-registry-table). On boot we (a) seed the baked-in
        // default route definitions IF ABSENT — a CanonicalSeed-style
        // idempotent startup upsert, the route-definition analogue of
        // GatewayRouteAccessService's CanonicalSeed — then (b) prime the
        // local cache from the table.
        seedDefaults().then(refreshNow()).subscribe();
    }

    /**
     * Idempotently seed the baked-in default route definitions ({@link
     * UrlRegistryDefaultRoutes}) so a DB-driven {@code /be/** -> be-gateway} route
     * exists the first time a fresh cluster boots, without an out-of-band INSERT or
     * a hand-run admin call. The route-definition analogue of {@code CanonicalSeed}
     * (which seeds the route-ACCESS floor): the same default that ships as the
     * static YAML route in the generator's fe-gateway config, now ALSO materialised
     * as a {@code url_registry} row so it can be re-pointed via the admin-bff without
     * a redeploy.
     *
     * <p><b>Seed-if-absent (LWT).</b> Each row is written with
     * {@code INSERT ... IF NOT EXISTS} — a Cassandra lightweight transaction that
     * applies ONLY when no row for that {@code path_prefix} (the PK) exists yet. A
     * plain INSERT is an upsert-by-PK and would silently CLOBBER an admin's later
     * edit (re-pointed uri / changed required_role) on the next pod boot; the
     * {@code IF NOT EXISTS} guard makes the seed a true one-time floor — once the
     * row exists (seeded, or admin-created/edited) the seed is a no-op. Multi-pod
     * boots racing the same seed are safe: the LWT lets exactly one win and the
     * rest no-op.
     *
     * <p>Gated by {@code app.url-registry.seed-defaults.enabled} (default true),
     * mirroring the toggle style of the surrounding cache services so an operator
     * can disable the baked-in floor on a cluster that manages the registry
     * entirely out-of-band.
     */
    Mono<Void> seedDefaults() {
        if (!seedDefaults || cql == null) {
            return Mono.empty();
        }
        Mono<Void> chain = Mono.empty();
        for (Route r : UrlRegistryDefaultRoutes.defaults()) {
            chain = chain.then(seedIfAbsent(r));
        }
        return chain.onErrorResume(e -> {
            log.warn("[url-registry] default-route seed failed (registry may lack baked-in floor): {}",
                    e.getMessage());
            return Mono.empty();
        });
    }

    /**
     * {@code INSERT ... IF NOT EXISTS} a single default route. The LWT result row
     * carries {@code [applied]}; we log whether the seed landed or was skipped
     * (a pre-existing — possibly admin-edited — row) but never treat a skip as an
     * error. {@code registered_at} is stamped {@code now()} only on the row that
     * actually applies.
     */
    private Mono<Void> seedIfAbsent(Route r) {
        Integer stripPrefix = r.stripPrefix();
        return Mono.from(cql.execute(
                "INSERT INTO url_registry " +
                "(path_prefix, downstream_uri, service_name, registered_at, required_role, strip_prefix) " +
                "VALUES (?, ?, ?, ?, ?, ?) IF NOT EXISTS",
                r.pathPrefix(), r.downstreamUri(), r.serviceName(), Instant.now(),
                r.requiredRole() == null ? "" : r.requiredRole(),
                stripPrefix == null ? 0 : stripPrefix))
            .doOnNext(applied -> {
                if (applied) {
                    log.info("[url-registry] seeded default route {} -> {}",
                            r.pathPrefix(), r.downstreamUri());
                } else {
                    log.debug("[url-registry] default route {} already present — seed skipped (no clobber)",
                            r.pathPrefix());
                }
            })
            .then();
    }

    /** Lookup the route registered for the longest matching prefix.
     *  Path "/api/games/123" prefers "/api/games/" over "/api/" if both
     *  are registered. */
    public Optional<Route> resolve(String requestPath) {
        if (requestPath == null) return Optional.empty();
        Map<String, Route> snapshot = routes;
        String best = null;
        for (String prefix : snapshot.keySet()) {
            if (requestPath.startsWith(prefix)
                    && (best == null || prefix.length() > best.length())) {
                best = prefix;
            }
        }
        return best == null ? Optional.empty() : Optional.of(snapshot.get(best));
    }

    /** Register / update a route entry. Idempotent — repeat
     *  registrations for the same prefix overwrite. Used by registrant
     *  apps to claim their URL space at boot.
     *
     *  <p>Public signature kept STABLE (no {@code strip_prefix} parameter) so
     *  existing/external registrant callers compile unchanged — a self-registering
     *  app claims a plain forward and never strips. The write defaults
     *  {@code strip_prefix} to {@code 0} (no strip); a route that needs a prefix
     *  strip is configured via the admin-bff / a seeded default, not self-registration. */
    public Mono<Void> register(String pathPrefix, String downstreamUri,
                                String serviceName, String requiredRole) {
        if (!enabled || cql == null) return Mono.empty();
        return cql.execute(
                "INSERT INTO url_registry " +
                "(path_prefix, downstream_uri, service_name, registered_at, required_role, strip_prefix) " +
                "VALUES (?, ?, ?, ?, ?, ?)",
                pathPrefix, downstreamUri, serviceName, Instant.now(),
                requiredRole == null ? "" : requiredRole, 0)
            .then();
    }

    public Instant lastRefreshAt() {
        return lastRefreshAt;
    }

    /** Current snapshot of every registered route — the source the
     *  {@code UrlRegistryRouteDefinitionLocator} turns into live Spring Cloud
     *  Gateway {@code RouteDefinition}s. */
    public Collection<Route> routes() {
        return routes.values();
    }

    @Scheduled(fixedDelayString = "${app.url-registry.refresh-interval-ms:10000}")
    void refresh() {
        if (!enabled || cql == null) return;
        refreshNow().subscribe();
    }

    private Mono<Void> refreshNow() {
        var next = new HashMap<String, Route>();
        return cql.queryForRows(
                "SELECT path_prefix, downstream_uri, service_name, required_role, strip_prefix FROM url_registry")
            .doOnNext(row -> {
                String prefix = row.getString("path_prefix");
                String uri    = row.getString("downstream_uri");
                if (prefix != null && uri != null) {
                    // strip_prefix is nullable (rows seeded before migration 008, or
                    // null-valued). getObject returns null for a Cassandra NULL int —
                    // a raw getInt would coerce NULL to 0 SILENTLY (harmless here) but
                    // we keep null distinct from an explicit 0 so the Route faithfully
                    // reflects the row; the locator treats both null and <=0 as no-strip.
                    Object sp = row.getObject("strip_prefix");
                    Integer stripPrefix = (sp instanceof Number n) ? n.intValue() : null;
                    next.put(prefix, new Route(
                            prefix, uri,
                            row.getString("service_name"),
                            row.getString("required_role"),
                            stripPrefix));
                }
            })
            .then(Mono.fromRunnable(() -> {
                boolean changed = !next.equals(routes);
                routes = Collections.unmodifiableMap(next);
                lastRefreshAt = Instant.now();
                log.debug("[url-registry] refreshed: {} routes (changed={})", next.size(), changed);
                // Only nudge Spring Cloud Gateway to rebuild its route table when
                // the registry actually changed — a RefreshRoutesEvent re-runs every
                // RouteDefinitionLocator, so publishing it on every idle 10 s tick
                // would be wasteful. The first prime (EPOCH → now) always counts as
                // a change since the live routes start empty.
                if (changed && events != null) {
                    events.publishEvent(new RefreshRoutesEvent(this));
                }
            }))
            .onErrorResume(e -> {
                log.warn("[url-registry] refresh failed: {}", e.getMessage());
                return Mono.empty();
            })
            .then();
    }

    /** Test seam — prime the in-memory route snapshot without a live Cassandra,
     *  mirroring {@code GatewayRouteAccessService.primeForTest}. Public because the
     *  route-definition locator (and its test) live in the {@code config} package. */
    public void primeForTest(Map<String, Route> testRoutes) {
        this.routes = Collections.unmodifiableMap(new HashMap<>(testRoutes));
    }
}
