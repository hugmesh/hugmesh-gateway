package systems.hugmesh.gateway.cache;

import systems.hugmesh.gateway.cache.UrlRegistryService.Route;

import java.util.List;

/**
 * The canonical {@code url_registry} default ROUTE-DEFINITION seed — the
 * route-DEFINITION analogue of {@link CanonicalSeed} (which seeds the
 * route-ACCESS floor {@code gateway_route_access}). Baked into the image so a
 * fresh cluster has the platform's default cross-namespace route definitions in
 * the DB-driven registry the first time it boots, without an out-of-band INSERT
 * or a hand-run admin call.
 *
 * <p><b>The {@code /be/**} default.</b> The headline default is the
 * cross-namespace scope {@code /be/** -> hugmesh-be-gateway}: a request to
 * {@code /be/...} on the fe-gateway is forwarded to the backend gateway. This is
 * the SAME default that ships as the static YAML route in the generator's
 * fe-gateway config
 * ({@code hugmesh-generator/specs/cluster/apps/20-gateway-fe.yaml}, route id
 * {@code be-default}) — now ALSO materialised as a {@code url_registry} row so an
 * admin can re-point it via the admin-bff ({@code /bff/admin/routes}) without a
 * redeploy, exactly as that YAML's own comment anticipates ("once DB-driven route
 * definitions land … an admin can re-point this entry via the routing DB + admin
 * UI without a redeploy").
 *
 * <p><b>StripPrefix — the DB route now strips faithfully (StripPrefix=1).</b> The
 * static {@code be-default} route carries a {@code StripPrefix=1} filter so
 * {@code /be/api -> /api} at the be-gateway. The {@code url_registry} table now has
 * a {@code strip_prefix int} column (migration 008) and
 * {@link systems.hugmesh.gateway.config.UrlRegistryRouteDefinitionLocator} emits
 * a {@code StripPrefix=N} filter when it is {@code > 0}, so this seed sets
 * {@code stripPrefix = 1} and the DB-driven route forwards {@code /be/api -> /api}
 * (STRIPPED) — behaviourally IDENTICAL to the static route. This closes the latent
 * regression where the DB route emitted NO filter and, if it won Spring Cloud
 * Gateway's route ordering over the static {@code StripPrefix=1} route (both match
 * {@code /be/**} at default order 0, so which wins is non-deterministic), forwarded
 * {@code /be/api} UNSTRIPPED and broke the backend. So:
 * <ul>
 *   <li>The DB route's locator id ({@code url-registry:be}) is DISTINCT from the
 *       static route id ({@code be-default}); both coexist with no
 *       duplicate-id collision, and — now that BOTH strip {@code /be} identically —
 *       the static-vs-DB {@code /be/**} ordering is HARMLESS (whichever wins
 *       strips the same way).</li>
 *   <li>The static YAML route is retained as the resilient FLOOR (it works even
 *       if Cassandra is down at boot, before the seed/refresh runs). Fully
 *       retiring it is a deliberate FOLLOW-UP, once the DB route is the sole
 *       source.</li>
 * </ul>
 *
 * <p><b>Column mapping</b> (matches {@code hugmesh_gateway.url_registry}, see
 * {@link UrlRegistryService} / migrations 003 + 008):
 * <pre>{@code
 *   path_prefix    = /be/                                  (PK; locator appends ** -> Path=/be/**)
 *   downstream_uri = http://hugmesh-be-gateway.hugmesh-backend.svc.cluster.local:8080
 *   service_name   = hugmesh-be-gateway
 *   required_role  = ""                                    (route-ACCESS is governed by the
 *                                                          be-tier CanonicalSeed / gateway_route_access,
 *                                                          NOT this fine-grained per-route override)
 *   strip_prefix   = 1                                     (locator emits StripPrefix=1, matching the
 *                                                          static be-default route's StripPrefix=1)
 * }</pre>
 */
final class UrlRegistryDefaultRoutes {

    private UrlRegistryDefaultRoutes() {}

    /** In-cluster DNS of the backend gateway service — the SAME downstream the
     *  generator's static {@code be-default} route targets. */
    static final String BE_GATEWAY_URI =
            "http://hugmesh-be-gateway.hugmesh-backend.svc.cluster.local:8080";

    /** Path prefix for the cross-namespace backend scope. The locator appends
     *  {@code **} ({@code /be/} -> {@code Path=/be/**}) and sanitises the id
     *  ({@code /be/} -> {@code url-registry:be}). Trailing slash mirrors the other
     *  registered prefixes ({@code /api/games/}) and the locator's own convention. */
    static final String BE_PATH_PREFIX = "/be/";

    /** StripPrefix segment count for the {@code /be/} route — strips the leading
     *  {@code /be} so {@code /be/api -> /api} at the be-gateway, matching the static
     *  {@code be-default} route's {@code StripPrefix=1}. The locator turns this into
     *  a {@code StripPrefix=1} FilterDefinition. */
    static final int BE_STRIP_PREFIX = 1;

    /**
     * The baked-in default route definitions. Currently just the
     * {@code /be/** -> be-gateway} cross-namespace scope; appended-to as further
     * platform defaults become DB-driven. {@code requiredRole} is blank — the
     * route-ACCESS posture for the be tier is the {@link CanonicalSeed} floor, not
     * this per-route override. {@code stripPrefix = 1} makes the DB route strip
     * {@code /be} exactly like the static {@code be-default} route (StripPrefix=1).
     */
    static List<Route> defaults() {
        return List.of(
                new Route(BE_PATH_PREFIX, BE_GATEWAY_URI, "hugmesh-be-gateway", "",
                        BE_STRIP_PREFIX));
    }
}
