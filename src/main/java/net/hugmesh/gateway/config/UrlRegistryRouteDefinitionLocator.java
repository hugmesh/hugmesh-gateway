package net.hugmesh.gateway.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.FilterDefinition;
import org.springframework.cloud.gateway.handler.predicate.PredicateDefinition;
import org.springframework.cloud.gateway.route.RouteDefinition;
import org.springframework.cloud.gateway.route.RouteDefinitionLocator;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import net.hugmesh.gateway.cache.UrlRegistryService;

import java.net.URI;
import java.util.List;

/**
 * Turns the Cassandra-backed {@code url_registry} table (read into memory by
 * {@link UrlRegistryService}) into live Spring Cloud Gateway routes. This is the
 * bridge that was missing: the registry already knew every
 * {@code path_prefix → downstream_uri} mapping, but nothing converted those into
 * routable {@link RouteDefinition}s — so a registered URL never actually forwarded.
 *
 * <p>Spring Cloud Gateway merges every {@link RouteDefinitionLocator} bean in the
 * context (via its {@code CompositeRouteDefinitionLocator}), so the definitions
 * produced here sit <em>alongside</em> the static {@code spring.cloud.gateway.routes}
 * from {@code application.yml} rather than replacing them. Each registry row becomes:
 *
 * <pre>{@code
 *   id        = sanitized(path_prefix)            e.g. "/api/games/" -> "api_games"
 *   uri       = downstream_uri                    e.g. http://games-api:8080
 *   predicate = Path=<path_prefix>**              e.g. Path=/api/games/**
 *   filter    = StripPrefix=<strip_prefix>        e.g. StripPrefix=1   (only when strip_prefix > 0)
 * }</pre>
 *
 * <p>The {@code StripPrefix} filter is emitted ONLY when the row's
 * {@code strip_prefix} column is {@code > 0} (migration 008) — so the seeded
 * {@code /be/**} route strips {@code /be} ({@code /be/api -> /api}) exactly like the
 * static {@code be-default} route's {@code StripPrefix=1}. Rows with a null/{@code <= 0}
 * {@code strip_prefix} (self-registering apps, admin control routes) emit no filter.
 *
 * <p>{@link UrlRegistryService} publishes a
 * {@link org.springframework.cloud.gateway.event.RefreshRoutesEvent} whenever its
 * snapshot changes, which prompts the gateway to re-invoke
 * {@link #getRouteDefinitions()} — so an admin's {@code /bff/admin/routes} write lands
 * as a live route within one registry-refresh tick, no redeploy / config push.
 *
 * <p>This is the route <em>definition</em> source. It is deliberately separate from
 * {@code GatewayRouteAccessService} (the route <em>access</em> control layer); the two
 * tables and concerns never mix.
 */
@Component
public class UrlRegistryRouteDefinitionLocator implements RouteDefinitionLocator {

    private static final Logger log = LoggerFactory.getLogger(UrlRegistryRouteDefinitionLocator.class);

    private final UrlRegistryService registry;

    public UrlRegistryRouteDefinitionLocator(UrlRegistryService registry) {
        this.registry = registry;
    }

    @Override
    public Flux<RouteDefinition> getRouteDefinitions() {
        return Flux.fromIterable(registry.routes())
                .filter(r -> r.pathPrefix() != null && !r.pathPrefix().isBlank()
                        && r.downstreamUri() != null && !r.downstreamUri().isBlank())
                .map(this::toDefinition);
    }

    private RouteDefinition toDefinition(UrlRegistryService.Route route) {
        RouteDefinition def = new RouteDefinition();
        def.setId("url-registry:" + sanitizeId(route.pathPrefix()));
        def.setUri(URI.create(route.downstreamUri().trim()));

        // Shorthand form parses "Path=/api/games/**" into the positional
        // _genkey_0 arg the gateway gathers into PathRoutePredicateFactory's
        // `patterns` list — exactly how a YAML `- Path=/api/**` entry is read.
        PredicateDefinition path = new PredicateDefinition("Path=" + toPathPattern(route.pathPrefix()));
        def.setPredicates(List.of(path));

        // StripPrefix support: a row with strip_prefix > 0 reproduces a static
        // YAML route's `- StripPrefix=N` filter (so the seeded /be/** route strips
        // /be -> /api at the be-gateway, identical to the static be-default route).
        // Shorthand "StripPrefix=1" parses into the positional _genkey_0 arg exactly
        // how a YAML `- StripPrefix=1` entry is read. null/<=0 => no filter at all
        // (unchanged for self-registering apps and admin routes that do not strip).
        Integer strip = route.stripPrefix();
        if (strip != null && strip > 0) {
            FilterDefinition stripPrefix = new FilterDefinition("StripPrefix=" + strip);
            def.setFilters(List.of(stripPrefix));
        }

        log.debug("[url-registry] route definition {} -> {} (predicate={}, filters={})",
                def.getId(), def.getUri(), path.getArgs(), def.getFilters());
        return def;
    }

    /** Append {@code **} so the prefix matches itself and everything under it,
     *  unless the registrant already supplied an Ant glob tail. */
    static String toPathPattern(String pathPrefix) {
        String p = pathPrefix.trim();
        return p.endsWith("*") ? p : p + "**";
    }

    /** A stable, route-id-safe token derived from the path prefix
     *  ({@code /api/games/} → {@code api_games}). */
    static String sanitizeId(String pathPrefix) {
        String id = pathPrefix.trim()
                .replaceAll("^/+", "")
                .replaceAll("/+$", "")
                .replaceAll("[^A-Za-z0-9]+", "_");
        return id.isBlank() ? "root" : id;
    }
}
