package systems.hugmesh.gateway.cache;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

import java.util.UUID;

/**
 * Reactive (R2DBC) store for the {@code gateway_route_access} SOURCE OF TRUTH
 * in Postgres. Replaces the former raw {@code DatabaseClient} SQL read in
 * {@link GatewayRouteAccessService}. Matches the hugmesh-federation-api
 * reference idiom ({@link ReactiveCrudRepository} + derived finders).
 *
 * <p>Unlike federation (whose Postgres IS its primary auto-configured datastore)
 * this repository is backed by the DEDICATED, conditional route-access
 * {@code ConnectionFactory} wired in
 * {@link systems.hugmesh.gateway.config.RouteAccessR2dbcConfig} only when
 * {@code app.route-access.r2dbc-url} is set — so a Cassandra-only / dev gateway
 * has no Postgres dependency and the service falls back to the Cassandra cache.
 */
public interface GatewayRouteAccessRepository
        extends ReactiveCrudRepository<GatewayRouteAccessRow, UUID> {

    /**
     * Every rule for a single gateway instance — the exact semantics of the
     * legacy {@code SELECT ... FROM gateway_route_access WHERE gateway = :gw}.
     * No ordering was specified in the original SQL (the in-memory longest-
     * pattern walk in {@link GatewayRouteAccessService#decide} is order-
     * independent), so this derived finder reproduces it without an ORDER BY.
     */
    Flux<GatewayRouteAccessRow> findByGateway(String gateway);
}
