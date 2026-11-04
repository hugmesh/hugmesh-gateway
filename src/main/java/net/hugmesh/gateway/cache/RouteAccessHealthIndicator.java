package net.hugmesh.gateway.cache;

import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * Health contributor {@code routeAccess}: {@code DOWN} while the gateway enforces
 * something other than a fresh load from its authoritative route-access source
 * (hugmesh-gateway#61). That covers the seed floor at cold start, the seed floor
 * because every source failed or returned zero rows, and a stale Cassandra
 * snapshot while Postgres is failing. Request handling is unaffected: the gate
 * keeps enforcing that floor/snapshot, never an empty table.
 *
 * <p>This indicator is part of the aggregate {@code /actuator/health} only. It is
 * deliberately NOT in the {@code readiness} or {@code liveness} groups, which the
 * chart and compose probes poll: a Postgres outage must not pull every gateway
 * out of rotation, because the gateway's fallback is fail-CLOSED, not fail-open.
 * With no datastore wired (route access disabled, or a seed-only dev gateway) the
 * seed IS the authority and this reports {@code UP}.
 */
@Component("routeAccess")
public class RouteAccessHealthIndicator implements HealthIndicator {

    private final GatewayRouteAccessService routeAccess;

    public RouteAccessHealthIndicator(GatewayRouteAccessService routeAccess) {
        this.routeAccess = routeAccess;
    }

    @Override
    public Health health() {
        if (!routeAccess.isEnabled()) {
            return Health.up().withDetail("enabled", false).build();
        }
        String reason = routeAccess.degradedReason();
        Health.Builder b = reason == null ? Health.up() : Health.down();
        b.withDetail("gateway", routeAccess.gatewayName())
         .withDetail("authoritativeSource", routeAccess.authoritativeSource())
         .withDetail("enforcing", routeAccess.source())
         .withDetail("rules", routeAccess.ruleCount())
         .withDetail("lastRefreshAt", String.valueOf(routeAccess.lastRefreshAt()));
        if (reason != null) {
            b.withDetail("reason", reason);
            Instant since = routeAccess.degradedSince();
            if (since != null) b.withDetail("degradedSince", since.toString());
        }
        return b.build();
    }
}
