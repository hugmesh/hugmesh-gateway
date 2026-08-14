package net.hugmesh.gateway.config;

import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.timelimiter.TimeLimiterConfig;
import org.springframework.cloud.circuitbreaker.resilience4j.ReactiveResilience4JCircuitBreakerFactory;
import org.springframework.cloud.client.circuitbreaker.Customizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

/**
 * Spring Cloud Circuit Breaker (Resilience4j) tuning for the gateway's
 * route-access control-plane refresh — the hugmesh.net analogue of the
 * hugmesh.games {@code cassandra} breaker (which wraps the cluster-wide
 * rate-limit / revocation reads so a slow store doesn't pile up checks on the
 * hot path).
 *
 * <p>{@link net.hugmesh.gateway.cache.GatewayRouteAccessService} polls
 * its rule set every {@code app.route-access.refresh-interval-ms} and swaps an
 * in-memory snapshot, so an admin's rule change lands across <em>all gateway
 * pods</em> within one tick. Each refresh reads a datastore — the Postgres
 * source-of-truth load and, on its absence/failure, the Cassandra read-cache
 * fallback. Both reads run through the {@code routeAccess} breaker:
 * <ul>
 *   <li><b>CLOSED</b> — refresh reads pass through; failures grow the window.</li>
 *   <li><b>OPEN</b> — refresh ticks fast-fail with {@code CallNotPermittedException}
 *       (routed to the fallback) instead of blocking the scheduler on a slow or
 *       partitioned datastore; the gateway keeps enforcing its last-good rule
 *       snapshot (never fail-open).</li>
 *   <li><b>HALF-OPEN</b> — a few probe reads; success closes it and the next refresh
 *       picks up whatever rules the admin changed while it was open.</li>
 * </ul>
 * The breaker only governs <em>refresh</em>; the request-time {@code decide()} check
 * is a constant-time in-memory walk and never touches a datastore.
 */
@Configuration
public class GatewayResilienceConfig {

    /**
     * Configure the {@code routeAccess} circuit-breaker instance. Values mirror the
     * hugmesh.games {@code cassandra} instance; the 3s time limit comfortably
     * exceeds a healthy refresh yet sits under the 5s default poll interval so a
     * hung read is cancelled before the next tick fires.
     */
    @Bean
    public Customizer<ReactiveResilience4JCircuitBreakerFactory> routeAccessBreakerCustomizer() {
        CircuitBreakerConfig cb = CircuitBreakerConfig.custom()
                .slidingWindowSize(10)
                .minimumNumberOfCalls(5)
                .failureRateThreshold(50f)
                .waitDurationInOpenState(Duration.ofSeconds(30))
                .permittedNumberOfCallsInHalfOpenState(3)
                .build();
        TimeLimiterConfig tl = TimeLimiterConfig.custom()
                .timeoutDuration(Duration.ofSeconds(3))
                .build();
        return factory -> factory.configure(
                builder -> builder.circuitBreakerConfig(cb).timeLimiterConfig(tl),
                "routeAccess");
    }
}
