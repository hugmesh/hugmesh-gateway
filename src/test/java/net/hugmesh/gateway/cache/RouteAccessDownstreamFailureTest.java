package net.hugmesh.gateway.cache;

import com.datastax.oss.driver.api.core.cql.Row;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Status;
import org.springframework.cloud.client.circuitbreaker.ConfigBuilder;
import org.springframework.cloud.client.circuitbreaker.ReactiveCircuitBreaker;
import org.springframework.cloud.client.circuitbreaker.ReactiveCircuitBreakerFactory;
import org.springframework.data.cassandra.core.ReactiveCassandraTemplate;
import org.springframework.data.cassandra.core.cql.ReactiveCqlOperations;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ServerWebExchangeDecorator;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.security.Principal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;

import net.hugmesh.gateway.cache.GatewayRouteAccessService.Decision;
import net.hugmesh.gateway.filter.GatewayRouteAccessFilter;
import net.hugmesh.gateway.security.DomainRegistry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * WAVE-2 DOWNSTREAM-FAILURE resilience — when the route-access control-plane datastore
 * is slow / partitioned / erroring (the {@code routeAccess} circuit breaker is OPEN),
 * the gateway's REQUEST path must still return a CONTROLLED verdict (enforce the
 * last-good rule snapshot) at the {@link GatewayRouteAccessFilter} HTTP boundary —
 * NEVER a 500 / a leaked stack trace, and NEVER fail-open.
 *
 * <p>The companion {@code GatewayRouteAccessServiceTest.refreshPath_isRoutedThroughRouteAccessBreaker}
 * proves the refresh read is WRAPPED in the breaker. This test takes the next step that
 * matters for the user-facing contract: under an OPEN breaker (and under a raw datastore
 * ERROR), it drives the FILTER and asserts the HTTP-boundary outcome.
 *
 * <p><b>What "last-good" is here.</b> {@code init()} synchronously seeds the in-memory
 * snapshot with the {@code CanonicalSeed} for this gateway tier (so the gate is NEVER
 * fail-open before the first datastore round-trip), THEN fires a refresh tick. With the
 * breaker OPEN (or the datastore erroring) that refresh fast-fails to the fallback
 * ({@code Mono.empty}), and when a read DOES complete it returns zero rows (a fresh
 * Cassandra cache), which is refused as a load (hugmesh-gateway#61). Either way the
 * CANONICAL SEED stands as the enforced ruleset.
 *
 * <p>The Cassandra template is a REAL mock that answers zero rows, never {@code null}: a
 * {@code null} template skips the Cassandra fallback entirely, which is exactly how the
 * #61 fail-open (an empty cache swapped in over the seed) went untested.
 *
 * <p>For {@code hugmesh-be-gateway} the seed grants
 * {@code /api/** -> ROLE_USER} (a user reaches a plain api path) but governs
 * {@code /api/admin/** -> ROLE_ADMIN} (a user is DENIED there). The assertions key on
 * those production-seed verdicts:
 * <ul>
 *   <li><b>OPEN breaker → seed DENY still 403</b> — a ROLE_USER on {@code /api/admin/**}
 *       gets the controlled 403 + {@code X-Route-Denied} header (not 500, not forwarded);</li>
 *   <li><b>OPEN breaker → seed ALLOW still forwards</b> — a ROLE_USER on {@code /api/**}
 *       still forwards (the gateway serves its last-good ALLOW the breaker could not
 *       refresh away);</li>
 *   <li><b>datastore READ errors → refresh swallows, seed retained</b> — a refresh whose
 *       datastore read errors completes WITHOUT propagating out of {@code init()}, the seed
 *       is retained, and a subsequent request is still adjudicated (controlled), not 500;</li>
 *   <li><b>decide() never throws</b> — the request-time check is a constant-time in-memory
 *       walk that takes no datastore, so a hung/erroring store can never surface as a
 *       request-path exception.</li>
 * </ul>
 *
 * <p>Per the comprehensive test standard these are the resilience / fault-injection
 * facet of USER-SITUATIONAL access: the SAME allow/deny verdict must hold while the
 * control-plane datastore is degraded — degradation must never escalate (fail-open) nor
 * leak a stack trace (uncontrolled 500).
 */
class RouteAccessDownstreamFailureTest {

    private static final String GATEWAY = "hugmesh-be-gateway";
    private static final String SINGLE_ISSUER = "http://casdoor:8000";

    /** Single-issuer registry → every host/token resolves to "default" (single-tenant
     *  back-compat), so the filter's domain scoping is a no-op here and we isolate the
     *  resilience behaviour. */
    private static DomainRegistry registry() {
        return new DomainRegistry(SINGLE_ISSUER, "", "");
    }

    private static Jwt userJwt() {
        return Jwt.withTokenValue("test")
                .header("alg", "none")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .subject("u-1")
                .issuer(SINGLE_ISSUER)
                .claim("roles", List.of("user"))
                .claim("name", "u-1")
                .build();
    }

    private static AbstractAuthenticationToken plainUser() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        return new JwtAuthenticationToken(userJwt(), authorities);
    }

    /** The BE-tier seed governs /api/admin/** to ROLE_ADMIN — a ROLE_USER is DENIED.
     *  This is the path we use to prove the controlled-DENY survives a datastore outage. */
    private static final String SEED_DENIED_FOR_USER = "/api/admin/users";

    /** The BE-tier seed grants /api/** to ROLE_USER — a ROLE_USER is ALLOWED here. */
    private static final String SEED_ALLOWED_FOR_USER = "/api/reports/q3";

    private MockServerWebExchange driveFilter(GatewayRouteAccessService svc, String path,
                                              AtomicBoolean forwarded) {
        GatewayRouteAccessFilter filter = new GatewayRouteAccessFilter(svc, registry());
        WebFilterChain chain = ex -> {
            forwarded.set(true);
            return Mono.empty();
        };
        MockServerHttpRequest req = MockServerHttpRequest.get(path)
                .header(HttpHeaders.HOST, "gateway.local").build();
        MockServerWebExchange mwex = MockServerWebExchange.from(req);
        filter.filter(new PrincipalExchange(mwex, plainUser()), chain).block();
        return mwex;
    }

    // ── OPEN breaker → last-good snapshot still enforced (controlled, never 500) ─

    @Test
    void openBreaker_seedDeny_stillReturnsControlled403_notFailOpen_norStackTrace() {
        // The breaker is OPEN: init() seeds the canonical BE floor, then the refresh tick
        // fast-fails to the fallback (Mono.empty) WITHOUT throwing, so nothing is
        // installed and the seed stands. A ROLE_USER on the seed's ROLE_ADMIN-gated /api/admin/**
        // is the last-good DENY.
        GatewayRouteAccessService svc = new GatewayRouteAccessService(
                emptyCassandra(), null, GATEWAY, true, false, openBreakerFactory());
        assertThatCode(svc::init)
                .as("the OPEN-breaker refresh tick must not propagate out of init()")
                .doesNotThrowAnyException();

        AtomicBoolean forwarded = new AtomicBoolean(false);
        MockServerWebExchange mwex = driveFilter(svc, SEED_DENIED_FOR_USER, forwarded);

        assertThat(forwarded).as("breaker-open must NOT fail open — the request is not forwarded").isFalse();
        assertThat(mwex.getResponse().getStatusCode())
                .as("a controlled 403 from the last-good seed DENY, never an uncontrolled 500")
                .isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(mwex.getResponse().getHeaders().getFirst("X-Route-Denied"))
                .as("the controlled-denial header is set — not a stack-trace body")
                .isEqualTo(GATEWAY + ":" + SEED_DENIED_FOR_USER);
    }

    @Test
    void openBreaker_seedAllow_stillForwards() {
        // The other side of the controlled verdict: a path the seed grants ROLE_USER
        // (/api/**) still forwards while the breaker is open — the gateway serves its
        // last-good ALLOW, never fail-CLOSED on everything either.
        GatewayRouteAccessService svc = new GatewayRouteAccessService(
                emptyCassandra(), null, GATEWAY, true, false, openBreakerFactory());
        svc.init();

        AtomicBoolean forwarded = new AtomicBoolean(false);
        MockServerWebExchange mwex = driveFilter(svc, SEED_ALLOWED_FOR_USER, forwarded);

        assertThat(forwarded).as("granted last-good ALLOW still forwards under an open breaker").isTrue();
        assertThat(mwex.getResponse().getStatusCode())
                .as("no error status set on the forwarded path")
                .isNull();
    }

    // ── datastore READ errors → refresh swallows, request path stays controlled ─

    @Test
    void datastoreReadErrors_refreshDoesNotPropagate_seedRetained() {
        // A breaker that does NOT short-circuit but lets a throwing read run, then routes
        // its error to the fallback — modelling a datastore that is REACHABLE but ERRORS.
        // The service's guarded(...)+onErrorResume must catch it, the refresh completes
        // empty, the seed is retained, and init() must not propagate the datastore error.
        GatewayRouteAccessService svc = new GatewayRouteAccessService(
                emptyCassandra(), null, GATEWAY, true, false, erroringBreakerFactory());

        assertThatCode(svc::init)
                .as("a refresh whose datastore read errors must NOT propagate out of init()")
                .doesNotThrowAnyException();

        // The request path is still adjudicated against the retained seed (controlled 403,
        // not a 500).
        AtomicBoolean forwarded = new AtomicBoolean(false);
        MockServerWebExchange mwex = driveFilter(svc, SEED_DENIED_FOR_USER, forwarded);
        assertThat(forwarded).isFalse();
        assertThat(mwex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    // ── decide() is datastore-free: it can never surface a downstream failure ───

    @Test
    void decide_isInMemoryAndNeverThrows_evenUnderOpenBreaker() {
        // The request-time check takes no datastore. Even with the breaker open and the
        // refresh fast-failing, decide() is a pure walk over the in-memory seed snapshot —
        // a controlled verdict, never an exception (which would surface as a 500).
        GatewayRouteAccessService svc = new GatewayRouteAccessService(
                emptyCassandra(), null, GATEWAY, true, false, openBreakerFactory());
        svc.init();

        assertThatCode(() -> {
            Decision denied = svc.decide(SEED_DENIED_FOR_USER, "default", List.of("u-1"), List.of("ROLE_USER"));
            Decision allowed = svc.decide(SEED_ALLOWED_FOR_USER, "default", List.of("u-1"), List.of("ROLE_USER"));
            assertThat(denied).as("seed DENY enforced under an open breaker").isEqualTo(Decision.DENY);
            assertThat(allowed).as("seed ALLOW enforced under an open breaker").isEqualTo(Decision.ALLOW);
        }).doesNotThrowAnyException();
    }

    // ── #61: Postgres REJECTS the login, Cassandra is FRESH (zero rows) ─────────

    @Test
    void postgresRejected_freshCassandra_seedDenyStillReturns403_notForwarded() {
        // The measured fail-open (issue #61 scenario S2): a CLOSED breaker lets both reads
        // run; Postgres errors (wrong password), Cassandra answers zero rows. The empty
        // result must not replace the seed: a ROLE_USER on the seed-governed admin path
        // still gets the controlled 403, not a forward.
        GatewayRouteAccessRepository rejected = mock(GatewayRouteAccessRepository.class);
        when(rejected.findByGateway(GATEWAY)).thenReturn(
                Flux.error(new RuntimeException("password authentication failed for user \"be_gateway\"")));
        GatewayRouteAccessService svc = new GatewayRouteAccessService(
                emptyCassandra(), rejected, GATEWAY, true, false,
                RouteAccessEmptyLoadFloorTest.passThroughBreakerFactory());
        svc.init();
        svc.refreshNow().block();   // a later tick, same outcome

        AtomicBoolean forwarded = new AtomicBoolean(false);
        MockServerWebExchange mwex = driveFilter(svc, SEED_DENIED_FOR_USER, forwarded);
        assertThat(forwarded).as("an empty cache must not turn the gate fail-open").isFalse();
        assertThat(mwex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(mwex.getResponse().getHeaders().getFirst("X-Route-Denied"))
                .isEqualTo(GATEWAY + ":" + SEED_DENIED_FOR_USER);

        AtomicBoolean allowedForwarded = new AtomicBoolean(false);
        driveFilter(svc, SEED_ALLOWED_FOR_USER, allowedForwarded);
        assertThat(allowedForwarded).as("the seed ALLOW still forwards").isTrue();

        assertThat(new RouteAccessHealthIndicator(svc).health().getStatus())
                .as("running on the seed floor while Postgres fails is reported, not silent")
                .isEqualTo(Status.DOWN);
    }

    // ── test fixtures ───────────────────────────────────────────────────────────

    /** A Cassandra template whose route-access SELECT returns ZERO rows (a fresh
     *  cache), and whose mirror INSERTs succeed. */
    private static ReactiveCassandraTemplate emptyCassandra() {
        ReactiveCqlOperations cql = mock(ReactiveCqlOperations.class);
        when(cql.queryForRows(anyString())).thenReturn(Flux.<Row>empty());
        when(cql.execute(anyString(), any(Object[].class))).thenReturn(Mono.just(true));
        ReactiveCassandraTemplate template = mock(ReactiveCassandraTemplate.class);
        when(template.getReactiveCqlOperations()).thenReturn(cql);
        return template;
    }

    /** A {@link ReactiveCircuitBreakerFactory} whose breaker is genuinely OPEN: it
     *  ALWAYS routes the call to the fallback with a real {@link CallNotPermittedException}
     *  (what an open Resilience4j breaker raises), exactly as the production
     *  {@code GatewayRouteAccessService.guarded(...)} fallback handles. */
    private static ReactiveCircuitBreakerFactory<?, ?> openBreakerFactory() {
        ReactiveCircuitBreaker open = new ReactiveCircuitBreaker() {
            @Override public <T> Mono<T> run(Mono<T> toRun, Function<Throwable, Mono<T>> fallback) {
                // Open breaker: the wrapped read is NOT executed; the fallback runs with
                // a CallNotPermittedException, just like Resilience4j fast-fail.
                return Mono.defer(() -> fallback.apply(callNotPermitted()));
            }
            @Override public <T> Flux<T> run(Flux<T> toRun, Function<Throwable, Flux<T>> fallback) {
                return Flux.defer(() -> fallback.apply(callNotPermitted()));
            }
        };
        return new SingleBreakerFactory(open);
    }

    private static CallNotPermittedException callNotPermitted() {
        CircuitBreaker cb = CircuitBreaker.of("routeAccess", CircuitBreakerConfig.ofDefaults());
        cb.transitionToOpenState();
        return CallNotPermittedException.createCallNotPermittedException(cb);
    }

    /** A breaker that models a REACHABLE datastore whose read ERRORS (a timeout /
     *  connection reset surfaced as an exception, NOT a fast-fail). It raises a
     *  datastore-style exception and lets the production fallback ({@code t -> Mono.empty()})
     *  handle it — so {@code guarded(...)} routes to empty, the refresh completes, and the
     *  seed is retained. */
    private static ReactiveCircuitBreakerFactory<?, ?> erroringBreakerFactory() {
        ReactiveCircuitBreaker erroring = new ReactiveCircuitBreaker() {
            @Override public <T> Mono<T> run(Mono<T> toRun, Function<Throwable, Mono<T>> fallback) {
                return Mono.<T>error(new RuntimeException("route-access datastore read timed out"))
                        .onErrorResume(fallback);
            }
            @Override public <T> Flux<T> run(Flux<T> toRun, Function<Throwable, Flux<T>> fallback) {
                return Flux.<T>error(new RuntimeException("route-access datastore read timed out"))
                        .onErrorResume(fallback);
            }
        };
        return new SingleBreakerFactory(erroring);
    }

    /** Minimal factory that returns the supplied breaker for any id. */
    @SuppressWarnings({"rawtypes", "unchecked"})
    private static final class SingleBreakerFactory extends ReactiveCircuitBreakerFactory {
        private final ReactiveCircuitBreaker breaker;
        SingleBreakerFactory(ReactiveCircuitBreaker breaker) { this.breaker = breaker; }
        @Override public ReactiveCircuitBreaker create(String id) { return breaker; }
        @Override protected ConfigBuilder configBuilder(String id) { return null; }
        @Override public void configureDefault(Function defaultConfiguration) { }
    }

    /** Populates getPrincipal() on a MockServerWebExchange (it is empty otherwise) —
     *  mirrors the helper in {@code GatewayRouteAccessFilterTest}. */
    private static final class PrincipalExchange extends ServerWebExchangeDecorator {
        private final Principal principal;
        PrincipalExchange(ServerWebExchange delegate, Principal principal) {
            super(delegate);
            this.principal = principal;
        }
        @Override
        @SuppressWarnings("unchecked")
        public <T extends Principal> Mono<T> getPrincipal() {
            return Mono.just((T) principal);
        }
    }
}
