package net.hugmesh.gateway.cache;

import com.datastax.oss.driver.api.core.cql.Row;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;
import org.springframework.cloud.client.circuitbreaker.ConfigBuilder;
import org.springframework.cloud.client.circuitbreaker.ReactiveCircuitBreaker;
import org.springframework.cloud.client.circuitbreaker.ReactiveCircuitBreakerFactory;
import org.springframework.data.cassandra.core.ReactiveCassandraTemplate;
import org.springframework.data.cassandra.core.cql.ReactiveCqlOperations;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.stream.Stream;

import net.hugmesh.gateway.cache.GatewayRouteAccessService.Decision;
import net.hugmesh.gateway.cache.GatewayRouteAccessService.Rule;
import net.hugmesh.gateway.config.RouteAccessR2dbcConfig;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * hugmesh-gateway#61: an EMPTY route-access load must never replace the seed floor
 * or a non-empty snapshot. Measured fail-open: Postgres rejected the gateway's
 * login, the switchIfEmpty fallback read a FRESH (empty) Cassandra cache, and the
 * unconditional swap installed {@code []}, so every governed path became
 * {@code NO_RULE} and was forwarded for a plain ROLE_USER.
 *
 * <p>Every branch of {@code refreshNow()} is driven here against a mocked
 * {@link GatewayRouteAccessRepository} (Postgres) AND a mocked
 * {@link ReactiveCassandraTemplate} (never {@code null}, which is what hid the
 * branch before), each run with no breaker and with a pass-through breaker that
 * routes a read error to the production fallback (what a CLOSED Resilience4j
 * breaker does).
 */
class RouteAccessEmptyLoadFloorTest {

    private static final String GATEWAY = "hugmesh-be-gateway";
    /** BE seed: /api/admin/** -> ROLE_ADMIN, so a ROLE_USER is DENIED here. */
    private static final String SEED_DENIED_FOR_USER = "/api/admin/users";
    private static final List<String> USER = List.of("ROLE_USER");
    private static final List<String> IDS = List.of("u-1");

    // ── fixtures ────────────────────────────────────────────────────────────────

    /** A mocked Postgres repository whose next answer is whatever {@code next} holds. */
    private static GatewayRouteAccessRepository postgres(AtomicReference<Flux<GatewayRouteAccessRow>> next) {
        GatewayRouteAccessRepository repo = mock(GatewayRouteAccessRepository.class);
        when(repo.findByGateway(GATEWAY)).thenAnswer(inv -> next.get());
        return repo;
    }

    private static GatewayRouteAccessRow pgRow(String pattern, String role) {
        return new GatewayRouteAccessRow(UUID.nameUUIDFromBytes((pattern + role).getBytes()),
                GATEWAY, pattern, role, null, true, null, false, null);
    }

    /** Three Postgres rows, distinguishable from the seed by the /pg-only/** pattern. */
    private static List<GatewayRouteAccessRow> pgTable() {
        return List.of(
                pgRow("/api/admin/**", "ROLE_ADMIN"),
                pgRow("/api/**", "ROLE_USER"),
                pgRow("/pg-only/**", "ROLE_ADMIN"));
    }

    /** A mocked Cassandra template whose {@code SELECT} streams {@code rows}, and
     *  whose mirror INSERTs succeed and are counted in {@code mirrored}. */
    private static ReactiveCassandraTemplate cassandra(AtomicReference<Flux<Row>> rows,
                                                       AtomicInteger mirrored) {
        ReactiveCqlOperations cql = mock(ReactiveCqlOperations.class);
        when(cql.queryForRows(anyString())).thenAnswer(inv -> rows.get());
        when(cql.execute(anyString(), any(Object[].class))).thenAnswer(inv -> {
            mirrored.incrementAndGet();
            return Mono.just(true);
        });
        ReactiveCassandraTemplate template = mock(ReactiveCassandraTemplate.class);
        when(template.getReactiveCqlOperations()).thenReturn(cql);
        return template;
    }

    private static Row cRow(String gateway, String pattern, String role) {
        Row row = mock(Row.class);
        when(row.getString("id")).thenReturn("c-" + pattern + "-" + role);
        when(row.getString("gateway")).thenReturn(gateway);
        when(row.getString("url_pattern")).thenReturn(pattern);
        when(row.getString("role")).thenReturn(role);
        when(row.getString("casdoor_user")).thenReturn(null);
        when(row.getBoolean("allow")).thenReturn(true);
        when(row.getString("domain")).thenReturn(null);
        when(row.getBoolean("mfa_required")).thenReturn(false);
        return row;
    }

    private static RuntimeException authRejected() {
        return new RuntimeException("password authentication failed for user \"be_gateway\"");
    }

    static Stream<Arguments> breakers() {
        return Stream.of(
                Arguments.of("no breaker", null),
                Arguments.of("closed breaker (error -> fallback)", passThroughBreakerFactory()));
    }

    private static GatewayRouteAccessService service(GatewayRouteAccessRepository repo,
                                                     ReactiveCassandraTemplate template,
                                                     ReactiveCircuitBreakerFactory<?, ?> breakers) {
        return new GatewayRouteAccessService(template, repo, GATEWAY, true, false, breakers);
    }

    /** Seed then one refresh tick, like {@code @PostConstruct init()}, but blocking
     *  on the tick instead of firing it off. */
    private static void coldStart(GatewayRouteAccessService svc) {
        svc.init();
        svc.refreshNow().block();
    }

    private static Health health(GatewayRouteAccessService svc) {
        return new RouteAccessHealthIndicator(svc).health();
    }

    // ── Postgres OK ─────────────────────────────────────────────────────────────

    @ParameterizedTest(name = "{0}")
    @MethodSource("breakers")
    void postgresOk_installsTheTable_mirrorsIt_andIsHealthy(String label, ReactiveCircuitBreakerFactory<?, ?> b) {
        var pg = new AtomicReference<>(Flux.fromIterable(pgTable()));
        var cs = new AtomicReference<Flux<Row>>(Flux.empty());
        var mirrored = new AtomicInteger();
        GatewayRouteAccessService svc = service(postgres(pg), cassandra(cs, mirrored), b);

        coldStart(svc);

        assertThat(svc.source()).isEqualTo("postgres");
        assertThat(svc.ruleCount()).isEqualTo(3);
        assertThat(svc.decide("/pg-only/x", "default", IDS, USER)).isEqualTo(Decision.DENY);
        assertThat(svc.isPrimed()).isTrue();
        assertThat(svc.degradedReason()).isNull();
        assertThat(mirrored.get()).as("every Postgres row write-through-mirrored, on both ticks")
                .isEqualTo(2 * 3);
        assertThat(health(svc).getStatus()).isEqualTo(Status.UP);
    }

    // ── Postgres fails + Cassandra EMPTY at cold start -> the seed floor (#61 S2) ─

    @ParameterizedTest(name = "{0}")
    @MethodSource("breakers")
    void postgresFails_cassandraEmpty_coldStart_keepsSeedFloor(String label, ReactiveCircuitBreakerFactory<?, ?> b) {
        var pg = new AtomicReference<Flux<GatewayRouteAccessRow>>(Flux.error(authRejected()));
        var cs = new AtomicReference<Flux<Row>>(Flux.empty());
        GatewayRouteAccessService svc = service(postgres(pg), cassandra(cs, new AtomicInteger()), b);

        coldStart(svc);
        svc.refreshNow().block();   // and it stays that way tick after tick

        assertThat(svc.ruleCount())
                .as("the empty Cassandra result must NOT replace the seed floor")
                .isEqualTo(CanonicalSeed.forGateway(GATEWAY).size())
                .isPositive();
        assertThat(svc.source()).isEqualTo("seed");
        assertThat(svc.decide(SEED_DENIED_FOR_USER, "default", IDS, USER))
                .as("a seed-governed admin path is still DENIED for a ROLE_USER (was NO_RULE -> forwarded)")
                .isEqualTo(Decision.DENY);
        assertThat(svc.isPrimed())
                .as("an empty load is not a load: the snapshot is still not authoritative")
                .isFalse();
        assertThat(svc.degradedReason())
                .contains("postgres")
                .contains("password authentication failed")
                .contains("seed floor");
        Health h = health(svc);
        assertThat(h.getStatus()).isEqualTo(Status.DOWN);
        assertThat(h.getDetails()).containsEntry("enforcing", "seed")
                .containsEntry("authoritativeSource", "postgres");
    }

    // ── Postgres fails + Cassandra EMPTY after a good load -> keeps that load ────

    @ParameterizedTest(name = "{0}")
    @MethodSource("breakers")
    void postgresFails_cassandraEmpty_afterGoodLoad_keepsLastKnownGood(String label, ReactiveCircuitBreakerFactory<?, ?> b) {
        var pg = new AtomicReference<>(Flux.fromIterable(pgTable()));
        var cs = new AtomicReference<Flux<Row>>(Flux.empty());
        GatewayRouteAccessService svc = service(postgres(pg), cassandra(cs, new AtomicInteger()), b);
        coldStart(svc);
        assertThat(svc.source()).isEqualTo("postgres");
        var primedAt = svc.lastRefreshAt();

        pg.set(Flux.error(authRejected()));
        svc.refreshNow().block();

        assertThat(svc.source()).as("the last-known-good Postgres snapshot stays").isEqualTo("postgres");
        assertThat(svc.ruleCount()).isEqualTo(3);
        assertThat(svc.decide("/pg-only/x", "default", IDS, USER)).isEqualTo(Decision.DENY);
        assertThat(svc.decide(SEED_DENIED_FOR_USER, "default", IDS, USER)).isEqualTo(Decision.DENY);
        assertThat(svc.lastRefreshAt()).as("nothing was installed").isEqualTo(primedAt);
        assertThat(svc.degradedReason()).contains("last-known-good postgres snapshot (3 rules)");
        assertThat(health(svc).getStatus()).isEqualTo(Status.DOWN);

        // ... and recovery clears the degraded state.
        pg.set(Flux.fromIterable(pgTable()));
        svc.refreshNow().block();
        assertThat(svc.degradedReason()).isNull();
        assertThat(health(svc).getStatus()).isEqualTo(Status.UP);
    }

    // ── Postgres fails + Cassandra POPULATED -> the Cassandra snapshot (#61 S3) ──

    @ParameterizedTest(name = "{0}")
    @MethodSource("breakers")
    void postgresFails_cassandraPopulated_installsCassandra(String label, ReactiveCircuitBreakerFactory<?, ?> b) {
        var pg = new AtomicReference<Flux<GatewayRouteAccessRow>>(Flux.error(authRejected()));
        var cs = new AtomicReference<Flux<Row>>(Flux.just(
                cRow(GATEWAY, "/api/admin/**", "ROLE_ADMIN"),
                cRow(GATEWAY, "/cass-only/**", "ROLE_ADMIN"),
                // another gateway's row in the shared table is never enforced here
                cRow("hugmesh-fe-gateway", "/fe-only/**", "ROLE_ADMIN")));
        GatewayRouteAccessService svc = service(postgres(pg), cassandra(cs, new AtomicInteger()), b);

        coldStart(svc);

        assertThat(svc.source()).isEqualTo("cassandra");
        assertThat(svc.ruleCount()).isEqualTo(2);
        assertThat(svc.decide("/cass-only/x", "default", IDS, USER)).isEqualTo(Decision.DENY);
        assertThat(svc.decide("/fe-only/x", "default", IDS, USER)).isEqualTo(Decision.NO_RULE);
        assertThat(svc.degradedReason())
                .as("serving the cache while the source of truth fails is still degraded")
                .contains("last-known-good cassandra snapshot (2 rules)");
        assertThat(health(svc).getStatus()).isEqualTo(Status.DOWN);
    }

    // ── Postgres REACHABLE but returns zero rows -> never installed either ──────

    @ParameterizedTest(name = "{0}")
    @MethodSource("breakers")
    void postgresReturnsZeroRows_isNotInstalled_coldStartAndAfterGoodLoad(String label, ReactiveCircuitBreakerFactory<?, ?> b) {
        var pg = new AtomicReference<Flux<GatewayRouteAccessRow>>(Flux.empty());
        var cs = new AtomicReference<Flux<Row>>(Flux.empty());
        GatewayRouteAccessService svc = service(postgres(pg), cassandra(cs, new AtomicInteger()), b);

        coldStart(svc);
        assertThat(svc.source()).isEqualTo("seed");
        assertThat(svc.decide(SEED_DENIED_FOR_USER, "default", IDS, USER)).isEqualTo(Decision.DENY);
        assertThat(svc.degradedReason()).contains("returned 0 rows for " + GATEWAY);

        pg.set(Flux.fromIterable(pgTable()));
        svc.refreshNow().block();
        pg.set(Flux.empty());   // e.g. every row of this gateway deleted, or a renamed gateway
        svc.refreshNow().block();
        assertThat(svc.source()).isEqualTo("postgres");
        assertThat(svc.ruleCount()).isEqualTo(3);
        assertThat(health(svc).getStatus()).isEqualTo(Status.DOWN);
    }

    // ── admin edits still land: a NON-empty Postgres table is authoritative ─────

    @Test
    void adminDeletingSomeRows_takesEffectOnTheNextTick() {
        var pg = new AtomicReference<>(Flux.fromIterable(pgTable()));
        var cs = new AtomicReference<Flux<Row>>(Flux.empty());
        GatewayRouteAccessService svc = service(postgres(pg), cassandra(cs, new AtomicInteger()), null);
        coldStart(svc);
        assertThat(svc.decide("/pg-only/x", "default", IDS, USER)).isEqualTo(Decision.DENY);

        pg.set(Flux.fromIterable(pgTable().subList(0, 2)));   // admin deleted /pg-only/**
        svc.refreshNow().block();

        assertThat(svc.ruleCount()).isEqualTo(2);
        assertThat(svc.decide("/pg-only/x", "default", IDS, USER))
                .as("the deleted row no longer governs the path")
                .isEqualTo(Decision.NO_RULE);
        assertThat(svc.degradedReason()).isNull();
    }

    // ── invalid ROUTE_ACCESS_R2DBC_URL -> wired-and-failing, not Cassandra-only ──

    @ParameterizedTest(name = "{0}")
    @MethodSource("breakers")
    void invalidR2dbcUrl_keepsSeedFloor_andReportsDegraded(String label, ReactiveCircuitBreakerFactory<?, ?> b) {
        GatewayRouteAccessRepository invalid = RouteAccessR2dbcConfig.failingRepository(
                "ROUTE_ACCESS_R2DBC_URL is set but invalid (IllegalArgumentException)");
        var cs = new AtomicReference<Flux<Row>>(Flux.empty());
        GatewayRouteAccessService svc = service(invalid, cassandra(cs, new AtomicInteger()), b);

        coldStart(svc);

        assertThat(svc.authoritativeSource()).isEqualTo("postgres");
        assertThat(svc.source()).isEqualTo("seed");
        assertThat(svc.decide(SEED_DENIED_FOR_USER, "default", IDS, USER)).isEqualTo(Decision.DENY);
        assertThat(svc.isPrimed()).isFalse();
        assertThat(svc.degradedReason()).contains("ROUTE_ACCESS_R2DBC_URL is set but invalid");
        assertThat(health(svc).getStatus()).isEqualTo(Status.DOWN);
    }

    // ── health: no datastore wired / disabled -> UP (the seed IS the authority) ──

    @Test
    void health_isUp_whenNoDatastoreIsWired_orRouteAccessIsDisabled() {
        GatewayRouteAccessService seedOnly = service(null, null, null);
        coldStart(seedOnly);
        assertThat(seedOnly.degradedReason()).isNull();
        assertThat(health(seedOnly).getStatus()).isEqualTo(Status.UP);

        GatewayRouteAccessService disabled =
                new GatewayRouteAccessService(null, null, GATEWAY, false, false, null);
        disabled.init();
        assertThat(health(disabled).getStatus()).isEqualTo(Status.UP);
    }

    @Test
    void health_isDown_beforeTheFirstLoad_whenADatastoreIsWired() {
        var pg = new AtomicReference<Flux<GatewayRouteAccessRow>>(Flux.never());
        GatewayRouteAccessService svc = service(postgres(pg), null, null);
        svc.init();   // the first tick never completes
        assertThat(svc.degradedReason()).contains("not loaded yet");
        assertThat(health(svc).getStatus()).isEqualTo(Status.DOWN);
    }

    @Test
    void everyCanonicalTierSeed_isNonEmpty_soAnEmptyLoadIsNeverTheIntendedState() {
        for (String gw : List.of("hugmesh-pki-gateway", "hugmesh-be-gateway", "hugmesh-fe-gateway",
                "brand-x-be-gateway", "something-else", "")) {
            List<Rule> seed = CanonicalSeed.forGateway(gw);
            assertThat(seed).as("seed for '%s'", gw).isNotEmpty();
        }
    }

    // ── breaker fixture ─────────────────────────────────────────────────────────

    /** A CLOSED breaker: it runs the read and routes an error to the fallback,
     *  as Resilience4j does before it trips. */
    static ReactiveCircuitBreakerFactory<?, ?> passThroughBreakerFactory() {
        ReactiveCircuitBreaker closed = new ReactiveCircuitBreaker() {
            @Override public <T> Mono<T> run(Mono<T> toRun, Function<Throwable, Mono<T>> fallback) {
                return toRun.onErrorResume(fallback);
            }
            @Override public <T> Flux<T> run(Flux<T> toRun, Function<Throwable, Flux<T>> fallback) {
                return toRun.onErrorResume(fallback);
            }
        };
        return new SingleBreakerFactory(closed);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    static final class SingleBreakerFactory extends ReactiveCircuitBreakerFactory {
        private final ReactiveCircuitBreaker breaker;
        SingleBreakerFactory(ReactiveCircuitBreaker breaker) { this.breaker = breaker; }
        @Override public ReactiveCircuitBreaker create(String id) { return breaker; }
        @Override protected ConfigBuilder configBuilder(String id) { return null; }
        @Override public void configureDefault(Function defaultConfiguration) { }
    }
}
