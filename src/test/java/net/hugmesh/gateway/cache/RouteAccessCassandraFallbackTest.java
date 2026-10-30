package net.hugmesh.gateway.cache;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;
import org.springframework.cloud.client.circuitbreaker.ReactiveCircuitBreakerFactory;
import reactor.core.publisher.Flux;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import net.hugmesh.gateway.cache.GatewayRouteAccessService.Decision;
import net.hugmesh.gateway.cache.GatewayRouteAccessService.Rule;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * hugmesh-gateway#61, round 2: the Cassandra fallback must not fail OPEN when the
 * cache holds only SOME of a gateway's rows (the refuter's S7 and S8: a 1-row
 * cache forwarded every seed-governed path and primed the MFA floor).
 *
 * <ul>
 *   <li>a Cassandra install is the UNION of the cache rows and every seed rule
 *       whose pattern the cache does not carry;</li>
 *   <li>a Cassandra install never moves {@code lastRefreshAt} while Postgres is
 *       wired, so {@code isPrimed()} stays false and health stays DOWN;</li>
 *   <li>the cache is complete-or-ignored: rows go into a new generation and the
 *       marker flips last; a reader takes only a generation whose row count and
 *       content hash match its marker;</li>
 *   <li>the mirror is deferred, so a driver that throws while the mirror is being
 *       assembled is never taken for a failed Postgres load.</li>
 * </ul>
 */
class RouteAccessCassandraFallbackTest {

    private static final String GATEWAY = "hugmesh-be-gateway";
    /** BE seed: /api/admin/** -> ROLE_ADMIN, so a ROLE_USER is DENIED here. */
    private static final String SEED_ADMIN_PATH = "/api/admin/users";
    /** BE seed: /bff/superadmin/** -> ROLE_SUPERADMIN (declared mfa_required). */
    private static final String SEED_SUPERADMIN_PATH = "/bff/superadmin/tailnet";
    private static final List<String> USER = List.of("ROLE_USER");
    private static final List<String> IDS = List.of("u-1");

    // ── fixtures ────────────────────────────────────────────────────────────────

    private static GatewayRouteAccessRepository postgres(AtomicReference<Flux<GatewayRouteAccessRow>> next) {
        GatewayRouteAccessRepository repo = mock(GatewayRouteAccessRepository.class);
        when(repo.findByGateway(GATEWAY)).thenAnswer(inv -> next.get());
        return repo;
    }

    private static GatewayRouteAccessRow pgRow(String pattern, String role) {
        return new GatewayRouteAccessRow(UUID.nameUUIDFromBytes((pattern + role).getBytes()),
                GATEWAY, pattern, role, null, true, null, false, null);
    }

    /** A Postgres table that governs the seed's admin pattern and adds /pg-only/**. */
    private static List<GatewayRouteAccessRow> pgTable() {
        return List.of(
                pgRow("/api/admin/**", "ROLE_ADMIN"),
                pgRow("/api/**", "ROLE_USER"),
                pgRow("/pg-only/**", "ROLE_ADMIN"));
    }

    private static Rule rule(String pattern, String role) {
        return new Rule("c-" + pattern + "-" + role, GATEWAY, pattern, role, null, true, null, false);
    }

    /** The refuter's S7/S8 cache: one complete-looking row that governs nothing the seed does. */
    private static List<Rule> oneRowCache() {
        return List.of(rule("/login/**", "PUBLIC"));
    }

    private static RuntimeException authRejected() {
        return new RuntimeException("password authentication failed for user \"be_gateway\"");
    }

    static Stream<Arguments> breakers() {
        return Stream.of(
                Arguments.of("no breaker", null),
                Arguments.of("closed breaker (error -> fallback)",
                        RouteAccessEmptyLoadFloorTest.passThroughBreakerFactory()));
    }

    private static GatewayRouteAccessService service(GatewayRouteAccessRepository repo,
                                                     FakeRouteAccessCassandra cs,
                                                     ReactiveCircuitBreakerFactory<?, ?> breakers) {
        return new GatewayRouteAccessService(cs == null ? null : cs.template(), repo, GATEWAY, true, false, breakers);
    }

    private static void coldStart(GatewayRouteAccessService svc) {
        svc.init();
        svc.refreshNow().block();
    }

    private static Health health(GatewayRouteAccessService svc) {
        return new RouteAccessHealthIndicator(svc).health();
    }

    // ── S7: partial cache at COLD START ─────────────────────────────────────────

    @ParameterizedTest(name = "{0}")
    @MethodSource("breakers")
    void s7_partialCacheAtColdStart_seedStillDecidesEveryPatternTheCacheLacks(
            String label, ReactiveCircuitBreakerFactory<?, ?> b) {
        var pg = new AtomicReference<Flux<GatewayRouteAccessRow>>(Flux.error(authRejected()));
        var cs = new FakeRouteAccessCassandra();
        cs.putCompleteGeneration(GATEWAY, "g-partial", oneRowCache());
        GatewayRouteAccessService svc = service(postgres(pg), cs, b);

        coldStart(svc);

        assertThat(svc.source()).isEqualTo("cassandra");
        assertThat(svc.decide(SEED_ADMIN_PATH, "default", IDS, USER))
                .as("the seed's /api/admin/** row still governs (was NO_RULE -> forwarded in S7)")
                .isEqualTo(Decision.DENY);
        assertThat(svc.decide(SEED_SUPERADMIN_PATH, "default", IDS, USER)).isEqualTo(Decision.DENY);
        assertThat(svc.decide("/login/x", "default", IDS, List.of()))
                .as("the cache row is enforced too")
                .isEqualTo(Decision.ALLOW);
        assertThat(svc.isMfaRequiredSurface(SEED_SUPERADMIN_PATH, "default"))
                .as("the seed's declared mfa_required row keeps its step-up on the fallback")
                .isTrue();
        assertThat(svc.ruleCount()).isEqualTo(1 + CanonicalSeed.forGateway(GATEWAY).size());
        assertThat(svc.isPrimed()).as("a Cassandra fallback never primes the MFA floor").isFalse();
        assertThat(svc.lastRefreshAt()).isEqualTo(Instant.EPOCH);
        Health h = health(svc);
        assertThat(h.getStatus()).isEqualTo(Status.DOWN);
        assertThat(h.getDetails()).containsEntry("enforcing", "cassandra")
                .containsEntry("authoritativeSource", "postgres");
        assertThat((String) h.getDetails().get("reason"))
                .contains("password authentication failed")
                .contains("seed-floor rules for patterns the cache lacks");
    }

    // ── S8: partial cache AFTER a good Postgres snapshot ────────────────────────

    @ParameterizedTest(name = "{0}")
    @MethodSource("breakers")
    void s8_partialCacheAfterGoodLoad_seedStillDecides_andPrimingDoesNotMove(
            String label, ReactiveCircuitBreakerFactory<?, ?> b) {
        var pg = new AtomicReference<>(Flux.fromIterable(pgTable()));
        var cs = new FakeRouteAccessCassandra();
        GatewayRouteAccessService svc = service(postgres(pg), cs, b);
        coldStart(svc);
        assertThat(svc.source()).isEqualTo("postgres");
        Instant primedAt = svc.lastRefreshAt();

        // Another replica later left a complete 1-row generation marked (the refuter's
        // hand-made state); then Postgres goes away.
        cs.clear();
        cs.putCompleteGeneration(GATEWAY, "g-partial", oneRowCache());
        pg.set(Flux.error(authRejected()));
        svc.refreshNow().block();

        assertThat(svc.source()).isEqualTo("cassandra");
        assertThat(svc.decide(SEED_ADMIN_PATH, "default", IDS, USER))
                .as("S8: was forwarded on the 1-row cache")
                .isEqualTo(Decision.DENY);
        assertThat(svc.decide(SEED_SUPERADMIN_PATH, "default", IDS, USER)).isEqualTo(Decision.DENY);
        assertThat(svc.lastRefreshAt())
                .as("the Cassandra install does not move lastRefreshAt")
                .isEqualTo(primedAt);
        assertThat(health(svc).getStatus()).isEqualTo(Status.DOWN);
        assertThat(svc.degradedReason()).contains("last-known-good cassandra snapshot");

        // Recovery: Postgres answers again, the snapshot is authoritative and UP.
        pg.set(Flux.fromIterable(pgTable()));
        svc.refreshNow().block();
        assertThat(svc.source()).isEqualTo("postgres");
        assertThat(svc.lastRefreshAt()).isAfter(primedAt);
        assertThat(svc.seedFloorRules()).isZero();
        assertThat(health(svc).getStatus()).isEqualTo(Status.UP);
    }

    @Test
    void cassandraFallback_neverPrimes_untilPostgresLoads() {
        var pg = new AtomicReference<Flux<GatewayRouteAccessRow>>(Flux.error(authRejected()));
        var cs = new FakeRouteAccessCassandra();
        cs.putCompleteGeneration(GATEWAY, "g1",
                List.of(rule("/api/admin/**", "ROLE_ADMIN"), rule("/api/**", "ROLE_USER")));
        GatewayRouteAccessService svc = service(postgres(pg), cs, null);
        coldStart(svc);
        svc.refreshNow().block();
        svc.refreshNow().block();
        assertThat(svc.source()).isEqualTo("cassandra");
        assertThat(svc.isPrimed()).as("tick after tick on the cache: still unprimed").isFalse();

        pg.set(Flux.fromIterable(pgTable()));
        svc.refreshNow().block();
        assertThat(svc.isPrimed()).as("the first Postgres load primes").isTrue();
    }

    /** With NO Postgres wired the cache IS the authority: a complete generation is
     *  still unioned with the seed, and it primes and reports UP. */
    @Test
    void cassandraOnlyWiring_completeGeneration_unionsWithSeed_primes_andIsUp() {
        var cs = new FakeRouteAccessCassandra();
        cs.putCompleteGeneration(GATEWAY, "g1", oneRowCache());
        GatewayRouteAccessService svc = service(null, cs, null);
        coldStart(svc);

        assertThat(svc.authoritativeSource()).isEqualTo("cassandra");
        assertThat(svc.source()).isEqualTo("cassandra");
        assertThat(svc.decide(SEED_ADMIN_PATH, "default", IDS, USER)).isEqualTo(Decision.DENY);
        assertThat(svc.isPrimed()).isTrue();
        assertThat(health(svc).getStatus()).isEqualTo(Status.UP);
    }

    // ── union semantics ─────────────────────────────────────────────────────────

    @Test
    void union_cachePatternReplacesTheSeedRowsForThatPattern_uncoveredSeedPatternsAreAdded() {
        Rule seedAdmin = new Rule("s1", GATEWAY, "/api/admin/**", "ROLE_ADMIN", null, true, null, false);
        Rule seedMod = new Rule("s2", GATEWAY, "/api/admin/**", "ROLE_MOD", null, true, null, false);
        Rule seedDeny = new Rule("s3", GATEWAY, "/internal/**", "ROLE_USER", null, false, null, false);
        Rule seedApi = new Rule("s4", GATEWAY, "/api/**", "ROLE_USER", null, true, null, false);
        Rule cacheAdmin = new Rule("c1", GATEWAY, "/api/admin/**", "ROLE_SUPERADMIN", null, true, null, false);
        Rule cacheOther = new Rule("c2", GATEWAY, "/other/**", "ROLE_USER", null, true, null, false);

        List<Rule> merged = GatewayRouteAccessService.withSeedFloor(
                List.of(cacheAdmin, cacheOther), List.of(seedAdmin, seedMod, seedDeny, seedApi));

        assertThat(merged)
                .as("cache rows first, then every seed rule whose pattern the cache lacks (deny rows too); "
                  + "the cache's /api/admin/** rows replace BOTH seed rows at that pattern")
                .containsExactly(cacheAdmin, cacheOther, seedDeny, seedApi);
    }

    @Test
    void union_isTheEnforcedSnapshot_cacheDecidesItsOwnPatterns_seedDecidesTheRest() {
        var pg = new AtomicReference<Flux<GatewayRouteAccessRow>>(Flux.error(authRejected()));
        var cs = new FakeRouteAccessCassandra();
        // The cache NARROWS /api/** (an admin edit that reached the cache) and
        // carries no /api/admin/** row at all.
        cs.putCompleteGeneration(GATEWAY, "g1", List.of(rule("/api/**", "ROLE_MOD")));
        GatewayRouteAccessService svc = service(postgres(pg), cs, null);
        coldStart(svc);

        assertThat(svc.decide("/api/things", "default", IDS, USER))
                .as("the cache's own /api/** row decides /api/**: the seed's ROLE_USER grant is not added")
                .isEqualTo(Decision.DENY);
        assertThat(svc.decide("/api/things", "default", IDS, List.of("ROLE_MOD"))).isEqualTo(Decision.ALLOW);
        assertThat(svc.decide(SEED_ADMIN_PATH, "default", IDS, List.of("ROLE_MOD")))
                .as("the seed's longer /api/admin/** row still decides the admin subtree")
                .isEqualTo(Decision.DENY);
    }

    // ── complete-or-ignored cache ───────────────────────────────────────────────

    @Test
    void mirror_writesRowsBeforeTheMarker_andSkipsUnchangedContent() {
        var pg = new AtomicReference<>(Flux.fromIterable(pgTable()));
        var cs = new FakeRouteAccessCassandra();
        GatewayRouteAccessService svc = service(postgres(pg), cs, null);
        coldStart(svc);
        svc.refreshNow().block();

        String gen = cs.currentGeneration(GATEWAY);
        assertThat(gen).isNotNull();
        assertThat(cs.rowsIn(GATEWAY, gen)).isEqualTo(3);
        assertThat(cs.markerWrites.get()).as("three ticks, one content: one flip").isEqualTo(1);
        assertThat(cs.rowInserts.get()).isEqualTo(3);
    }

    @Test
    void interruptedMirror_leavesThePreviousCompleteGenerationInForce() {
        var pg = new AtomicReference<>(Flux.fromIterable(pgTable()));
        var cs = new FakeRouteAccessCassandra();
        GatewayRouteAccessService svc = service(postgres(pg), cs, null);
        coldStart(svc);
        String complete = cs.currentGeneration(GATEWAY);
        assertThat(cs.rowsIn(GATEWAY, complete)).isEqualTo(3);

        // The admin adds a row; the mirror of the new 4-row table dies after its
        // first row (a timeout, a pod kill).
        List<GatewayRouteAccessRow> grown = new ArrayList<>(pgTable());
        grown.add(pgRow("/pg-new/**", "ROLE_ADMIN"));
        pg.set(Flux.fromIterable(grown));
        cs.failGenerationInsertsAfter = cs.rowInserts.get() + 1;
        svc.refreshNow().block();

        assertThat(svc.source()).as("Postgres itself was fine").isEqualTo("postgres");
        assertThat(cs.currentGeneration(GATEWAY))
                .as("the marker still names the previous complete generation")
                .isEqualTo(complete);
        assertThat(cs.generationIds(GATEWAY))
                .as("the abandoned partial generation is deleted best-effort")
                .containsExactly(complete);

        // Postgres goes away: the fallback enforces the previous COMPLETE generation.
        pg.set(Flux.error(authRejected()));
        svc.refreshNow().block();
        assertThat(svc.source()).isEqualTo("cassandra");
        assertThat(svc.decide("/pg-only/x", "default", IDS, USER))
                .as("a row of the previous complete generation is enforced")
                .isEqualTo(Decision.DENY);
        assertThat(svc.decide("/api/things", "default", IDS, USER)).isEqualTo(Decision.ALLOW);
        assertThat(svc.decide("/pg-new/x", "default", IDS, USER))
                .as("nothing of the interrupted generation is read")
                .isEqualTo(Decision.NO_RULE);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("breakers")
    void generationShorterThanItsMarker_isIgnored_atColdStart_andAfterAGoodLoad(
            String label, ReactiveCircuitBreakerFactory<?, ?> b) {
        var pg = new AtomicReference<Flux<GatewayRouteAccessRow>>(Flux.error(authRejected()));
        var cs = new FakeRouteAccessCassandra();
        List<Rule> whole = List.of(rule("/login/**", "PUBLIC"), rule("/api/**", "ROLE_USER"),
                rule("/x/**", "ROLE_ADMIN"));
        // The marker names 3 rows; only the first is visible (a replica that has the
        // marker but not yet the rows, or a generation deleted under the read).
        cs.putRows(GATEWAY, "g-short", whole.subList(0, 1));
        cs.mark(GATEWAY, "g-short", 3, GatewayRouteAccessService.contentHash(whole));
        GatewayRouteAccessService svc = service(postgres(pg), cs, b);

        coldStart(svc);
        assertThat(svc.source()).as("cold start keeps the seed floor").isEqualTo("seed");
        assertThat(svc.decide("/login/x", "default", IDS, List.of())).isEqualTo(Decision.NO_RULE);
        assertThat(svc.degradedReason()).contains("seed floor");

        pg.set(Flux.fromIterable(pgTable()));
        svc.refreshNow().block();
        cs.clear();
        cs.putRows(GATEWAY, "g-short", whole.subList(0, 1));
        cs.mark(GATEWAY, "g-short", 3, GatewayRouteAccessService.contentHash(whole));
        pg.set(Flux.error(authRejected()));
        svc.refreshNow().block();
        assertThat(svc.source()).as("after a good load, that load is kept").isEqualTo("postgres");
        assertThat(svc.decide("/pg-only/x", "default", IDS, USER)).isEqualTo(Decision.DENY);
        assertThat(health(svc).getStatus()).isEqualTo(Status.DOWN);
    }

    @Test
    void generationWithTheRightCountButDifferentContent_isIgnored() {
        var pg = new AtomicReference<Flux<GatewayRouteAccessRow>>(Flux.error(authRejected()));
        var cs = new FakeRouteAccessCassandra();
        List<Rule> written = List.of(rule("/login/**", "PUBLIC"));
        cs.putRows(GATEWAY, "g1", written);
        cs.mark(GATEWAY, "g1", 1, GatewayRouteAccessService.contentHash(
                List.of(rule("/login/**", "ROLE_ADMIN"))));
        GatewayRouteAccessService svc = service(postgres(pg), cs, null);
        coldStart(svc);
        assertThat(svc.source()).isEqualTo("seed");
        assertThat(svc.degradedReason()).contains("seed floor");
    }

    @Test
    void mirror_deletesOnlyTheGenerationThisPodMarkedBefore_neverAnotherPods() {
        var pg = new AtomicReference<>(Flux.fromIterable(pgTable()));
        var cs = new FakeRouteAccessCassandra();
        // Another replica's generation is current when this pod starts.
        cs.putCompleteGeneration(GATEWAY, "other-pod", List.of(rule("/old/**", "ROLE_ADMIN")));
        GatewayRouteAccessService svc = service(postgres(pg), cs, null);
        coldStart(svc);
        String mine1 = cs.currentGeneration(GATEWAY);
        assertThat(mine1).isNotEqualTo("other-pod");
        assertThat(cs.generationIds(GATEWAY))
                .as("this pod never marked other-pod, so it never deletes it")
                .containsExactlyInAnyOrder("other-pod", mine1);

        List<GatewayRouteAccessRow> grown = new ArrayList<>(pgTable());
        grown.add(pgRow("/pg-new/**", "ROLE_ADMIN"));
        pg.set(Flux.fromIterable(grown));
        svc.refreshNow().block();
        String mine2 = cs.currentGeneration(GATEWAY);
        assertThat(mine2).isNotEqualTo(mine1);
        assertThat(cs.generationIds(GATEWAY))
                .as("after flipping to its new generation the pod deletes its OWN previous one only")
                .containsExactlyInAnyOrder("other-pod", mine2);
    }

    // ── the mirror is DEFERRED (round-1 mutation M9 survived every test) ────────

    @Test
    void mirrorIsDeferred_aDriverThrowingWhileTheMirrorIsBuilt_isNotAFailedPostgresLoad() {
        var pg = new AtomicReference<>(Flux.fromIterable(pgTable()));
        var cs = new FakeRouteAccessCassandra();
        // A distinguishable, complete cache: if the tick ever falls back to it,
        // /cass-only/** becomes enforced and the source becomes "cassandra".
        cs.putCompleteGeneration(GATEWAY, "g-cache", List.of(rule("/cass-only/**", "ROLE_ADMIN")));
        cs.throwSynchronouslyOnNextQueries.set(1);   // the mirror's first statement throws
        GatewayRouteAccessService svc = service(postgres(pg), cs, null);

        svc.refreshNow().block();   // one tick, no init(): the throw hits the mirror

        assertThat(svc.source())
                .as("a mirror-side throw must not send the tick to the Cassandra fallback")
                .isEqualTo("postgres");
        assertThat(svc.decide("/cass-only/x", "default", IDS, USER)).isEqualTo(Decision.NO_RULE);
        assertThat(svc.degradedReason()).isNull();
        assertThat(svc.isPrimed()).isTrue();
        assertThat(cs.markerReads.get())
                .as("the only marker read attempted was the mirror's own (which threw); no fallback read")
                .isZero();
        assertThat(cs.generationReads.get()).isZero();
    }
}
