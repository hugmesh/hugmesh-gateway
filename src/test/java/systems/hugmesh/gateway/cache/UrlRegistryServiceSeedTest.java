package systems.hugmesh.gateway.cache;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.cassandra.core.ReactiveCassandraTemplate;
import org.springframework.data.cassandra.core.cql.ReactiveCqlOperations;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.gateway.cache.UrlRegistryService.Route;
import systems.hugmesh.gateway.config.UrlRegistryRouteDefinitionLocator;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Contract for the CanonicalSeed-style STARTUP seed of the {@code url_registry}
 * default route definitions (the {@code /be/** -> be-gateway} cross-namespace
 * scope). Covers: the seed upserts the {@code /be/} row with the right columns;
 * idempotency (two boots = one row, no error); a pre-existing (admin-edited) row
 * is NOT clobbered (the {@code IF NOT EXISTS} LWT is what the SELECT verifies);
 * the toggle disables the seed; and the seeded row surfaces as a working
 * {@link org.springframework.cloud.gateway.route.RouteDefinition} through
 * {@link UrlRegistryRouteDefinitionLocator}.
 *
 * <p>Built with a Mockito {@link ReactiveCqlOperations} so no live Cassandra is
 * needed — mirrors {@code GatewayCassandraSchemaAutoConfigurationTest}'s
 * default-answer CQL mock idiom, but here we stub the {@code execute(..., args)}
 * overload to return the LWT {@code [applied]} flag so seed-if-absent vs.
 * already-present can be distinguished.
 */
class UrlRegistryServiceSeedTest {

    /** Build a service over a Cassandra template whose CQL ops are the supplied mock,
     *  with the seed toggle on/off. The @PostConstruct is NOT run (no Spring context)
     *  — the tests drive {@code seedDefaults()} directly. */
    private static UrlRegistryService serviceWith(ReactiveCqlOperations cql, boolean seedDefaults) {
        ReactiveCassandraTemplate template = mock(ReactiveCassandraTemplate.class);
        when(template.getReactiveCqlOperations()).thenReturn(cql);
        return new UrlRegistryService(template, true, seedDefaults, null);
    }

    /** A default route is mapped to the canonical be-gateway downstream. */
    @Test
    void seed_upsertsBeRoute_withCorrectColumns() {
        ReactiveCqlOperations cql = mock(ReactiveCqlOperations.class);
        // LWT applied = true: the row did not exist, the seed lands.
        when(cql.execute(anyString(), any(Object[].class))).thenReturn(Mono.just(true));
        var svc = serviceWith(cql, true);

        StepVerifier.create(svc.seedDefaults()).verifyComplete();

        ArgumentCaptor<String> cqlCap = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Object[]> argsCap = ArgumentCaptor.forClass(Object[].class);
        verify(cql).execute(cqlCap.capture(), argsCap.capture());

        // INSERT ... IF NOT EXISTS — the seed-if-absent guard (a plain INSERT would
        // clobber an admin's later edit on the next boot).
        assertThat(cqlCap.getValue())
                .contains("INSERT INTO url_registry")
                .contains("path_prefix")
                .contains("downstream_uri")
                .contains("service_name")
                .contains("required_role")
                .contains("strip_prefix")
                .contains("IF NOT EXISTS");

        // Column VALUES round-trip the baked-in /be/ -> be-gateway default.
        Object[] args = argsCap.getValue();
        assertThat(args[0]).isEqualTo("/be/");                                  // path_prefix (PK)
        assertThat(args[1]).isEqualTo(UrlRegistryDefaultRoutes.BE_GATEWAY_URI); // downstream_uri
        assertThat(args[2]).isEqualTo("hugmesh-be-gateway");                 // service_name
        assertThat(args[4]).isEqualTo("");                                      // required_role (be-tier access is the CanonicalSeed floor)
        assertThat(args[5]).isEqualTo(1);                                       // strip_prefix=1 (matches the static be-default StripPrefix=1)
    }

    /** Running the seed twice is one logical row (each boot fires the same
     *  idempotent IF NOT EXISTS) and never errors — a fresh boot then a re-boot. */
    @Test
    void seed_isIdempotent_acrossTwoBoots() {
        AtomicInteger applied = new AtomicInteger();
        ReactiveCqlOperations cql = mock(ReactiveCqlOperations.class);
        // First boot: applied=true (row created). Second boot: applied=false (row
        // already present) — the IF NOT EXISTS no-ops, no error, no duplicate.
        when(cql.execute(anyString(), any(Object[].class)))
                .thenAnswer(inv -> Mono.just(applied.getAndIncrement() == 0));
        var svc = serviceWith(cql, true);

        StepVerifier.create(svc.seedDefaults()).verifyComplete();   // boot 1
        StepVerifier.create(svc.seedDefaults()).verifyComplete();   // boot 2 — no error

        // Exactly one default route, so exactly one INSERT per boot (two total),
        // both the SAME idempotent IF NOT EXISTS statement.
        verify(cql, times(2)).execute(anyString(), any(Object[].class));
    }

    /** A pre-existing (admin-edited) row is NOT clobbered: the IF NOT EXISTS LWT
     *  returns applied=false and the seed treats it as a no-op skip (no error, no
     *  overwrite). This is what protects an admin's /bff/admin/routes re-point from
     *  being reverted on the next pod boot. */
    @Test
    void seed_doesNotClobber_preExistingAdminEditedRow() {
        ReactiveCqlOperations cql = mock(ReactiveCqlOperations.class);
        // applied=false => the row already exists (admin edited it); LWT did NOT write.
        when(cql.execute(anyString(), any(Object[].class))).thenReturn(Mono.just(false));
        var svc = serviceWith(cql, true);

        StepVerifier.create(svc.seedDefaults()).verifyComplete();

        // It still ISSUES the guarded INSERT (the LWT is how "absent?" is decided
        // server-side) but the statement carries IF NOT EXISTS so a present row is
        // left untouched — never a bare INSERT that would overwrite.
        verify(cql).execute(org.mockito.ArgumentMatchers.contains("IF NOT EXISTS"), any(Object[].class));
    }

    /** A datastore error during the seed is swallowed — boot proceeds (the static
     *  YAML route is the working floor; a half-seeded registry must not crash the pod). */
    @Test
    void seed_swallowsDatastoreError() {
        ReactiveCqlOperations cql = mock(ReactiveCqlOperations.class);
        when(cql.execute(anyString(), any(Object[].class)))
                .thenReturn(Mono.error(new RuntimeException("cassandra down")));
        var svc = serviceWith(cql, true);

        StepVerifier.create(svc.seedDefaults()).verifyComplete();
    }

    /** The toggle (app.url-registry.seed-defaults.enabled=false) skips the seed
     *  entirely — no DB write at all. */
    @Test
    void seed_disabled_writesNothing() {
        ReactiveCqlOperations cql = mock(ReactiveCqlOperations.class);
        var svc = serviceWith(cql, false);

        StepVerifier.create(svc.seedDefaults()).verifyComplete();

        org.mockito.Mockito.verifyNoInteractions(cql);
    }

    /** The seeded /be/ row, once in the registry snapshot, surfaces as a working
     *  Spring Cloud Gateway RouteDefinition: id url-registry:be, the be-gateway uri,
     *  a Path=/be/** predicate, AND a StripPrefix=1 filter — proving the seed maps
     *  to a route that resolves /be/** to the backend gateway and strips /be exactly
     *  like the static be-default route (so /be/api -> /api at the be-gateway). */
    @Test
    void seededRoute_buildsWorkingRouteDefinition() {
        Route be = UrlRegistryDefaultRoutes.defaults().get(0);
        UrlRegistryService registry = new UrlRegistryService(null, true, true, null);
        registry.primeForTest(java.util.Map.of(be.pathPrefix(), be));
        var locator = new UrlRegistryRouteDefinitionLocator(registry);

        var defs = locator.getRouteDefinitions().collectList().block();
        assertThat(defs).hasSize(1);
        var def = defs.get(0);
        assertThat(def.getId()).isEqualTo("url-registry:be");
        assertThat(def.getUri()).hasToString(UrlRegistryDefaultRoutes.BE_GATEWAY_URI);
        assertThat(def.getPredicates()).hasSize(1);
        var p = def.getPredicates().get(0);
        assertThat(p.getName()).isEqualTo("Path");
        assertThat(p.getArgs().values()).containsExactly("/be/**");
        // StripPrefix=1 filter — the DB route now strips /be faithfully (closing the
        // regression where the DB route emitted no filter and could win the /be/**
        // ordering over the static StripPrefix=1 route, forwarding /be/api unstripped).
        assertThat(def.getFilters()).hasSize(1);
        var f = def.getFilters().get(0);
        assertThat(f.getName()).isEqualTo("StripPrefix");
        assertThat(f.getArgs().values()).containsExactly("1");
    }

    /** Defaults sanity: the baked-in seed contains exactly the /be/ cross-namespace
     *  scope mapped to the canonical be-gateway downstream, carrying strip_prefix=1
     *  (so the DB route strips /be like the static be-default route). */
    @Test
    void defaults_containBeCrossNamespaceScope() {
        List<Route> defaults = UrlRegistryDefaultRoutes.defaults();
        assertThat(defaults).hasSize(1);
        Route be = defaults.get(0);
        assertThat(be.pathPrefix()).isEqualTo("/be/");
        assertThat(be.downstreamUri()).isEqualTo(UrlRegistryDefaultRoutes.BE_GATEWAY_URI);
        assertThat(be.serviceName()).isEqualTo("hugmesh-be-gateway");
        assertThat(be.stripPrefix()).isEqualTo(1);
    }
}
