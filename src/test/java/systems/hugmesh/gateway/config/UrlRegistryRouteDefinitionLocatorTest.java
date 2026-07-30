package systems.hugmesh.gateway.config;

import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.FilterDefinition;
import org.springframework.cloud.gateway.handler.predicate.PredicateDefinition;
import org.springframework.cloud.gateway.route.RouteDefinition;
import reactor.test.StepVerifier;
import systems.hugmesh.gateway.cache.UrlRegistryService;
import systems.hugmesh.gateway.cache.UrlRegistryService.Route;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Contract for the DB-driven route-definition locator: each {@code url_registry}
 * row primed into {@link UrlRegistryService} must surface as a Spring Cloud Gateway
 * {@link RouteDefinition} with a sanitized id, the downstream uri, and a
 * {@code Path=<prefix>**} predicate. Built with a null Cassandra template + null
 * event publisher and primed via the test seam, so no live cluster / context is
 * needed.
 */
class UrlRegistryRouteDefinitionLocatorTest {

    private UrlRegistryRouteDefinitionLocator locatorWith(Route... routes) {
        UrlRegistryService registry = new UrlRegistryService(null, true, true, null);
        Map<String, Route> map = new LinkedHashMap<>();
        for (Route r : routes) {
            map.put(r.pathPrefix(), r);
        }
        registry.primeForTest(map);
        return new UrlRegistryRouteDefinitionLocator(registry);
    }

    /** Default test route: no strip_prefix (null) — the common case (an app route
     *  that forwards as-is and emits NO StripPrefix filter). */
    private static Route route(String prefix, String uri) {
        return new Route(prefix, uri, "svc-" + prefix, "", null);
    }

    @Test
    void registryRow_becomesPathRouteDefinition() {
        var locator = locatorWith(route("/api/games/", "http://games-api:8080"));

        StepVerifier.create(locator.getRouteDefinitions())
            .assertNext(def -> {
                assertThat(def.getId()).isEqualTo("url-registry:api_games");
                assertThat(def.getUri()).hasToString("http://games-api:8080");
                assertThat(def.getPredicates()).hasSize(1);
                PredicateDefinition p = def.getPredicates().get(0);
                assertThat(p.getName()).isEqualTo("Path");
                // shorthand parsing puts the pattern in the positional _genkey_0
                assertThat(p.getArgs().values()).containsExactly("/api/games/**");
                // No strip_prefix on this row => NO StripPrefix filter (the route
                // forwards the full path unchanged).
                assertThat(def.getFilters()).isEmpty();
            })
            .verifyComplete();
    }

    /** A row with strip_prefix > 0 emits a StripPrefix=N FilterDefinition — the
     *  parsed shorthand of a YAML {@code - StripPrefix=N} entry. This is how the
     *  seeded /be/** route reproduces the static be-default route's StripPrefix=1
     *  so /be/api -> /api at the be-gateway. */
    @Test
    void rowWithStripPrefix_emitsStripPrefixFilter() {
        var locator = locatorWith(new Route("/be/", "http://be-gateway:8080",
                "hugmesh-be-gateway", "", 1));

        StepVerifier.create(locator.getRouteDefinitions())
            .assertNext(def -> {
                assertThat(def.getId()).isEqualTo("url-registry:be");
                assertThat(def.getPredicates()).hasSize(1);
                assertThat(def.getFilters()).hasSize(1);
                FilterDefinition f = def.getFilters().get(0);
                assertThat(f.getName()).isEqualTo("StripPrefix");
                // shorthand parsing puts the count in the positional _genkey_0
                assertThat(f.getArgs().values()).containsExactly("1");
            })
            .verifyComplete();
    }

    /** Regression guard: strip_prefix of 0 or null emits NO filter (admin/app
     *  routes that must NOT strip — e.g. an internal control-plane route whose
     *  downstream expects the full path). Both the explicit 0 and the null map to
     *  "no strip" so neither leaks a StripPrefix=0 (a 0-segment strip is a no-op
     *  anyway, but emitting the filter would be misleading and untested ground). */
    @Test
    void rowWithZeroOrNullStripPrefix_emitsNoFilter() {
        var locator = locatorWith(
                new Route("/admin/", "http://admin-api:8080", "admin", "ROLE_ADMIN", 0),
                new Route("/app/", "http://app-api:8080", "app", "", null));

        List<RouteDefinition> defs = locator.getRouteDefinitions().collectList().block();
        assertThat(defs).hasSize(2);
        assertThat(defs).allSatisfy(def -> assertThat(def.getFilters()).isEmpty());
    }

    @Test
    void prefixAlreadyEndingInGlob_isNotDoubleStarred() {
        assertThat(UrlRegistryRouteDefinitionLocator.toPathPattern("/api/x/**")).isEqualTo("/api/x/**");
        assertThat(UrlRegistryRouteDefinitionLocator.toPathPattern("/api/x/*")).isEqualTo("/api/x/*");
        assertThat(UrlRegistryRouteDefinitionLocator.toPathPattern("/api/x/")).isEqualTo("/api/x/**");
    }

    @Test
    void sanitizeId_stripsSlashesAndPunctuation() {
        assertThat(UrlRegistryRouteDefinitionLocator.sanitizeId("/api/games/")).isEqualTo("api_games");
        assertThat(UrlRegistryRouteDefinitionLocator.sanitizeId("/")).isEqualTo("root");
        assertThat(UrlRegistryRouteDefinitionLocator.sanitizeId("/v2.0/orders")).isEqualTo("v2_0_orders");
    }

    @Test
    void blankOrIncompleteRows_areSkipped() {
        var locator = locatorWith(
            route("/api/ok/", "http://ok:8080"),
            new Route("/api/no-uri/", "", "svc", "", null),
            new Route("", "http://orphan:8080", "svc", "", null),
            new Route(null, "http://nullprefix:8080", "svc", "", null));

        List<RouteDefinition> defs = locator.getRouteDefinitions().collectList().block();
        assertThat(defs).hasSize(1);
        assertThat(defs.get(0).getId()).isEqualTo("url-registry:api_ok");
    }

    @Test
    void emptyRegistry_yieldsNoDefinitions() {
        var locator = locatorWith();
        StepVerifier.create(locator.getRouteDefinitions()).verifyComplete();
    }
}
