package net.hugmesh.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.gateway.config.GatewayProperties;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Smoke test — context must load without external services (no
 * Cassandra, no Casdoor reachable). The Cassandra autoconfigurations are
 * excluded so no CqlSession is opened; the cache services take their
 * {@code ReactiveCassandraTemplate} as a {@code @Nullable} constructor arg
 * and no-op (cql=null) when the bean is absent.
 *
 * <p>Wire-level Cassandra + JWT coverage lives in integration tests
 * that provision a Testcontainers cluster — out of scope for the
 * per-PR unit gate.
 */
@SpringBootTest
@TestPropertySource(properties = {
        "app.revocation.enabled=false",
        "app.url-registry.enabled=false",
        "app.resource-access.enabled=false",
        "app.route-access.enabled=false",
        // A non-empty placeholder JWKS URI lets the reactive JwtDecoder bean
        // build WITHOUT a network call — it only fetches the JWKS lazily on the
        // first token validation, which this smoke test never performs. An
        // empty value throws "jwkSetUri cannot be empty"; an issuer-uri would
        // trigger eager OIDC discovery against an unreachable Casdoor.
        "spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://localhost/jwks",
        // Spring Boot 4.x relocated the Cassandra autoconfigurations into
        // dedicated modules (org.springframework.boot.cassandra.autoconfigure
        // and org.springframework.boot.data.cassandra.autoconfigure). The old
        // 3.x FQCNs below no longer match anything, so without the corrected
        // names the smoke test opens a real CqlSession to 127.0.0.1:9042 and
        // fails. With Cassandra excluded there is no ReactiveCassandraTemplate
        // bean — hence the @Nullable constructor args on the cache services.
        "spring.autoconfigure.exclude=" +
                "org.springframework.boot.cassandra.autoconfigure.CassandraAutoConfiguration," +
                "org.springframework.boot.data.cassandra.autoconfigure.DataCassandraAutoConfiguration," +
                "org.springframework.boot.data.cassandra.autoconfigure.DataCassandraReactiveAutoConfiguration",
})
class HugMeshGatewayApplicationTests {

    @Autowired
    GatewayProperties gatewayProperties;

    @Autowired
    net.hugmesh.gateway.filter.GatewayRouteAccessFilter routeAccessFilter;

    @Test
    void contextLoads() {
    }

    /**
     * REGRESSION GUARD (SCG-5 namespace). Spring Cloud Gateway 5.0 (Spring Boot 4)
     * removed the legacy {@code spring.cloud.gateway.*} route prefix in favour of
     * {@code spring.cloud.gateway.server.webflux.*}. The legacy prefix binds NOTHING
     * — silently, with no error — so the statically-configured fallback routes in
     * {@code application.yml} simply vanish after the Boot-4 bump. This asserts the
     * baked {@code api-default} route actually binds via {@link GatewayProperties}, so
     * a future revert to the stale prefix fails the build instead of failing OPEN at
     * runtime (request 404s past the route-access gate with no downstream).
     */
    /**
     * SHIPS-DARK GUARD for the {@code X-Domain} producer (issue #4, TODO 2).
     * Every other test builds the filter by hand, so none of them can see the
     * value {@code application.yml} actually ships. This one drives the REAL
     * container-wired bean — {@code app.domain-header.forward} bound from the
     * shipped default, with no property override here — and asserts both halves
     * of the posture at once: a client-supplied {@code X-Domain} is STRIPPED, and
     * nothing is stamped in its place. Flipping the shipped default to
     * {@code true} (in {@code application.yml} or in the {@code @Value} fallback)
     * fails HERE, which is the only place it can be caught, because no downstream
     * consumer of the header exists yet.
     */
    @Test
    void xDomainProducerShipsInert_butTheInboundStripIsLive() {
        var req = org.springframework.mock.http.server.reactive.MockServerHttpRequest
                .get("/api/anything").header("X-Domain", "brandy").build();
        var exchange = org.springframework.mock.web.server.MockServerWebExchange.from(req);
        var seen = new java.util.concurrent.atomic.AtomicReference<
                org.springframework.web.server.ServerWebExchange>();
        routeAccessFilter.filter(exchange, ex -> {
            seen.set(ex);
            return reactor.core.publisher.Mono.empty();
        }).block();
        assertThat(seen.get())
                .as("an anonymous request must still forward")
                .isNotNull();
        assertThat(seen.get().getRequest().getHeaders().get("X-Domain"))
                .as("inbound strip live + outbound stamp dark on the SHIPPED defaults")
                .isNull();
    }

    @Test
    void staticRoutesBindUnderScg5WebfluxNamespace() {
        assertThat(gatewayProperties.getRoutes())
                .as("spring.cloud.gateway.server.webflux.routes must bind the baked api-default route")
                .extracting(r -> r.getId())
                .contains("api-default");
    }
}
