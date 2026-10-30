package net.hugmesh.gateway.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.env.MockEnvironment;
import reactor.test.StepVerifier;

import net.hugmesh.gateway.cache.GatewayRouteAccessRepository;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * hugmesh-gateway#61: a SET-but-invalid {@code ROUTE_ACCESS_R2DBC_URL} used to
 * return {@code null}, which the route-access service reads as "no source of truth
 * configured" and runs Cassandra-only, silently. It must instead be wired as a
 * source of truth that always FAILS, so the service keeps its floor, stays
 * un-primed and reports degraded. A blank/unset URL still means "not configured".
 */
class RouteAccessR2dbcConfigTest {

    private static GatewayRouteAccessRepository build(String url) {
        MockEnvironment env = new MockEnvironment();
        if (url != null) env.setProperty("app.route-access.r2dbc-url", url);
        return new RouteAccessR2dbcConfig().gatewayRouteAccessRepository(env);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "not-a-url",
            "postgres://be_gateway:pw@route-access-db:5432/hugmesh",     // missing the r2dbc: scheme
            "r2dbc:no-such-driver://be_gateway:pw@route-access-db:5432/hugmesh"})
    void invalidUrl_isWiredAsAFailingSourceOfTruth_notAsAbsent(String url) {
        GatewayRouteAccessRepository repo = build(url);

        assertThat(repo).as("an invalid URL must not read as 'no source of truth'").isNotNull();
        StepVerifier.create(repo.findByGateway("hugmesh-be-gateway"))
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("ROUTE_ACCESS_R2DBC_URL is set but invalid")
                        .hasMessageNotContaining("pw@"))
                .verify();
        assertThat(repo.toString()).contains("FailingGatewayRouteAccessRepository");
    }

    @Test
    void blankUrl_meansNotConfigured() {
        assertThat(build("")).isNull();
        assertThat(build("   ")).isNull();
        assertThat(build(null)).isNull();
    }

    @Test
    void validUrl_buildsARealRepository_withoutConnecting() {
        GatewayRouteAccessRepository repo =
                build("r2dbc:postgresql://be_gateway:pw@127.0.0.1:1/hugmesh");
        assertThat(repo).isNotNull();
        assertThat(repo.toString()).doesNotContain("FailingGatewayRouteAccessRepository");
    }
}
