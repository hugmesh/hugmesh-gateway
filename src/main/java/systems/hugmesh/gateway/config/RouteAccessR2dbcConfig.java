package systems.hugmesh.gateway.config;

import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.data.r2dbc.repository.support.R2dbcRepositoryFactory;
import org.springframework.lang.Nullable;
import systems.hugmesh.gateway.cache.GatewayRouteAccessRepository;

/**
 * Wires the gateway's connection to the {@code gateway_route_access}
 * SOURCE OF TRUTH in Postgres, reactively (R2DBC), from a single env
 * var {@code ROUTE_ACCESS_R2DBC_URL}.
 *
 * <p>Why a dedicated {@link ConnectionFactory} instead of the
 * {@code spring.r2dbc.*} auto-config? The gateway image is mostly a
 * Cassandra + JWT proxy; pulling Postgres into the primary
 * {@code spring.r2dbc} namespace would make the auto-configured
 * connection pool mandatory for every gateway pod and fail fast on boot
 * when (in dev / a Cassandra-only deployment) no Postgres is reachable.
 * Instead this factory is built ONLY when the route-access URL is set
 * ({@code app.route-access.r2dbc-url}, env {@code ROUTE_ACCESS_R2DBC_URL}),
 * and {@link systems.hugmesh.gateway.cache.GatewayRouteAccessService}
 * treats a missing client as "fall back to the Cassandra read-cache".
 *
 * <p>The URL is an R2DBC URL, e.g.
 * {@code r2dbc:postgresql://postgres.hugmesh-backend.svc.cluster.local:5432/hugmesh}.
 * Credentials are appended as query params or carried in the URL by the
 * deployment (the admin-api already owns DDL + writes; the gateway only
 * SELECTs its own gateway's rows).
 */
@Configuration
public class RouteAccessR2dbcConfig {

    private static final Logger log = LoggerFactory.getLogger(RouteAccessR2dbcConfig.class);

    /**
     * The reactive route-access repository over the {@code gateway_route_access}
     * SOURCE OF TRUTH in Postgres, or {@code null} when
     * {@code ROUTE_ACCESS_R2DBC_URL} is unset / blank / malformed — in which case
     * {@link systems.hugmesh.gateway.cache.GatewayRouteAccessService} runs
     * Cassandra-cache-only. Guarded by {@code @ConditionalOnProperty} so the bean
     * (and the Postgres driver wiring) simply doesn't exist without a URL.
     *
     * <p><b>Why only this one bean (no {@link ConnectionFactory} /
     * {@link R2dbcEntityTemplate} beans published).</b> The dedicated
     * {@code ConnectionFactory} + {@code R2dbcEntityTemplate} are built as LOCALS
     * here and never exposed as beans. Publishing a {@code ConnectionFactory} bean
     * would activate Spring Boot's actuator {@code ConnectionFactoryHealthContributor}
     * auto-config, which then fails to start ({@code 'beans' must not be empty})
     * when — as on a Cassandra-only / dev gateway, and in the {@code @SpringBootTest}
     * slices — the URL resolves blank and the factory is absent. Keeping the
     * repository the ONLY published bean preserves the gateway's deliberate exclusion
     * of the primary {@code spring.r2dbc} auto-config and never trips actuator R2DBC
     * health (matching the former dedicated {@code DatabaseClient}-only wiring).
     *
     * <p>The repository is produced directly via {@link R2dbcRepositoryFactory}
     * (NOT {@code @EnableR2dbcRepositories}, which would bind to the absent primary
     * factory). NOT the {@code spring.r2dbc.*} primary factory — the gateway must
     * not require Postgres on boot.
     */
    @Bean
    @ConditionalOnProperty(name = "app.route-access.r2dbc-url")
    @Nullable
    GatewayRouteAccessRepository gatewayRouteAccessRepository(
            Environment env) {
        String url = env.getProperty("app.route-access.r2dbc-url");
        if (url == null || url.isBlank()) {
            return null;
        }
        final ConnectionFactory cf;
        try {
            cf = ConnectionFactories.get(url.trim());
            log.info("[route-access] Postgres source-of-truth wired ({} masked)", maskHost(url));
        } catch (RuntimeException e) {
            // A malformed URL must NOT take the whole gateway down — the
            // Cassandra read-cache keeps serving the last-known rules.
            log.error("[route-access] invalid ROUTE_ACCESS_R2DBC_URL, falling back to "
                    + "Cassandra cache only: {}", e.getMessage());
            return null;
        }
        R2dbcEntityTemplate template = new R2dbcEntityTemplate(cf);
        return new R2dbcRepositoryFactory(template)
                .getRepository(GatewayRouteAccessRepository.class);
    }

    /** Strip any user:password before logging the URL. */
    private static String maskHost(String url) {
        int at = url.indexOf('@');
        int slashes = url.indexOf("://");
        if (at > 0 && slashes > 0 && at > slashes) {
            return url.substring(0, slashes + 3) + "***@" + url.substring(at + 1);
        }
        return url;
    }
}
