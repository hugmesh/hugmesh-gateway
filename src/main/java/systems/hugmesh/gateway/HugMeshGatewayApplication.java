package systems.hugmesh.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.data.r2dbc.autoconfigure.DataR2dbcAutoConfiguration;
import org.springframework.boot.r2dbc.autoconfigure.R2dbcAutoConfiguration;
import org.springframework.boot.r2dbc.autoconfigure.R2dbcTransactionManagerAutoConfiguration;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * HugMesh platform gateway — one binary, multiple instance names.
 *
 * <p>The Docker image bakes this binary in; the deployed instance gets
 * its identity from {@code spring.application.name}:
 *
 * <ul>
 *   <li>{@code hugmesh-pki-gateway} — the PKI/identity front door (Casdoor)</li>
 *   <li>{@code hugmesh-be-gateway}  — the backend (BFF/API) front door</li>
 *   <li>{@code hugmesh-fe-gateway}  — the front-end (UI) front door</li>
 * </ul>
 *
 * <p>and, per-brand, {@code ${BRAND}-{pki,be,fe}-gateway}. See {@code CanonicalSeed}
 * for how an instance name resolves to its tier's baked-in route-access floor.
 *
 * <p>Every instance shares the same Cassandra cluster (different
 * keyspaces per environment) for the revocation list + URL registry
 * tables — see RevocationListService + UrlRegistryService.
 *
 * <p>{@code @EnableScheduling} powers the periodic refresh hooks on
 * those two cache services.
 *
 * <p>The R2DBC auto-configuration is excluded: the only Postgres the
 * gateway touches is the {@code gateway_route_access} source of truth,
 * wired by {@link systems.hugmesh.gateway.config.RouteAccessR2dbcConfig}
 * from {@code ROUTE_ACCESS_R2DBC_URL} as a dedicated, optional reactive
 * repository (built over its own {@code ConnectionFactory}, NOT the primary
 * {@code spring.r2dbc.*} one). Excluding the auto-configs keeps a gateway with
 * no route-access URL from failing on boot trying to build a primary
 * {@code spring.r2dbc.*} connection pool, and stops
 * {@code DataR2dbcAutoConfiguration} from demanding a primary R2DBC
 * connection we deliberately leave absent when the URL is unset.
 */
@SpringBootApplication(exclude = {
        R2dbcAutoConfiguration.class,
        R2dbcTransactionManagerAutoConfiguration.class,
        DataR2dbcAutoConfiguration.class
})
@EnableScheduling
public class HugMeshGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(HugMeshGatewayApplication.class, args);
	}
}
