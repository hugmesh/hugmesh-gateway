package systems.hugmesh.autoconfigure;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.data.cassandra.autoconfigure.DataCassandraReactiveAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.data.cassandra.core.ReactiveCassandraTemplate;
import org.springframework.data.cassandra.core.cql.ReactiveCqlOperations;
import systems.hugmesh.gateway.cache.CassandraSchemaMigrations;

/**
 * Registers {@link CassandraSchemaMigrations} as a true auto-configuration so
 * its {@code @ConditionalOnBean(ReactiveCassandraTemplate.class)} gate is
 * evaluated AFTER Spring Boot's Cassandra reactive auto-configuration has (or
 * hasn't) contributed the template / CQL beans.
 *
 * <p><strong>Why this class exists.</strong> The migration runner used to be a
 * component-scanned {@code @Component} carrying
 * {@code @ConditionalOnBean(ReactiveCqlOperations.class)} directly. That never
 * fired in any real deployment: component-scan registration happens BEFORE
 * auto-configuration, so the {@code ReactiveCqlTemplate} /
 * {@code ReactiveCassandraTemplate} bean definitions did not exist yet and the
 * condition was deterministically FALSE. The whole gateway keyspace therefore
 * got NO schema — {@code revocations}, {@code url_registry},
 * {@code resource_access}, {@code gateway_route_access}, {@code hs_tokens} —
 * and in particular migration 006 ({@code hs_tokens}, the account-states P0
 * prereq) and 007 (the multi-brand {@code domain} column the multi-tenancy
 * work depends on) never applied. The unit suite passed because it inspects the
 * static {@code MIGRATIONS} registry by reflection rather than running the
 * bean. Spring's own javadoc warns that {@code @ConditionalOnBean} is only safe
 * on auto-configuration classes; this class is that auto-configuration,
 * imported via
 * {@code META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports}.
 *
 * <p>This package ({@code systems.hugmesh.autoconfigure}) is deliberately
 * OUTSIDE the {@code systems.hugmesh.gateway} {@code @SpringBootApplication}
 * component-scan root — a scanned {@code @Configuration} would be processed with
 * the same too-early condition evaluation that broke the original.
 *
 * <p>Behaviour is otherwise unchanged. The
 * {@code @ConditionalOnBean(ReactiveCassandraTemplate.class)} gate preserves the
 * original Cassandra-less safety: a deployment without the Cassandra
 * reactive starter/template boots clean with the migration bean simply absent.
 * (Spring Boot 4's {@link DataCassandraReactiveAutoConfiguration} already
 * contributes the {@code ReactiveCqlTemplate} that satisfies the injected
 * {@link ReactiveCqlOperations}, so — unlike the hugmesh.games sibling fix —
 * no extra CQL-template bean needs contributing here.)
 */
@AutoConfiguration(after = DataCassandraReactiveAutoConfiguration.class)
public class GatewayCassandraSchemaAutoConfiguration {

    /**
     * Materialise the schema-migration runner only when Cassandra reactive is
     * wired. {@code ReactiveCassandraTemplate} is the same "is Cassandra
     * present?" signal the cache services nullable-inject, and Boot
     * co-contributes the {@link ReactiveCqlOperations} ({@code ReactiveCqlTemplate})
     * the runner needs alongside it.
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(ReactiveCassandraTemplate.class)
    @ConditionalOnProperty(name = "app.cassandra.migrations.enabled", havingValue = "true", matchIfMissing = true)
    CassandraSchemaMigrations cassandraSchemaMigrations(ReactiveCqlOperations cql) {
        return new CassandraSchemaMigrations(cql);
    }
}
