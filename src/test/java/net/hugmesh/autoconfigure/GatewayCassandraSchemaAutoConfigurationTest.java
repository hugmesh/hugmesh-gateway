package net.hugmesh.autoconfigure;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.cassandra.core.ReactiveCassandraTemplate;
import org.springframework.data.cassandra.core.cql.ReactiveCqlOperations;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.gateway.cache.CassandraSchemaMigrations;

import java.util.LinkedHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Regression for the CRITICAL games-session handoff bug: {@link CassandraSchemaMigrations}
 * was a component-scanned {@code @Component} carrying
 * {@code @ConditionalOnBean(ReactiveCqlOperations.class)}. Component-scan registration
 * happens BEFORE auto-configuration contributes the Cassandra template / CQL beans, so the
 * condition was deterministically FALSE and the migration runner was silently absent from
 * EVERY real deployment — the gateway keyspace got no tables and migrations 006
 * ({@code hs_tokens}) and 007 (the multi-brand {@code domain} column) never applied.
 *
 * <p>The fix moves registration to {@link GatewayCassandraSchemaAutoConfiguration}, a true
 * {@code @AutoConfiguration} ordered AFTER Boot's Cassandra reactive auto-configuration. This
 * test proves the bean is now REGISTERED when Cassandra is present (the deployment-real path),
 * is ABSENT when Cassandra is not wired (Cassandra-less deploys still boot), honours the
 * property gate, and — once registered — actually carries migrations 006 and 007.
 *
 * <p>The Cassandra beans are MOCKED so the runner exercises the auto-configuration's bean
 * registration / condition evaluation without a live cluster; the migration runner's
 * {@code @PostConstruct} (which executes the CQL) is fed harmless empty publishers.
 */
class GatewayCassandraSchemaAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(GatewayCassandraSchemaAutoConfiguration.class));

    /** Stand-ins for the beans Spring Boot's {@code DataCassandraReactiveAutoConfiguration}
     *  contributes when Cassandra reactive is wired: a {@link ReactiveCassandraTemplate}
     *  (the {@code @ConditionalOnBean} signal) and the {@link ReactiveCqlOperations} the
     *  migration runner injects. The CQL stub returns empty publishers so the migration's
     *  boot-time {@code @PostConstruct} completes without touching a real cluster. */
    @Configuration
    static class CassandraPresentConfig {
        @Bean
        ReactiveCassandraTemplate reactiveCassandraTemplate() {
            return mock(ReactiveCassandraTemplate.class);
        }

        @Bean
        ReactiveCqlOperations reactiveCqlOperations() {
            // Default-answer mock: any ReactiveCqlOperations method that returns a
            // reactive type yields an EMPTY publisher, so the migration runner's
            // boot-time @PostConstruct (queryForObject SELECT -> empty = "not yet
            // applied", then execute() the CREATE/ALTER/INSERT) completes against no
            // real cluster regardless of which execute/queryForObject overload it hits.
            return mock(ReactiveCqlOperations.class, invocation -> {
                Class<?> returnType = invocation.getMethod().getReturnType();
                if (Mono.class.isAssignableFrom(returnType)) {
                    return Mono.empty();
                }
                if (Flux.class.isAssignableFrom(returnType)) {
                    return Flux.empty();
                }
                return null;
            });
        }
    }

    /** Mirrors a deployment WITHOUT the Cassandra reactive starter: no template, no CQL. */
    @Configuration
    static class CassandraAbsentConfig {
    }

    @Test
    void cassandraPresent_registersTheMigrationBean() {
        // THE FIX: with the Cassandra template + CQL beans present, the auto-config's
        // @ConditionalOnBean now evaluates AFTER they exist, so the migration runner is
        // registered — the path that was deterministically dead before.
        runner.withUserConfiguration(CassandraPresentConfig.class).run(ctx -> {
            assertThat(ctx).hasNotFailed();
            assertThat(ctx).hasSingleBean(CassandraSchemaMigrations.class);
        });
    }

    @Test
    void cassandraAbsent_doesNotRegisterTheMigrationBean() {
        // Cassandra-less deploys still boot: no template bean -> @ConditionalOnBean keeps
        // the migration runner absent (and nothing tries to talk to a cluster).
        runner.withUserConfiguration(CassandraAbsentConfig.class).run(ctx -> {
            assertThat(ctx).hasNotFailed();
            assertThat(ctx).doesNotHaveBean(CassandraSchemaMigrations.class);
        });
    }

    @Test
    void migrationsDisabledByProperty_doesNotRegisterTheBean() {
        // The property gate lets an operator opt out even with Cassandra wired.
        runner.withUserConfiguration(CassandraPresentConfig.class)
                .withPropertyValues("app.cassandra.migrations.enabled=false")
                .run(ctx -> {
                    assertThat(ctx).hasNotFailed();
                    assertThat(ctx).doesNotHaveBean(CassandraSchemaMigrations.class);
                });
    }

    @Test
    void registeredBean_carriesMigrations006And007() throws Exception {
        // Proves the live deployment path now applies the formerly-dead migrations:
        // the REGISTERED bean's migration registry contains 006 (hs_tokens) and 007
        // (the multi-brand domain column) — the two that never ran while the bean
        // was a dead @Component.
        runner.withUserConfiguration(CassandraPresentConfig.class).run(ctx -> {
            assertThat(ctx).hasSingleBean(CassandraSchemaMigrations.class);

            var field = CassandraSchemaMigrations.class.getDeclaredField("MIGRATIONS");
            field.setAccessible(true);
            @SuppressWarnings("unchecked")
            LinkedHashMap<String, String> migrations =
                    (LinkedHashMap<String, String>) field.get(null);

            assertThat(migrations).containsKeys(
                    "006-hs-tokens-table",
                    "007-gateway-route-access-domain-column");
            assertThat(migrations.get("006-hs-tokens-table"))
                    .contains("CREATE TABLE IF NOT EXISTS hs_tokens");
            assertThat(migrations.get("007-gateway-route-access-domain-column"))
                    .contains("ALTER TABLE gateway_route_access ADD domain text");
        });
    }
}
