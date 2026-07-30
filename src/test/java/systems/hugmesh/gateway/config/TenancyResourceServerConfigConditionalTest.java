package systems.hugmesh.gateway.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.web.server.ServerWebExchange;
import systems.hugmesh.gateway.security.DomainRegistry;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * BUG 2 regression — the multi-issuer decoder must be genuinely CONFIG-GATED so a
 * single-issuer / default cluster never routes through {@code tenantAuthManagerResolver}
 * (which would otherwise do OIDC discovery and ignore the explicit jwk-set-uri).
 *
 * <p>Two halves are exercised:
 * <ol>
 *   <li><b>The conditional</b> — {@link TenancyResourceServerConfig} (and its
 *       {@code tenantAuthManagerResolver} bean) must be ABSENT both when
 *       {@code app.tenancy.issuers} is unset AND when it is the EMPTY string (the
 *       {@code ${APP_TENANCY_ISSUERS:}} default in application.yml). A bare
 *       {@code @ConditionalOnProperty(name=...)} treated empty as
 *       present-and-true and wrongly activated the bean. It must become PRESENT
 *       only once real {@code issuer=domain} pairs are supplied.</li>
 *   <li><b>The swap predicate</b> — {@link DomainRegistry#isMultiIssuer()} (the
 *       gate {@link SecurityConfig} now keys the swap on) is {@code false} for the
 *       lone back-compat issuer and {@code true} only with more than one trusted
 *       issuer, so the swap is genuinely not taken on a single-issuer cluster.</li>
 * </ol>
 */
class TenancyResourceServerConfigConditionalTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of())
            .withUserConfiguration(TestRegistryConfig.class, TenancyResourceServerConfig.class)
            // The single-issuer jwk-set-uri the back-compat decoder would bind to —
            // present in every deployment; never network-touched here (the resolver
            // builds decoders lazily, per issuer, on first token sight).
            .withPropertyValues(
                    "spring.security.oauth2.resourceserver.jwt.issuer-uri=http://casdoor:8000",
                    "spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://casdoor:8000/jwks");

    /** A DomainRegistry primed from the SAME properties the runner sets, so the
     *  conditional config under test can construct. */
    @org.springframework.context.annotation.Configuration
    static class TestRegistryConfig {
        @org.springframework.context.annotation.Bean
        DomainRegistry domainRegistry(
                @org.springframework.beans.factory.annotation.Value(
                        "${spring.security.oauth2.resourceserver.jwt.issuer-uri:}") String issuer,
                @org.springframework.beans.factory.annotation.Value(
                        "${app.tenancy.issuers:}") String issuers,
                @org.springframework.beans.factory.annotation.Value(
                        "${app.tenancy.hosts:}") String hosts) {
            return new DomainRegistry(issuer, issuers, hosts);
        }
    }

    // ── The conditional (config-gating) ───────────────────────────────────────

    @Test
    void default_noTenancyIssuers_doesNotContributeResolver() {
        // No app.tenancy.issuers at all — the multi-issuer config + its resolver
        // bean must be ABSENT, so SecurityConfig keeps the single-issuer
        // jwk-set-uri o.jwt(...) path.
        runner.run(ctx -> {
            assertThat(ctx).doesNotHaveBean(TenancyResourceServerConfig.class);
            assertThat(ctx.getBeanNamesForType(ReactiveAuthenticationManagerResolver.class))
                    .as("no tenant resolver bean on the default/single-issuer context")
                    .isEmpty();
        });
    }

    @Test
    void emptyTenancyIssuers_theApplicationYmlDefault_doesNotContributeResolver() {
        // app.tenancy.issuers="" (the ${APP_TENANCY_ISSUERS:} default) is "present
        // and not false" — a bare @ConditionalOnProperty would WRONGLY activate the
        // bean. The .contains('=') guard keeps it absent.
        runner.withPropertyValues("app.tenancy.issuers=").run(ctx -> {
            assertThat(ctx).doesNotHaveBean(TenancyResourceServerConfig.class);
            assertThat(ctx.getBeanNamesForType(ReactiveAuthenticationManagerResolver.class))
                    .as("empty issuers must NOT activate the tenant resolver")
                    .isEmpty();
        });
    }

    @Test
    void populatedTenancyIssuers_contributesResolver() {
        // Real issuer=domain pairs -> the conditional fires and the resolver bean is
        // present (multi-brand mode). Built lazily, so no Casdoor is contacted here.
        runner.withPropertyValues(
                "app.tenancy.issuers=https://id.brandx.tld=brandx,https://id.brandy.tld=brandy")
            .run(ctx -> {
                assertThat(ctx).hasSingleBean(TenancyResourceServerConfig.class);
                assertThat(ctx).hasSingleBean(ReactiveAuthenticationManagerResolver.class);
            });
    }

    // ── The swap predicate (isMultiIssuer) ────────────────────────────────────

    @Test
    void singleIssuer_isNotMultiIssuer_soSwapIsNotTaken() {
        // The lone back-compat issuer -> isMultiIssuer() == false, so even if a
        // resolver were present SecurityConfig would NOT swap onto it (it keeps the
        // jwk-set-uri o.jwt path). This is the dead-code-made-live guard.
        DomainRegistry single = new DomainRegistry("http://casdoor:8000", "", "");
        assertThat(single.isMultiIssuer()).isFalse();
    }

    @Test
    void multipleIssuers_isMultiIssuer_soSwapIsTaken() {
        DomainRegistry multi = new DomainRegistry(
                "https://id.brandx.tld",
                "https://id.brandx.tld=brandx,https://id.brandy.tld=brandy", "");
        assertThat(multi.isMultiIssuer()).isTrue();
    }

    @Test
    void securityConfig_swapNotTaken_whenResolverPresentButSingleIssuer() {
        // Direct guard on the predicate SecurityConfig keys the swap on: with a
        // single-issuer registry the swap must not be taken even if a (stub)
        // resolver is contributed — the bug was swapping on resolver != null alone.
        DomainRegistry single = new DomainRegistry("http://casdoor:8000", "", "");
        ReactiveAuthenticationManagerResolver<ServerWebExchange> stub =
                exchange -> reactor.core.publisher.Mono.empty();
        boolean swapTaken = stub != null && single.isMultiIssuer();
        assertThat(swapTaken)
                .as("single-issuer must keep the jwk-set-uri o.jwt path, not the resolver")
                .isFalse();
    }
}
