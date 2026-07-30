package systems.hugmesh.gateway.config;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import systems.hugmesh.gateway.security.DomainRegistry;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The tenancy resolver must fail CLOSED on an empty trusted-issuer allowlist.
 *
 * <p>This pins the vendored copy of the {@code hugmesh-commons} fix (see
 * hugmesh-commons#21). The gate must test strict membership of a NON-EMPTY
 * {@link DomainRegistry#trustedIssuers()} set, and must NOT delegate to
 * {@link DomainRegistry#isTrusted}, which inherits {@code domainOf}'s legacy
 * single-tenant fail-open and answers "trusted" for ANY issuer on an empty
 * registry — which would hand an attacker-chosen {@code iss} to
 * {@code ReactiveJwtDecoders.fromIssuerLocation}, i.e. OIDC discovery against an
 * attacker-controlled URL.
 *
 * <p>No network: the deny paths return before any decoder is constructed, and the
 * allow path uses the discovery-free back-compat {@code jwk-set-uri} branch.
 */
class TenancyResolverFailClosedTest {

    private static final String BRAND_A = "https://idp.brandx.example";
    private static final String BRAND_B = "https://idp.brandy.example";
    private static final String EVIL = "https://evil.attacker.tld";

    private static ReactiveAuthenticationManagerResolver<String> resolver(
            DomainRegistry r, Map<String, ReactiveAuthenticationManager> cache) {
        return new TenancyResourceServerConfig(r, "", "", false, 600_000L)
                .byIssuerResolver(cache);
    }

    @Nested
    class GuardPremise {

        /**
         * PREMISE GUARD — not an endorsement. {@code isTrusted} FAILS OPEN on an
         * empty registry, which is exactly why the resolver must not use it. Do
         * NOT "fix" {@code domainOf} to make this pass: that default is
         * load-bearing for legacy single-tenant clusters and changing it is a
         * live-boot behaviour change.
         */
        @Test
        void isTrusted_failsOpen_onEmptyRegistry_soTheResolverMustNotUseIt() {
            DomainRegistry empty = new DomainRegistry("", "=brand", "");
            assertThat(empty.trustedIssuers()).isEmpty();
            assertThat(empty.isMultiIssuer()).isFalse();
            assertThat(empty.isTrusted(EVIL)).isTrue();
        }
    }

    @Nested
    class EmptyAllowlistDeniesEveryIssuer {

        /**
         * "=brand" contains '=' so the @ConditionalOnExpression fires and the bean
         * is ACTIVE, but it parses to ZERO pairs (eq <= 0 skip) and there is no
         * issuer-uri to seed the back-compat entry => EMPTY registry.
         */
        @Test
        void activeBeanWithUnparsableCsv_deniesAttackerIssuer() {
            var cache = new ConcurrentHashMap<String, ReactiveAuthenticationManager>();
            assertThat(resolver(new DomainRegistry("", "=brand", ""), cache)
                    .resolve(EVIL).block()).isNull();
            // Nothing constructed => no discovery attempted.
            assertThat(cache).isEmpty();
        }

        @Test
        void activeBeanWithBlankDomainCsv_deniesAttackerIssuer() {
            var cache = new ConcurrentHashMap<String, ReactiveAuthenticationManager>();
            assertThat(resolver(new DomainRegistry("", "https://iss=", ""), cache)
                    .resolve(EVIL).block()).isNull();
            assertThat(cache).isEmpty();
        }

        @Test
        void emptyAllowlist_deniesEvenAWellFormedIssuer() {
            var cache = new ConcurrentHashMap<String, ReactiveAuthenticationManager>();
            assertThat(resolver(new DomainRegistry("", "=brand", ""), cache)
                    .resolve(BRAND_A).block()).isNull();
            assertThat(cache).isEmpty();
        }

        @Test
        void nullAndBlankIssuers_areDenied() {
            var cache = new ConcurrentHashMap<String, ReactiveAuthenticationManager>();
            var r = resolver(new DomainRegistry("", "=brand", ""), cache);
            assertThat(r.resolve(null).block()).isNull();
            assertThat(r.resolve("").block()).isNull();
            assertThat(r.resolve("   ").block()).isNull();
        }
    }

    @Nested
    class PopulatedAllowlistStillFailsClosedForUnknownIssuers {

        private final DomainRegistry multi =
                new DomainRegistry("", BRAND_A + "=brandx," + BRAND_B + "=brandy", "");

        @Test
        void unknownIssuer_isDenied() {
            var cache = new ConcurrentHashMap<String, ReactiveAuthenticationManager>();
            assertThat(resolver(multi, cache).resolve(EVIL).block()).isNull();
            assertThat(cache).isEmpty();
        }

        /** Strict equality — never startsWith/contains. */
        @Test
        void issuerPrefixOfATrustedIssuer_isDenied() {
            var cache = new ConcurrentHashMap<String, ReactiveAuthenticationManager>();
            var r = resolver(multi, cache);
            assertThat(r.resolve(BRAND_A + ".evil.tld").block()).isNull();
            assertThat(r.resolve(BRAND_A + "@evil.tld").block()).isNull();
            assertThat(cache).isEmpty();
        }
    }

    @Nested
    class TrustedIssuerResolvesAndCachesCanonically {

        private final DomainRegistry multi =
                new DomainRegistry("", BRAND_A + "=brandx," + BRAND_B + "=brandy", "");

        /** Back-compat issuer + jwk-set-uri => discovery-free decoder branch. */
        private ReactiveAuthenticationManagerResolver<String> backCompatResolver(
                Map<String, ReactiveAuthenticationManager> cache) {
            return new TenancyResourceServerConfig(
                    multi, BRAND_A, BRAND_A + "/jwks", false, 600_000L)
                    .byIssuerResolver(cache);
        }

        @Test
        void trustedIssuer_resolvesToAManager() {
            var cache = new ConcurrentHashMap<String, ReactiveAuthenticationManager>();
            assertThat(backCompatResolver(cache).resolve(BRAND_A).block()).isNotNull();
            assertThat(cache).containsOnlyKeys(BRAND_A);
        }

        /** Canonical cache key (waste, not vulnerability): slash variants share one manager. */
        @Test
        void slashVariantsShareOneCachedManager() {
            var cache = new ConcurrentHashMap<String, ReactiveAuthenticationManager>();
            var r = backCompatResolver(cache);
            var bare = r.resolve(BRAND_A).block();
            var slashed = r.resolve(BRAND_A + "/").block();
            assertThat(bare).isNotNull();
            assertThat(slashed).isSameAs(bare);
            assertThat(cache).containsOnlyKeys(BRAND_A);
        }
    }
}
