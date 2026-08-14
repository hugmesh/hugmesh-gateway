package net.hugmesh.gateway.security;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link DomainRegistry} — the issuer/host -&gt; domain source of truth. The
 * keystone of the multi-tenant isolation boundary: get this wrong and a token
 * from brand-Y is mapped to brand-X (or an untrusted Casdoor is accepted).
 *
 * <p>Delineated per the test standard:
 * <ul>
 *   <li>USER-SITUATIONAL — a single configured tenant resolving its own issuer.</li>
 *   <li>MULTIUSER-SITUATIONAL — several brands configured, each resolving its own.</li>
 *   <li>CROSS-USER — the isolation boundary: brand-Y's issuer must NOT resolve to
 *       brand-X's domain; an UNTRUSTED issuer fails closed (null).</li>
 *   <li>CONCURRENT — many threads resolving issuers at once see consistent answers.</li>
 * </ul>
 */
class DomainRegistryTest {

    // ── USER-SITUATIONAL — single-tenant / legacy back-compat ────────────────
    @Nested
    class UserSituational_SingleIssuer {

        @Test
        void noConfigAtAll_anyIssuer_mapsToDefault() {
            // The most degenerate single-tenant case: no issuer-uri, no registry.
            DomainRegistry reg = new DomainRegistry("", "", "");
            assertThat(reg.domainOf("http://anything:8000")).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
            assertThat(reg.domainOf(null)).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
            assertThat(reg.isMultiIssuer()).isFalse();
        }

        @Test
        void loneConfiguredIssuer_mapsToDefault_trailingSlashTolerant() {
            DomainRegistry reg = new DomainRegistry("http://casdoor:8000/", "", "");
            // trailing slash on either side is normalised away
            assertThat(reg.domainOf("http://casdoor:8000")).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
            assertThat(reg.domainOf("http://casdoor:8000/")).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
            assertThat(reg.isTrusted("http://casdoor:8000")).isTrue();
            assertThat(reg.isMultiIssuer()).isFalse();
        }

        @Test
        void singleIssuer_theConfiguredIssuer_isDefault_aDifferentIssuerFailsClosed() {
            // With exactly the ONE configured issuer seeded, that issuer -> default.
            // A DIFFERENT issuer (which the single-issuer resource server would
            // already reject at iss-validation) returns null defensively — it never
            // gets silently mapped to "default". The empty-map (no issuer-uri at all)
            // case is the only one that returns "default" for any issuer.
            DomainRegistry reg = new DomainRegistry("http://casdoor:8000", "", "");
            assertThat(reg.domainOf("http://casdoor:8000")).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
            assertThat(reg.domainOf("http://someone-else:8000")).isNull();
        }

        @Test
        void singleIssuer_hostCheckIsNoOp_everyHostDefault() {
            DomainRegistry reg = new DomainRegistry("http://casdoor:8000", "", "");
            assertThat(reg.domainForHost("api.brandx.tld")).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
            assertThat(reg.domainForHost(null)).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
        }
    }

    // ── MULTIUSER-SITUATIONAL — several brands, each its own ──────────────────
    @Nested
    class MultiUserSituational_MultiBrand {

        private final DomainRegistry reg = new DomainRegistry(
                "https://id.brandx.tld",
                "https://id.brandx.tld=brandx,https://id.brandy.tld=brandy",
                "api.brandx.tld=brandx,brandy.tld=brandy");

        @Test
        void eachBrandIssuerResolvesToItsOwnDomain() {
            assertThat(reg.domainOf("https://id.brandx.tld")).isEqualTo("brandx");
            assertThat(reg.domainOf("https://id.brandy.tld")).isEqualTo("brandy");
            assertThat(reg.isMultiIssuer()).isTrue();
            assertThat(reg.trustedIssuers())
                .containsExactlyInAnyOrder("https://id.brandx.tld", "https://id.brandy.tld");
        }

        @Test
        void hostResolvesBySuffix() {
            assertThat(reg.domainForHost("api.brandx.tld")).isEqualTo("brandx");
            // suffix match: any sub-host of brandy.tld
            assertThat(reg.domainForHost("www.brandy.tld")).isEqualTo("brandy");
            assertThat(reg.domainForHost("brandy.tld")).isEqualTo("brandy");
            // port is stripped
            assertThat(reg.domainForHost("api.brandx.tld:8443")).isEqualTo("brandx");
        }

        @Test
        void domainValueIsSanitisedLowercase() {
            DomainRegistry r = new DomainRegistry("",
                    "https://id.a.tld=Brand_X!!,https://id.b.tld=BRAND B", "");
            assertThat(r.domainOf("https://id.a.tld")).isEqualTo("brand-x--");
            assertThat(r.domainOf("https://id.b.tld")).isEqualTo("brand-b");
        }
    }

    // ── CROSS-USER — the isolation boundary (the security keystone) ───────────
    @Nested
    class CrossUser_IsolationBoundary {

        private final DomainRegistry reg = new DomainRegistry(
                "https://id.brandx.tld",
                "https://id.brandx.tld=brandx,https://id.brandy.tld=brandy",
                "api.brandx.tld=brandx,api.brandy.tld=brandy");

        @Test
        void brandYIssuer_doesNotResolveToBrandXDomain() {
            // NEGATIVE isolation: brand-Y's issuer must never come back as brand-X.
            assertThat(reg.domainOf("https://id.brandy.tld")).isNotEqualTo("brandx");
            assertThat(reg.domainOf("https://id.brandx.tld")).isNotEqualTo("brandy");
        }

        @Test
        void untrustedIssuer_failsClosed_null() {
            // An issuer NOT in the multi-brand allowlist must be rejected (null),
            // never silently mapped to some domain — this is what makes the
            // multi-issuer decoder 401 an unknown iss.
            assertThat(reg.domainOf("https://evil.attacker.tld")).isNull();
            assertThat(reg.isTrusted("https://evil.attacker.tld")).isFalse();
        }

        @Test
        void unmappedHost_inMultiBrand_fallsBackToDefault_notAnotherBrand() {
            // A Host not in the map must NOT resolve to a real brand (which would
            // grant that brand's bypass); it falls back to "default" so the
            // gateway's domain match fails for a real-brand principal.
            assertThat(reg.domainForHost("unknown.host.tld")).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
        }

        @Test
        void nullIssuer_inMultiBrand_failsClosed() {
            assertThat(reg.domainOf(null)).isNull();
        }
    }

    // ── CONCURRENT — many threads resolving at once ───────────────────────────
    @Nested
    class Concurrent {

        @Test
        void concurrentResolution_isConsistent() throws Exception {
            DomainRegistry reg = new DomainRegistry(
                    "https://id.brandx.tld",
                    "https://id.brandx.tld=brandx,https://id.brandy.tld=brandy", "");
            ExecutorService pool = Executors.newFixedThreadPool(8);
            AtomicBoolean mismatch = new AtomicBoolean(false);
            try {
                Future<?>[] futures = new Future<?>[200];
                for (int i = 0; i < futures.length; i++) {
                    final boolean x = (i % 2 == 0);
                    futures[i] = pool.submit(() -> {
                        String iss = x ? "https://id.brandx.tld" : "https://id.brandy.tld";
                        String expect = x ? "brandx" : "brandy";
                        for (int k = 0; k < 500; k++) {
                            if (!expect.equals(reg.domainOf(iss))) mismatch.set(true);
                            // an untrusted issuer must always fail closed under load
                            if (reg.domainOf("https://evil.tld") != null) mismatch.set(true);
                        }
                    });
                }
                for (Future<?> f : futures) f.get(30, TimeUnit.SECONDS);
            } finally {
                pool.shutdownNow();
            }
            assertThat(mismatch.get()).as("no cross-brand or fail-open mismatch under concurrency").isFalse();
        }
    }
}
