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

    // ── ONION HOSTS — hugmesh-gateway#38 ─────────────────────────────────────
    // A Tor v3 onion is minted on the node, so it reaches the registry through the
    // RUNTIME host-map file, and an UNMAPPED onion must fail CLOSED (null) rather
    // than collapse to "default" and serve another brand.
    @Nested
    class OnionHosts {

        /** Realistic v3 onion names (56 base32 chars + ".onion"). */
        static final String ONION_X = "a".repeat(52) + "bxid.onion";
        static final String ONION_Y = "b".repeat(52) + "byid.onion";
        static final String ONION_Z = "c".repeat(52) + "czid.onion";

        private static final String ISSUERS =
                "https://id.brandx.tld=brandx,https://id.brandy.tld=brandy";

        @org.junit.jupiter.api.io.TempDir
        java.nio.file.Path tmp;

        private java.nio.file.Path write(String name, String content) throws Exception {
            java.nio.file.Path f = tmp.resolve(name);
            java.nio.file.Files.writeString(f, content);
            return f;
        }

        @Test
        void mappedOnion_literal_resolvesToItsSlug_caseTrailingDotPortAndSubdomainTolerant() {
            DomainRegistry reg = new DomainRegistry("https://id.brandx.tld", ISSUERS,
                    "api.brandx.tld=brandx," + ONION_Y + "=brandy");
            assertThat(reg.domainForHost(ONION_Y)).isEqualTo("brandy");
            assertThat(reg.domainForHost(ONION_Y.toUpperCase())).isEqualTo("brandy");
            assertThat(reg.domainForHost(ONION_Y + ".")).isEqualTo("brandy");
            assertThat(reg.domainForHost(ONION_Y + ":80")).isEqualTo("brandy");
            // Tor routes every sub-label of a v3 onion to the same service
            assertThat(reg.domainForHost("www." + ONION_Y)).isEqualTo("brandy");
        }

        @Test
        void unmappedOnion_withAHostMap_failsClosed_null_neverDefault() {
            DomainRegistry reg = new DomainRegistry("https://id.brandx.tld", ISSUERS,
                    "api.brandx.tld=brandx," + ONION_Y + "=brandy");
            assertThat(reg.domainForHost(ONION_Z)).as("unregistered onion").isNull();
            assertThat(reg.domainForHost(ONION_Z + ".")).as("trailing-dot FQDN form").isNull();
            assertThat(reg.domainForHost("onion")).as("bare TLD").isNull();
            // ...while an unmapped ORDINARY host keeps its "default" contract
            assertThat(reg.domainForHost("unknown.host.tld")).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
        }

        @Test
        void unmappedOnion_singleBrandWithAHostMap_stillFailsClosed() {
            // Single issuer but a host map is configured: the operator has declared
            // host-based tenancy, so an unregistered onion is not "the" brand.
            DomainRegistry reg = new DomainRegistry("http://casdoor:8000", "",
                    "hugmesh.net=default");
            assertThat(reg.isMultiIssuer()).isFalse();
            assertThat(reg.domainForHost(ONION_Z)).isNull();
        }

        @Test
        void unmappedOnion_multiIssuerWithoutAnyHostMap_failsClosed() {
            DomainRegistry reg = new DomainRegistry("https://id.brandx.tld", ISSUERS, "");
            assertThat(reg.isMultiIssuer()).isTrue();
            assertThat(reg.domainForHost(ONION_Z)).isNull();
            // ordinary hosts on that registry are unchanged ("default")
            assertThat(reg.domainForHost("api.brandx.tld")).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
        }

        @Test
        void singleTenant_noHostMap_noFile_onionStaysDefault() {
            // One brand, no host map: there is no OTHER brand to leak, and the compose
            // lane's lone onion door (TOR=1) must keep working.
            DomainRegistry reg = new DomainRegistry("http://casdoor:8000", "", "");
            assertThat(reg.domainForHost(ONION_Z)).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
            DomainRegistry none = new DomainRegistry("", "", "", "");
            assertThat(none.domainForHost(ONION_Z)).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
        }

        @Test
        void fileConfiguredButAbsent_onionFailsClosed_ordinaryHostDefault() {
            // The mis-registration window: the file path is set but the reconcile has
            // not written it yet, so the effective map is EMPTY — the onion must still
            // be refused, not collapsed to default.
            DomainRegistry reg = new DomainRegistry("http://casdoor:8000", "", "",
                    tmp.resolve("not-yet-written.map").toString());
            assertThat(reg.domainForHost(ONION_X)).isNull();
            assertThat(reg.domainForHost("hugmesh.net")).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
        }

        @Test
        void fileEntries_areReadAtConstruction() throws Exception {
            var f = write("hosts.map", "# minted by hugmesh-tor-reconcile\n\n"
                    + ONION_X + "=brandx\n" + ONION_Y + " = BrandY\n");
            DomainRegistry reg = new DomainRegistry("https://id.brandx.tld", ISSUERS, "",
                    f.toString());
            assertThat(reg.domainForHost(ONION_X)).isEqualTo("brandx");
            assertThat(reg.domainForHost(ONION_Y)).isEqualTo("brandy");
            assertThat(reg.domainForHost(ONION_Z)).isNull();
        }

        @Test
        void fileIsReReadOnChange_appendRegisters_removeUnregisters_deleteEmpties() throws Exception {
            var f = write("hosts.map", ONION_X + "=brandx\n");
            DomainRegistry reg = new DomainRegistry("https://id.brandx.tld", ISSUERS, "",
                    f.toString());
            assertThat(reg.domainForHost(ONION_Y)).as("before the mint lands").isNull();

            java.nio.file.Files.writeString(f, ONION_X + "=brandx\n" + ONION_Y + "=brandy\n");
            reg.reloadHostsFile();
            assertThat(reg.domainForHost(ONION_Y)).as("appended after mint").isEqualTo("brandy");
            assertThat(reg.domainForHost(ONION_X)).isEqualTo("brandx");

            java.nio.file.Files.writeString(f, ONION_Y + "=brandy\n");
            reg.reloadHostsFile();
            assertThat(reg.domainForHost(ONION_X)).as("entry removed").isNull();

            java.nio.file.Files.delete(f);
            reg.reloadHostsFile();
            assertThat(reg.domainForHost(ONION_Y)).as("file deleted").isNull();
        }

        @Test
        void configMapStyleSymlinkSwap_isPickedUp() throws Exception {
            // A mounted ConfigMap key is a symlink into ..data/, which kubelet swaps
            // atomically; the path's own inode never changes. Content is re-read.
            var v1 = java.nio.file.Files.createDirectory(tmp.resolve("..v1"));
            var v2 = java.nio.file.Files.createDirectory(tmp.resolve("..v2"));
            java.nio.file.Files.writeString(v1.resolve("hosts"), ONION_X + "=brandx\n");
            java.nio.file.Files.writeString(v2.resolve("hosts"), ONION_X + "=brandx\n" + ONION_Y + "=brandy\n");
            var data = tmp.resolve("..data");
            java.nio.file.Files.createSymbolicLink(data, v1.getFileName());
            var key = tmp.resolve("hosts");
            java.nio.file.Files.createSymbolicLink(key, java.nio.file.Path.of("..data", "hosts"));
            DomainRegistry reg = new DomainRegistry("https://id.brandx.tld", ISSUERS, "",
                    key.toString());
            assertThat(reg.domainForHost(ONION_Y)).isNull();

            var tmpLink = tmp.resolve("..data_tmp");
            java.nio.file.Files.createSymbolicLink(tmpLink, v2.getFileName());
            java.nio.file.Files.move(tmpLink, data, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            reg.reloadHostsFile();
            assertThat(reg.domainForHost(ONION_Y)).isEqualTo("brandy");
        }

        @Test
        void fileOnlyRegistersOnions_nonOnionAndBareTldLinesAreDropped() throws Exception {
            // The file is written by a NODE process: it may add an onion, never map an
            // HTTPS host, and never a bare "onion" suffix that would capture them all.
            var f = write("hosts.map", "api.brandx.tld=brandy\nonion=brandy\n.onion=brandy\n"
                    + ONION_X + "=brandx\n");
            DomainRegistry reg = new DomainRegistry("https://id.brandx.tld", ISSUERS, "",
                    f.toString());
            assertThat(reg.domainForHost("api.brandx.tld")).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
            assertThat(reg.domainForHost(ONION_Z)).as("no catch-all onion entry").isNull();
            assertThat(reg.domainForHost(ONION_X)).isEqualTo("brandx");
        }

        @Test
        void fileLine_neverOverridesTheOperatorLiteral() throws Exception {
            var f = write("hosts.map", ONION_X + "=brandy\n");
            DomainRegistry reg = new DomainRegistry("https://id.brandx.tld", ISSUERS,
                    ONION_X + "=brandx", f.toString());
            assertThat(reg.domainForHost(ONION_X)).isEqualTo("brandx");
        }

        @Test
        void fileCsvRunOnOneLine_isAccepted() throws Exception {
            var f = write("hosts.map", ONION_X + "=brandx," + ONION_Y + "=brandy\n");
            DomainRegistry reg = new DomainRegistry("https://id.brandx.tld", ISSUERS, "",
                    f.toString());
            assertThat(reg.domainForHost(ONION_X)).isEqualTo("brandx");
            assertThat(reg.domainForHost(ONION_Y)).isEqualTo("brandy");
        }

        @Test
        void unreadableFile_keepsTheLastKnownGoodMap() throws Exception {
            var f = write("hosts.map", ONION_X + "=brandx\n");
            DomainRegistry reg = new DomainRegistry("https://id.brandx.tld", ISSUERS, "",
                    f.toString());
            // Replace the file with a directory: size() succeeds, readString() throws
            // an IOException that is NOT NoSuchFileException.
            java.nio.file.Files.delete(f);
            java.nio.file.Files.createDirectory(f);
            reg.reloadHostsFile();
            assertThat(reg.domainForHost(ONION_X)).as("transient read error keeps the map").isEqualTo("brandx");
        }

        @Test
        void oversizeFile_isNotParsed_andKeepsTheLastKnownGoodMap() throws Exception {
            var f = write("hosts.map", ONION_X + "=brandx\n");
            DomainRegistry reg = new DomainRegistry("https://id.brandx.tld", ISSUERS, "",
                    f.toString());
            StringBuilder big = new StringBuilder(ONION_Y + "=brandy\n");
            while (big.length() <= DomainRegistry.MAX_HOSTS_FILE_BYTES) big.append("#".repeat(1023)).append('\n');
            java.nio.file.Files.writeString(f, big);
            reg.reloadHostsFile();
            assertThat(reg.domainForHost(ONION_X)).isEqualTo("brandx");
            assertThat(reg.domainForHost(ONION_Y)).isNull();
        }

        @Test
        void trailingDotOrdinaryHost_resolvesToItsBrand_notDefault() {
            // "api.brandx.tld." is the same host; before normalisation it missed the
            // suffix match and became "default" — which a default-brand principal
            // would then MATCH on brand-X's surface.
            DomainRegistry reg = new DomainRegistry("https://id.brandx.tld", ISSUERS,
                    "api.brandx.tld=brandx");
            assertThat(reg.domainForHost("api.brandx.tld.")).isEqualTo("brandx");
            assertThat(reg.domainForHost("API.BRANDX.TLD.:443")).isEqualTo("brandx");
        }

        @Test
        void reloadIsScheduled_onTheDocumentedProperty() throws Exception {
            var m = DomainRegistry.class.getMethod("reloadHostsFile");
            var sch = m.getAnnotation(org.springframework.scheduling.annotation.Scheduled.class);
            assertThat(sch).as("@Scheduled drives the re-read").isNotNull();
            assertThat(sch.fixedDelayString()).isEqualTo("${app.tenancy.hosts-file-refresh-ms:5000}");
        }

        @Test
        void springBinding_hostsFileProperty_andTheScheduledPollPicksUpAnAppend() throws Exception {
            // The container-built bean: @Autowired constructor + @Value placeholders +
            // @EnableScheduling, with no direct reloadHostsFile() call — proves the
            // property name binds and the poll really re-reads on change.
            var f = write("hosts.map", ONION_X + "=brandx\n");
            new org.springframework.boot.test.context.runner.ApplicationContextRunner()
                    .withPropertyValues(
                            "spring.security.oauth2.resourceserver.jwt.issuer-uri=https://id.brandx.tld",
                            "app.tenancy.issuers=" + ISSUERS,
                            "app.tenancy.hosts-file=" + f,
                            "app.tenancy.hosts-file-refresh-ms=50")
                    .withUserConfiguration(SchedulingOn.class, DomainRegistry.class)
                    .run(ctx -> {
                        assertThat(ctx).hasNotFailed();
                        DomainRegistry reg = ctx.getBean(DomainRegistry.class);
                        assertThat(reg.domainForHost(ONION_X)).isEqualTo("brandx");
                        assertThat(reg.domainForHost(ONION_Y)).isNull();
                        java.nio.file.Files.writeString(f, ONION_X + "=brandx\n" + ONION_Y + "=brandy\n");
                        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
                        while (!"brandy".equals(reg.domainForHost(ONION_Y)) && System.nanoTime() < deadline) {
                            Thread.sleep(25);
                        }
                        assertThat(reg.domainForHost(ONION_Y))
                                .as("the scheduled poll re-read the appended line").isEqualTo("brandy");
                    });
        }

        @org.springframework.context.annotation.Configuration(proxyBeanMethods = false)
        @org.springframework.scheduling.annotation.EnableScheduling
        static class SchedulingOn { }

        @Test
        void concurrentReadsDuringSwaps_neverResolveAnOnionToAnotherBrandOrDefault() throws Exception {
            var f = write("hosts.map", ONION_X + "=brandx\n");
            DomainRegistry reg = new DomainRegistry("https://id.brandx.tld", ISSUERS, "",
                    f.toString());
            AtomicBoolean bad = new AtomicBoolean(false);
            AtomicBoolean stop = new AtomicBoolean(false);
            ExecutorService pool = Executors.newFixedThreadPool(6);
            try {
                Future<?>[] readers = new Future<?>[5];
                for (int i = 0; i < readers.length; i++) {
                    readers[i] = pool.submit(() -> {
                        while (!stop.get()) {
                            if (!"brandx".equals(reg.domainForHost(ONION_X))) bad.set(true);
                            String y = reg.domainForHost(ONION_Y);
                            if (y != null && !"brandy".equals(y)) bad.set(true);
                        }
                    });
                }
                for (int k = 0; k < 300; k++) {
                    java.nio.file.Files.writeString(f, (k % 2 == 0)
                            ? ONION_X + "=brandx\n" + ONION_Y + "=brandy\n"
                            : ONION_X + "=brandx\n");
                    reg.reloadHostsFile();
                }
                stop.set(true);
                for (Future<?> r : readers) r.get(30, TimeUnit.SECONDS);
            } finally {
                stop.set(true);
                pool.shutdownNow();
            }
            assertThat(bad.get()).as("no torn read across an atomic swap").isFalse();
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
