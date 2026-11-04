package net.hugmesh.gateway.cache;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import net.hugmesh.gateway.cache.GatewayRouteAccessService.Rule;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The baked {@link CanonicalSeed} must carry every pki/be/fe row of the cluster
 * Postgres seed, and nothing else, except the divergences named below with the
 * decision behind each (hugmesh-gateway#61 round 2). Any other difference, in
 * EITHER direction, fails this test: a row the generator adds that is not baked
 * here, a row baked here the generator does not carry, a changed role or
 * {@code allow}, or a baked {@code mfa_required} that disagrees with what the
 * seed's UPDATE statements set.
 *
 * <p><b>The vendored copy.</b> Tests cannot reach the network, so this reads a
 * byte-for-byte copy of generator
 * {@code specs/cluster/manifests/route-access/initdb/20-schema.sql} at
 * {@code src/test/resources/route-access/generator-20-schema.sql}, vendored from
 * hugmesh-generator {@code main} @ {@value #VENDORED_COMMIT} (git blob
 * {@value #VENDORED_BLOB}). Refresh it from the repo root with:
 *
 * <pre>
 *   env -u GH_TOKEN -u GITHUB_TOKEN gh api -H 'Accept: application/vnd.github.raw' \
 *     'repos/hugmesh/hugmesh-generator/contents/specs/cluster/manifests/route-access/initdb/20-schema.sql?ref=main' \
 *     &gt; src/test/resources/route-access/generator-20-schema.sql
 *   git hash-object src/test/resources/route-access/generator-20-schema.sql   # -&gt; new VENDORED_BLOB
 *   env -u GH_TOKEN -u GITHUB_TOKEN gh api repos/hugmesh/hugmesh-generator/commits/main --jq .sha   # -&gt; VENDORED_COMMIT
 * </pre>
 *
 * then update {@link #VENDORED_BLOB} / {@link #VENDORED_COMMIT} and make
 * {@link CanonicalSeed} (or, with a decision to point at, the divergence lists)
 * match whatever this test then reports.
 */
class CanonicalSeedSqlSyncTest {

    static final String VENDORED_COMMIT = "c9fb3e98285524e3f8ced8370ed3a769aa9128cd";
    static final String VENDORED_BLOB = "12c492e65d0d87f289639f5b4327b2ec8f7bcd58";
    private static final String RESOURCE = "/route-access/generator-20-schema.sql";

    private static final String PKI = CanonicalSeed.PKI;
    private static final String BE = CanonicalSeed.BE;
    private static final String FE = CanonicalSeed.FE;

    /** One row in the comparable shape: the four columns the seed INSERT sets. */
    record Key(String gateway, String pattern, String role, boolean allow) {
        @Override public String toString() {
            return "(" + gateway + ", " + pattern + ", " + role + ", " + (allow ? "allow" : "DENY") + ")";
        }
    }

    /**
     * Cluster-seed rows deliberately NOT baked. Each is pinned by its own test too.
     */
    static final Map<Key, String> SQL_ONLY = Map.of(
            new Key(PKI, "/**", "ROLE_SUPERADMIN", true),
            "decision 79 = B: headscale's SUPERADMIN floor moved to SecurityConfig's Host gate; "
            + "no seed ships a bare /** row (noSeed_shipsABareDoubleStarRow_zeroExceptions)",
            new Key(FE, "/social/matrix/**", "ROLE_USER", true),
            "the fe social shells stay congruent with the be platform gates "
            + "(canonicalSeed_feGateway_socialShellsGatedByPlatformRoles)",
            new Key(FE, "/social/mastodon/**", "ROLE_USER", true),
            "the fe social shells stay congruent with the be platform gates "
            + "(canonicalSeed_feGateway_socialShellsGatedByPlatformRoles)",
            new Key(FE, "/bff/superadmin/games-services/**", "ROLE_SUPERADMIN", false),
            "decision 41 authorises only the platform /bff/superadmin/** row; mirroring the decision-28 "
            + "deny row was asked and answered NO on hugmesh-generator#347 "
            + "(canonicalSeed_feGateway_superadminRow_shapeMatchesTheClusterSeed_andCarriesNoGamesServicesRefinement)");

    /** Baked rows the cluster seed does not carry. */
    static final Set<Key> SEED_ONLY = Set.of(
            // the be issuance gate: wildcard-version patterns with ROLE_MOD paired
            // (canonicalSeed_beGateway_externalClientIssuanceRows_presentAndPaired)
            new Key(BE, "/_matrix/client/*/login/**", "ROLE_MATRIX_EXTERNAL_CLIENT", true),
            new Key(BE, "/_matrix/client/*/login/**", "ROLE_MOD", true),
            new Key(BE, "/_matrix/client/*/register/**", "ROLE_MATRIX_EXTERNAL_CLIENT", true),
            new Key(BE, "/_matrix/client/*/register/**", "ROLE_MOD", true),
            new Key(BE, "/api/v1/apps", "ROLE_MOD", true),
            new Key(BE, "/oauth/authorize/**", "ROLE_MASTODON_EXTERNAL_CLIENT", true),
            new Key(BE, "/oauth/authorize/**", "ROLE_MOD", true),
            new Key(BE, "/oauth/token", "ROLE_MASTODON_EXTERNAL_CLIENT", true),
            new Key(BE, "/oauth/token", "ROLE_MOD", true),
            // the fe social shells' platform-role gate (see SQL_ONLY)
            new Key(FE, "/social/matrix/**", "ROLE_MATRIX", true),
            new Key(FE, "/social/matrix/**", "ROLE_MOD", true),
            new Key(FE, "/social/mastodon/**", "ROLE_MASTODON", true),
            new Key(FE, "/social/mastodon/**", "ROLE_MOD", true));

    /** The seed's row-scoped decision-28 UPDATE, whitespace-normalised. */
    static final String TARGETED_MFA_UPDATE =
            "UPDATE gateway_route_access SET mfa_required = true WHERE gateway = 'hugmesh-fe-gateway' "
            + "AND url_pattern = '/bff/superadmin/games-services/**' AND role = 'ROLE_SUPERADMIN' "
            + "AND allow = false AND mfa_required IS DISTINCT FROM true;";
    /** The seed's blanket flip UPDATE, whitespace-normalised. {@link #flip} is its Java form. */
    static final String BLANKET_MFA_UPDATE =
            "UPDATE gateway_route_access SET mfa_required = true WHERE allow = true "
            + "AND (url_pattern = '/bff/admin' OR url_pattern LIKE '/bff/admin/%' "
            + "OR url_pattern LIKE '/bff/%/admin/%' OR url_pattern = '/bff/superadmin' "
            + "OR url_pattern LIKE '/bff/superadmin/%' OR url_pattern LIKE '/bff/%/superadmin/%' "
            + "OR (COALESCE(NULLIF(lower(trim(domain)), 'default'), '') <> '' AND url_pattern IN (''))) "
            + "AND mfa_required IS DISTINCT FROM true;";

    /** {@link #BLANKET_MFA_UPDATE}'s predicate. Every seed row is unscoped, so its
     *  domain clause never applies; SQL LIKE '%' is any run of characters. */
    static boolean flip(Key k) {
        String p = k.pattern();
        return k.allow() && (p.equals("/bff/admin") || p.matches("/bff/admin/.*")
                || p.matches("/bff/.*/admin/.*") || p.equals("/bff/superadmin")
                || p.matches("/bff/superadmin/.*") || p.matches("/bff/.*/superadmin/.*"));
    }

    static boolean targeted(Key k) {
        return k.equals(new Key(FE, "/bff/superadmin/games-services/**", "ROLE_SUPERADMIN", false));
    }

    // ── reading the vendored seed ───────────────────────────────────────────────

    static byte[] vendoredBytes() {
        try (InputStream in = CanonicalSeedSqlSyncTest.class.getResourceAsStream(RESOURCE)) {
            assertThat(in).as("vendored seed %s on the test classpath", RESOURCE).isNotNull();
            return in.readAllBytes();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static String vendored() {
        return new String(vendoredBytes(), StandardCharsets.UTF_8);
    }

    /** The vendored seed with every {@code --} comment removed (no seed value
     *  contains {@code --}), so prose that quotes SQL is never parsed as SQL. */
    static String vendoredStatements() {
        return vendored().replaceAll("--[^\n]*", "");
    }

    private static final Pattern ROW = Pattern.compile(
            "^\\s*\\('([^']*)',\\s*'([^']*)',\\s*'([^']*)',\\s*(true|false)\\)");

    /** Every row of the seed's single {@code INSERT ... VALUES ... ON CONFLICT} statement. */
    static List<Key> sqlRows() {
        String sql = vendoredStatements();
        String head = "INSERT INTO gateway_route_access (gateway, url_pattern, role, allow) VALUES";
        assertThat(sql.indexOf(head)).as("the seed INSERT is present").isNotNegative();
        assertThat(sql.indexOf(head)).as("exactly ONE seed INSERT (a second one is not parsed)")
                .isEqualTo(sql.lastIndexOf(head));
        assertThat(sql.split("INSERT INTO", -1).length - 1)
                .as("no other INSERT statement in the file").isEqualTo(1);
        int start = sql.indexOf(head) + head.length();
        int end = sql.indexOf("\nON CONFLICT", start);
        assertThat(end).isPositive();
        List<Key> rows = new ArrayList<>();
        int tupleLines = 0;
        for (String line : sql.substring(start, end).split("\n")) {
            if (!line.trim().startsWith("(")) continue;
            tupleLines++;
            Matcher m = ROW.matcher(line);
            if (m.find()) rows.add(new Key(m.group(1), m.group(2), m.group(3), Boolean.parseBoolean(m.group(4))));
        }
        assertThat(rows).as("parser self-check: every tuple line of the INSERT parsed").hasSize(tupleLines);
        return rows;
    }

    static Map<Key, Rule> seedRows() {
        return Stream.of(PKI, BE, FE)
                .flatMap(gw -> CanonicalSeed.forGateway(gw).stream())
                .collect(Collectors.toMap(
                        r -> new Key(r.gateway(), r.urlPattern(), r.role(), r.allow()),
                        Function.identity(),
                        (a, b) -> { throw new AssertionError("duplicate baked row " + a.id()); }));
    }

    private static String normalised(String s) {
        return s.replaceAll("\\s+", " ").trim();
    }

    // ── the tests ───────────────────────────────────────────────────────────────

    @Test
    void vendoredCopy_isTheRecordedGeneratorBlob() throws Exception {
        byte[] body = vendoredBytes();
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(("blob " + body.length + "\0").getBytes(StandardCharsets.US_ASCII));
        sha1.update(body);
        assertThat(HexFormat.of().formatHex(sha1.digest()))
                .as("the vendored seed was edited by hand, or refreshed without updating VENDORED_BLOB")
                .isEqualTo(VENDORED_BLOB);
    }

    @Test
    void parser_findsEveryRowOfTheThreeGatewayTiers() {
        List<Key> rows = sqlRows();
        assertThat(rows).isNotEmpty();
        assertThat(rows.stream().filter(k -> List.of(PKI, BE, FE).contains(k.gateway())).count())
                .as("a seed with no pki/be/fe rows would make every comparison vacuous")
                .isGreaterThan(100);
        assertThat(new HashSet<>(rows)).as("the seed INSERT carries no duplicate rows").hasSameSizeAs(rows);
    }

    @Test
    void everyClusterSeedRow_isBaked_exceptTheNamedDivergences() {
        Set<Key> sql = sqlRows().stream()
                .filter(k -> List.of(PKI, BE, FE).contains(k.gateway()))
                .collect(Collectors.toSet());
        Set<Key> missing = new TreeSet<>(java.util.Comparator.comparing(Key::toString));
        missing.addAll(sql);
        missing.removeAll(seedRows().keySet());
        assertThat(missing)
                .as("cluster-seed rows missing from CanonicalSeed (bake them, or name the divergence and its decision)")
                .containsExactlyInAnyOrderElementsOf(SQL_ONLY.keySet());
    }

    @Test
    void everyBakedRow_isAClusterSeedRow_exceptTheNamedDivergences() {
        Set<Key> sql = new HashSet<>(sqlRows());
        Set<Key> extra = new TreeSet<>(java.util.Comparator.comparing(Key::toString));
        extra.addAll(seedRows().keySet());
        extra.removeAll(sql);
        assertThat(extra)
                .as("baked rows the cluster seed does not carry")
                .containsExactlyInAnyOrderElementsOf(SEED_ONLY);
    }

    @Test
    void mfaUpdates_areTheOnesThisTestDerivesFrom() {
        String sql = normalised(vendoredStatements());
        assertThat(sql)
                .as("the seed's UPDATE statements changed: re-derive flip()/targeted() and the declared set")
                .contains(normalised(TARGETED_MFA_UPDATE))
                .contains(normalised(BLANKET_MFA_UPDATE));
        assertThat(sql.split("SET mfa_required = true", -1).length - 1)
                .as("no other statement sets mfa_required").isEqualTo(2);
    }

    @Test
    void everyBakedRow_carriesTheMfaRequiredTheClusterSeedSetsOnIt() {
        Set<Key> sql = new HashSet<>(sqlRows());
        for (Map.Entry<Key, Rule> e : seedRows().entrySet()) {
            Key k = e.getKey();
            if (!sql.contains(k)) continue;   // SEED_ONLY rows: none is under the flip (asserted below)
            assertThat(e.getValue().mfaRequired())
                    .as("mfa_required of %s", k)
                    .isEqualTo(flip(k) || targeted(k));
        }
        for (Key k : SEED_ONLY) {
            assertThat(flip(k)).as("a seed-only row under the flip would need its own decision: %s", k).isFalse();
        }
    }

    @Test
    void declaredMfaSet_isExactlyTheFlipAppliedToTheBakedAllowRows() {
        Set<String> derived = seedRows().entrySet().stream()
                .filter(e -> flip(e.getKey()))
                .map(e -> e.getValue().id())
                .collect(Collectors.toCollection(TreeSet::new));
        assertThat(new TreeSet<>(CanonicalSeed.MFA_REQUIRED_FALLBACK_ROWS)).isEqualTo(derived);
    }

    @Test
    void namedDivergences_areStillReal() {
        Set<Key> sql = new HashSet<>(sqlRows());
        Set<Key> baked = seedRows().keySet();
        for (Key k : SQL_ONLY.keySet()) {
            assertThat(sql).as("SQL_ONLY entry %s is no longer in the cluster seed: drop it", k).contains(k);
            assertThat(baked).as("SQL_ONLY entry %s is baked after all: drop it", k).doesNotContain(k);
        }
        for (Key k : SEED_ONLY) {
            assertThat(baked).as("SEED_ONLY entry %s is no longer baked: drop it", k).contains(k);
            assertThat(sql).as("SEED_ONLY entry %s is in the cluster seed now: drop it", k).doesNotContain(k);
        }
    }
}
