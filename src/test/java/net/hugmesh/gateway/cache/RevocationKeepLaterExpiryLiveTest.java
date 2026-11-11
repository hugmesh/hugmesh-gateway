package net.hugmesh.gateway.cache;

import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.cql.Row;
import com.datastax.oss.driver.api.core.config.DefaultDriverOption;
import com.datastax.oss.driver.api.core.config.DriverConfigLoader;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.data.cassandra.core.ReactiveCassandraTemplate;
import org.springframework.data.cassandra.core.cql.session.DefaultBridgedReactiveSession;
import reactor.core.publisher.Flux;
import reactor.core.scheduler.Schedulers;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Live proof, against a real Cassandra, that a revocation key can be extended but never
 * shortened. Runs only when {@code REVOCATION_LIVE_CASSANDRA=host:port} names a throwaway
 * Cassandra (it creates and drops its own keyspace there); otherwise it is skipped. The
 * schema is the gateway's own: {@link CassandraSchemaMigrations} runs against a fresh
 * keyspace exactly as at boot.
 *
 * <p>This covers what the in-memory fake in {@link RevocationKeepLaterExpiryTest} cannot:
 * the real lightweight-transaction results, per-cell TTLs, a row whose INSERT row marker
 * has expired while the cells an UPDATE extended live on, and concurrent writers.
 *
 * <p>Uses only API that predates the fix, so the same class runs against the old service
 * to show the defect: the demotion, the suspension, the 5-second and the legacy-row cases
 * fail there.
 *
 * <p>{@code scripts/test-revocation-keep-later-expiry-live.sh} starts a pinned Cassandra on a
 * private network, runs this class, and removes both.
 */
@EnabledIfEnvironmentVariable(named = "REVOCATION_LIVE_CASSANDRA", matches = ".+")
class RevocationKeepLaterExpiryLiveTest {

    private static final long CUTOFF = 604_800L;
    private static final long GRANT = 3_600L;
    /** Schema changes on a node that has just started take longer than the driver's 2 s default. */
    private static DriverConfigLoader slowNode() {
        return DriverConfigLoader.programmaticBuilder()
                .withDuration(DefaultDriverOption.REQUEST_TIMEOUT, Duration.ofSeconds(60))
                .build();
    }

    private static CqlSession admin;
    private static CqlSession session;
    private static ReactiveCassandraTemplate template;
    private static String keyspace;

    @BeforeAll
    static void connect() {
        String[] hp = System.getenv("REVOCATION_LIVE_CASSANDRA").split(":");
        InetSocketAddress addr = new InetSocketAddress(hp[0], Integer.parseInt(hp[1]));
        String dc = System.getenv().getOrDefault("REVOCATION_LIVE_CASSANDRA_DC", "datacenter1");
        keyspace = "revocation_live_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        admin = CqlSession.builder().withConfigLoader(slowNode()).addContactPoint(addr)
                .withLocalDatacenter(dc).build();
        admin.execute("CREATE KEYSPACE " + keyspace
                + " WITH replication = {'class':'SimpleStrategy','replication_factor':1}");
        session = CqlSession.builder().withConfigLoader(slowNode()).addContactPoint(addr)
                .withLocalDatacenter(dc).withKeyspace(keyspace).build();
        template = new ReactiveCassandraTemplate(new DefaultBridgedReactiveSession(session));
        new CassandraSchemaMigrations(template.getReactiveCqlOperations()).applyAll().block(Duration.ofSeconds(60));
    }

    @AfterAll
    static void dropKeyspace() {
        if (session != null) session.close();
        if (admin != null) {
            admin.execute("DROP KEYSPACE IF EXISTS " + keyspace);
            admin.close();
        }
    }

    /** A gateway pod. Each call is a separate instance, as separate pods would be. */
    private static RevocationListService pod() {
        return new RevocationListService(template, true);
    }

    /** What a pod that boots now would enforce: a fresh instance, primed from Cassandra. */
    private static boolean freshPodRefuses(String key) throws InterruptedException {
        RevocationListService fresh = pod();
        fresh.init();
        for (int i = 0; i < 100 && !fresh.isPrimed(); i++) Thread.sleep(50);
        assertThat(fresh.isPrimed()).as("fresh pod primed from Cassandra").isTrue();
        return fresh.isRevoked(key);
    }

    private static Row stored(String key) {
        return session.execute("SELECT reason, expires_at, TTL(revoked_at) AS ttl_left "
                + "FROM revocations WHERE revocation_key = ?", key).one();
    }

    private static int ttlLeft(String key) {
        Row r = stored(key);
        assertThat(r).as("row for " + key).isNotNull();
        return r.getInt("ttl_left");
    }

    private static void write(RevocationListService pod, String key, String reason, long ttl) {
        pod.revoke(key, reason, ttl).block(Duration.ofSeconds(30));
    }

    private static String unique(String name) {
        return "subject:" + name + "-" + UUID.randomUUID().toString().substring(0, 8);
    }

    @Test
    void demotion_revokeThenGrant_keepsTheSevenDayCutOff() {
        String carol = unique("carol");
        write(pod(), carol, "role-revoke", CUTOFF);   // DELETE /bff/admin/roles/ROLE_ADMIN/carol
        write(pod(), carol, "role-grant", GRANT);     // POST /bff/admin/roles/ROLE_MOD/carol

        int ttl = ttlLeft(carol);
        System.out.println("LIVE demotion: TTL after revoke(604800) then grant(3600) = " + ttl);
        assertThat(ttl).as("TTL after the grant").isGreaterThan((int) CUTOFF - 120);
        assertThat(stored(carol).getString("reason")).isEqualTo("role-revoke");
    }

    @Test
    void sevenDayRevocation_overwrittenByFiveSeconds_isStillEnforcedAfterSeven() throws Exception {
        String dave = unique("dave");
        write(pod(), dave, "account-disable", CUTOFF);
        write(pod(), dave, "role-grant", 5);
        Thread.sleep(7_000);

        boolean refused = freshPodRefuses(dave);
        System.out.println("LIVE 7d-then-5s: after 7 s, row present=" + (stored(dave) != null)
                + ", fresh pod refuses=" + refused);
        assertThat(stored(dave)).as("row 7 s after a 5 s write").isNotNull();
        assertThat(refused).isTrue();
        assertThat(ttlLeft(dave)).isGreaterThan((int) CUTOFF - 120);
    }

    @Test
    void suspensionTicksAfterAccountDisable_doNotShortenIt() {
        String erin = unique("erin");
        write(pod(), erin, "account-disable", CUTOFF);
        for (int tick = 0; tick < 3; tick++) write(pod(), erin, "suspended: spam", GRANT);

        int ttl = ttlLeft(erin);
        System.out.println("LIVE disable+suspension ticks: TTL = " + ttl);
        assertThat(ttl).isGreaterThan((int) CUTOFF - 120);
        assertThat(stored(erin).getString("reason")).isEqualTo("account-disable");
    }

    @Test
    void anExtendedKeyOutlivesItsFirstRowMarker_andStillCannotBeShortened() throws Exception {
        // The first write is an INSERT (row marker, TTL 5); the extension is an UPDATE, which
        // re-writes every cell with TTL 60 but not the marker. After 7 s only the cells hold
        // the row up: it must still be read, still be enforced, and still count as existing
        // for the next conditional insert.
        String key = unique("marker");
        write(pod(), key, "first", 5);
        write(pod(), key, "extended", 60);
        Thread.sleep(7_000);

        assertThat(freshPodRefuses(key)).as("enforced after the marker expired").isTrue();
        write(pod(), key, "shorter", 10);
        int ttl = ttlLeft(key);
        System.out.println("LIVE row-marker: TTL after 5 -> 60, 7 s, then 10 = " + ttl);
        assertThat(ttl).isGreaterThan(40);
        assertThat(stored(key).getString("reason")).isEqualTo("extended");
    }

    @Test
    void aRowWithoutExpiry_fromTheOldWriteShape_isNotShortened_andCanBeExtended() {
        // What the old revoke wrote for ttlSeconds <= 0: no expires_at, table-default TTL.
        String key = unique("legacy");
        session.execute("INSERT INTO revocations (revocation_key, reason, revoked_at, expires_at, domain) "
                + "VALUES (?, 'ban', toTimestamp(now()), null, null)", key);
        write(pod(), key, "role-grant", GRANT);
        assertThat(ttlLeft(key)).as("1 h must not replace the ~24 h row").isGreaterThan(86_400 - 120);
        assertThat(stored(key).getString("reason")).isEqualTo("ban");

        write(pod(), key, "role-revoke", CUTOFF);
        assertThat(ttlLeft(key)).isGreaterThan((int) CUTOFF - 120);
        assertThat(stored(key).getInstant("expires_at")).isNotNull();
    }

    @Test
    void concurrentWritersFromSeveralPods_endAtTheLatestExpiry() {
        String key = unique("race");
        List<Long> ttls = new ArrayList<>();
        for (int i = 0; i < 23; i++) ttls.add(i % 2 == 0 ? GRANT : 300L + i);
        ttls.add(CUTOFF);
        Collections.shuffle(ttls);
        List<RevocationListService> pods = List.of(pod(), pod(), pod(), pod());

        Flux.range(0, ttls.size())
                .flatMap(i -> pods.get(i % pods.size()).revoke(key, "w" + i, ttls.get(i))
                        .subscribeOn(Schedulers.boundedElastic()), 24)
                .then()
                .block(Duration.ofSeconds(120));

        int ttl = ttlLeft(key);
        System.out.println("LIVE race: 24 writers, 1 of them 604800, final TTL = " + ttl);
        assertThat(ttl).isGreaterThan((int) CUTOFF - 120);
    }

    @Test
    void clear_stillLiftsAKeyEarly() throws Exception {
        String key = unique("cleared");
        write(pod(), key, "suspended", CUTOFF);
        pod().clear(key).block(Duration.ofSeconds(30));
        assertThat(stored(key)).isNull();
        assertThat(freshPodRefuses(key)).isFalse();
    }
}
