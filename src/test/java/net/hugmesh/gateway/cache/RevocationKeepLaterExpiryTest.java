package net.hugmesh.gateway.cache;

import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;
import net.hugmesh.gateway.cache.FakeRevocationsCassandra.StoredRow;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A revocation can be extended, never shortened (hugmesh-gateway: keep the later expiry).
 *
 * <p>Several admin-bff writers share {@code subject:<user>}: account-disable and role revoke
 * write a 168 h cut-off, role grant writes 1 h (only to force a re-mint), and an active
 * suspension re-writes 1 h every reconcile tick. With the old unconditional
 * {@code INSERT … USING TTL} the last write won, so an ordinary demotion (revoke ADMIN, then
 * grant MOD) or a suspension tick after an account-disable cut the 168 h key to 1 h and the
 * stale token was accepted again an hour later. These tests drive the real
 * {@link RevocationListService} against an in-memory table with Cassandra's
 * lightweight-transaction semantics ({@link FakeRevocationsCassandra}); the live proof against
 * a real Cassandra is {@code RevocationKeepLaterExpiryLiveTest}.
 */
class RevocationKeepLaterExpiryTest {

    private static final long CUTOFF = 604_800L;   // 168 h
    private static final long GRANT = 3_600L;      // 1 h

    private final FakeRevocationsCassandra db = new FakeRevocationsCassandra();

    private RevocationListService svc() {
        return new RevocationListService(db.template(), true);
    }

    private static void ok(reactor.core.publisher.Mono<Void> write) {
        StepVerifier.create(write).verifyComplete();
    }

    @Test
    void firstWrite_storesTheRequestedTtlAndAnExpiryToMatch() {
        var svc = svc();
        ok(svc.revoke("subject:carol", "role-revoke", CUTOFF));

        StoredRow row = db.row("subject:carol");
        assertThat(row.ttl()).isEqualTo((int) CUTOFF);
        assertThat(row.reason()).isEqualTo("role-revoke");
        assertThat(Duration.between(row.revokedAt(), row.expiresAt())).isEqualTo(Duration.ofSeconds(CUTOFF));
        assertThat(svc.isRevoked("subject:carol")).isTrue();
    }

    @Test
    void demotion_aGrantAfterARevokeDoesNotShortenTheCutOff() {
        var svc = svc();
        ok(svc.revoke("subject:carol", "role-revoke", CUTOFF));   // DELETE /bff/admin/roles/ROLE_ADMIN/carol
        StoredRow cutOff = db.row("subject:carol");

        ok(svc.revoke("subject:carol", "role-grant", GRANT));     // POST /bff/admin/roles/ROLE_MOD/carol

        StoredRow after = db.row("subject:carol");
        assertThat(after.ttl()).as("TTL after the grant").isEqualTo((int) CUTOFF);
        assertThat(after.expiresAt()).isEqualTo(cutOff.expiresAt());
        assertThat(after.reason()).isEqualTo("role-revoke");
        assertThat(svc.reasonFor("subject:carol")).isEqualTo("role-revoke");
    }

    @Test
    void suspensionTicksAfterAnAccountDisableDoNotShortenIt() {
        var svc = svc();
        ok(svc.revoke("subject:erin", "account-disable", CUTOFF));
        StoredRow cutOff = db.row("subject:erin");
        for (int tick = 0; tick < 3; tick++) {
            ok(svc.revoke("subject:erin", "suspended: spam", GRANT));
        }
        assertThat(db.row("subject:erin")).isEqualTo(cutOff);
    }

    @Test
    void aSevenDayRevocationIsNotOverwrittenByAFiveSecondOne() {
        var svc = svc();
        ok(svc.revoke("subject:dave", "account-disable", CUTOFF));
        ok(svc.revoke("subject:dave", "role-grant", 5));
        assertThat(db.row("subject:dave").ttl()).isEqualTo((int) CUTOFF);
    }

    @Test
    void aLongerWriteExtendsTheKey() {
        var svc = svc();
        ok(svc.revoke("subject:frank", "role-grant", GRANT));
        ok(svc.revoke("subject:frank", "role-revoke", CUTOFF));

        StoredRow row = db.row("subject:frank");
        assertThat(row.ttl()).isEqualTo((int) CUTOFF);
        assertThat(row.reason()).isEqualTo("role-revoke");
        assertThat(Duration.between(row.revokedAt(), row.expiresAt())).isEqualTo(Duration.ofSeconds(CUTOFF));
        assertThat(svc.reasonFor("subject:frank")).isEqualTo("role-revoke");
    }

    @Test
    void aKeptRowKeepsItsOwnReasonAndOwnerInTheLocalCache() {
        var svc = svc();
        ok(svc.revoke("subject:gina", "account-disable", CUTOFF, "brandy"));
        // A shorter write from a SUPERADMIN (no owning domain) must not re-label the row
        // on this pod either: the cross-tenant gate reads the owner from this cache.
        ok(svc.revoke("subject:gina", "role-grant", GRANT, null));

        assertThat(db.row("subject:gina").domain()).isEqualTo("brandy");
        assertThat(svc.domainOfKey("subject:gina")).isEqualTo("brandy");
        assertThat(svc.reasonFor("subject:gina")).isEqualTo("account-disable");
    }

    @Test
    void aNonPositiveTtlIsWrittenAsTheTableDefaultWithAnExpiry() {
        ok(svc().revoke("hs:matrix:alice", "ban", 0));
        StoredRow row = db.row("hs:matrix:alice");
        assertThat(row.ttl()).isEqualTo((int) RevocationListService.TABLE_DEFAULT_TTL_SECONDS);
        assertThat(row.expiresAt()).isNotNull();
        assertThat(Duration.between(row.revokedAt(), row.expiresAt()))
                .isEqualTo(Duration.ofSeconds(RevocationListService.TABLE_DEFAULT_TTL_SECONDS));
    }

    @Test
    void aRowWithoutAnExpiry_isMeasuredByItsRemainingTtl() {
        // Written by an older gateway with ttlSeconds <= 0: no expires_at, table-default TTL.
        Instant then = Instant.now().minusSeconds(60);
        db.rows.put("subject:hank", new StoredRow("account-disable", then, null, null, 86_340));
        var svc = svc();

        ok(svc.revoke("subject:hank", "role-grant", GRANT));
        assertThat(db.row("subject:hank").ttl()).as("1 h must not replace ~24 h").isEqualTo(86_340);
        assertThat(db.row("subject:hank").reason()).isEqualTo("account-disable");

        ok(svc.revoke("subject:hank", "role-revoke", CUTOFF));
        assertThat(db.row("subject:hank").ttl()).as("168 h extends it").isEqualTo((int) CUTOFF);
        assertThat(db.row("subject:hank").expiresAt()).isNotNull();
    }

    @Test
    void aRowWithNoTtlAtAll_neverCountsAsShorter() {
        db.rows.put("subject:ivy", new StoredRow("manual", Instant.now(), null, null, null));
        ok(svc().revoke("subject:ivy", "role-revoke", CUTOFF));
        assertThat(db.row("subject:ivy").reason()).isEqualTo("manual");
        assertThat(db.row("subject:ivy").ttl()).isNull();
    }

    @Test
    void aRowWithoutAnExpiryThatLapsesBeforeItsTtlIsRead_isWrittenAfresh() {
        db.rows.put("subject:hal", new StoredRow("ban", Instant.now(), null, null, 2));
        db.beforeTtlRead = db.rows::remove;   // it expires (or is cleared) right then

        ok(svc().revoke("subject:hal", "role-revoke", CUTOFF));

        assertThat(db.row("subject:hal")).isNotNull();
        assertThat(db.row("subject:hal").reason()).isEqualTo("role-revoke");
        assertThat(db.row("subject:hal").ttl()).isEqualTo((int) CUTOFF);
    }

    @Test
    void anotherPodExtendingTheKeyBetweenReadAndWrite_wins() {
        var svc = svc();
        ok(svc.revoke("subject:jo", "role-grant", GRANT));
        // Between this pod's read and its compare-and-set, another pod writes a cut-off.
        Instant later = Instant.now().plusSeconds(CUTOFF);
        AtomicInteger interleaved = new AtomicInteger();
        db.beforeConditionalUpdate = key -> {
            if (interleaved.getAndIncrement() == 0) {
                db.rows.put(key, new StoredRow("account-disable", Instant.now(), later, null, (int) CUTOFF));
            }
        };

        ok(svc.revoke("subject:jo", "suspended", 86_400L));

        assertThat(interleaved.get()).as("the compare-and-set ran").isGreaterThanOrEqualTo(1);
        StoredRow row = db.row("subject:jo");
        assertThat(row.expiresAt()).isEqualTo(later);
        assertThat(row.ttl()).isEqualTo((int) CUTOFF);
        assertThat(row.reason()).isEqualTo("account-disable");
    }

    @Test
    void losingTheCompareAndSetEveryTime_failsAndNeverWritesUnconditionally() {
        var svc = svc();
        ok(svc.revoke("subject:kim", "role-grant", GRANT));
        // A competing writer moves the expiry on every round, always to just short of ours,
        // so each round still wants to write and each compare-and-set loses.
        AtomicInteger rounds = new AtomicInteger();
        db.beforeConditionalUpdate = key -> {
            rounds.incrementAndGet();
            StoredRow cur = db.rows.get(key);
            db.rows.put(key, new StoredRow("competitor", cur.revokedAt(),
                    cur.expiresAt().plusMillis(1), null, cur.ttl()));
        };
        int writesBefore = db.writes().size();

        StepVerifier.create(svc.revoke("subject:kim", "role-revoke", CUTOFF))
                .expectError(IllegalStateException.class)
                .verify();

        assertThat(rounds.get()).isEqualTo(RevocationListService.MAX_CAS_ATTEMPTS);
        assertThat(db.row("subject:kim").reason()).isEqualTo("competitor");
        assertThat(db.writes().subList(writesBefore, db.writes().size()))
                .as("every write in the failed call was conditional")
                .allMatch(s -> s.contains(" IF "));
    }

    @Test
    void everyWriteToTheTableIsALightweightTransaction() {
        var svc = svc();
        ok(svc.revoke("subject:lee", "role-grant", GRANT));
        ok(svc.revoke("subject:lee", "role-revoke", CUTOFF));
        ok(svc.revoke("subject:lee", "role-grant", GRANT));
        ok(svc.clear("subject:lee"));

        assertThat(db.writes()).isNotEmpty()
                .allSatisfy(s -> assertThat(s).contains(" IF "));
    }

    @Test
    void clear_liftsTheKeyEarly() {
        var svc = svc();
        ok(svc.revoke("hs:matrix:alice", "suspended", CUTOFF));
        ok(svc.clear("hs:matrix:alice"));
        assertThat(db.row("hs:matrix:alice")).isNull();
        assertThat(svc.isRevoked("hs:matrix:alice")).isFalse();

        // And a key that was cleared can be written again from scratch, shorter or not.
        ok(svc.revoke("hs:matrix:alice", "logout", GRANT));
        assertThat(db.row("hs:matrix:alice").ttl()).isEqualTo((int) GRANT);
    }
}
