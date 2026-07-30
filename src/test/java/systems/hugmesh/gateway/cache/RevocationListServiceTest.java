package systems.hugmesh.gateway.cache;

import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;
import systems.hugmesh.gateway.cache.RevocationListService.HsToken;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit coverage for the account-states additions to the (formerly read-only)
 * revocation service: the {@code hs_tokens} lookup seam and the {@code revoke} /
 * {@code clear} WRITE primitives' input-guard + no-Cassandra behaviour. The
 * wire-level CQL (INSERT … USING TTL / DELETE applying against a live cluster)
 * is an integration concern; here we pin the contract reachable without a
 * datastore.
 */
class RevocationListServiceTest {

    private RevocationListService svc() {
        // null template -> cql == null; enabled=true exercises the not-wired
        // branch of the write primitives (init() early-returns on cql == null).
        return new RevocationListService(null, true);
    }

    @Test
    void hsTokenFor_resolvesPrimedHash_andNullForUnknown() {
        var svc = svc();
        svc.primeHsTokensForTest(Map.of(
                "hash-1", new HsToken("alice", "matrix", "brokered", "dev1")));
        assertThat(svc.hsTokenFor("hash-1"))
                .isEqualTo(new HsToken("alice", "matrix", "brokered", "dev1"));
        assertThat(svc.hsTokenFor("nope")).isNull();
        assertThat(svc.hsTokenFor(null)).isNull();
    }

    @Test
    void isRevoked_reflectsPrimedKeys() {
        var svc = svc();
        svc.primeRevokedForTest(Set.of("hs:matrix:alice", "external-client:bob:mastodon"));
        assertThat(svc.isRevoked("hs:matrix:alice")).isTrue();
        assertThat(svc.isRevoked("external-client:bob:mastodon")).isTrue();
        assertThat(svc.isRevoked("hs:matrix:carol")).isFalse();
        assertThat(svc.isRevoked(null)).isFalse();
    }

    @Test
    void revoke_blankKey_errors() {
        StepVerifier.create(svc().revoke("  ", "reason", 60))
                .expectError(IllegalArgumentException.class)
                .verify();
        StepVerifier.create(svc().revoke(null, "reason", 60))
                .expectError(IllegalArgumentException.class)
                .verify();
    }

    @Test
    void clear_blankKey_errors() {
        StepVerifier.create(svc().clear(""))
                .expectError(IllegalArgumentException.class)
                .verify();
    }

    @Test
    void revoke_withoutCassandra_isNoOp_completesEmpty() {
        // No Cassandra wired -> the write is logged and skipped, NOT an error,
        // so a misconfigured/dev pod degrades to "cannot persist" rather than
        // failing every revoke call.
        StepVerifier.create(svc().revoke("hs:matrix:alice", "ban", 3600)).verifyComplete();
    }

    @Test
    void clear_withoutCassandra_isNoOp_completesEmpty() {
        StepVerifier.create(svc().clear("hs:matrix:alice")).verifyComplete();
    }

    @Test
    void snapshot_reflectsPrimedKeys() {
        var svc = svc();
        svc.primeRevokedForTest(Set.of("hs:matrix:alice", "subject:bob-123"));
        var snap = svc.snapshot();
        assertThat(snap).containsExactlyInAnyOrder("hs:matrix:alice", "subject:bob-123");
    }

    @Test
    void snapshot_emptyWhenNothingPrimed() {
        assertThat(svc().snapshot()).isEmpty();
    }

    @Test
    void snapshot_returnsDifferentReferenceAfterPrime() {
        // snapshot() returns the current volatile reference; a subsequent prime yields
        // a different reference so callers cannot mutate the live set via the snapshot.
        var svc = svc();
        var before = svc.snapshot();
        svc.primeRevokedForTest(Set.of("hs:matrix:alice"));
        var after = svc.snapshot();
        assertThat(before).isNotSameAs(after);
        assertThat(before).isEmpty();
        assertThat(after).containsExactly("hs:matrix:alice");
    }

    @Test
    void domainOfKey_reflectsPrimedOwner_andNullForUnscopedOrUnknown() {
        // The per-key owning-domain accessor the cross-tenant revocation gate
        // (CWE-639) consults. A primed branded owner is returned; an un-primed
        // (unscoped/legacy) key and an unknown key both return null.
        var svc = svc();
        svc.primeKeyDomainsForTest(Map.of("subject:brandy-user", "brandy"));
        assertThat(svc.domainOfKey("subject:brandy-user")).isEqualTo("brandy");
        assertThat(svc.domainOfKey("subject:legacy-user")).isNull();   // unscoped
        assertThat(svc.domainOfKey("subject:never-seen")).isNull();    // unknown
        assertThat(svc.domainOfKey(null)).isNull();
    }
}
