package net.hugmesh.gateway.filter;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.gateway.cache.RevocationListService;
import net.hugmesh.gateway.cache.RevocationListService.HsToken;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Behaviour contract for the homeserver-token revocation gate (PREREQ P1). Built
 * with a {@link RevocationListService} primed via its test seams (no live
 * Cassandra) so this exercises the pure resolve-bearer → check-keys → allow/deny
 * logic, the {@code kind=personal}-only external-client rule, the fail-closed
 * posture on unknown tokens, the discovery exemption, and the enabled flag.
 */
class HomeserverTokenRevocationFilterTest {

    /** A recording chain — flips a flag when the request is forwarded downstream. */
    private static final class RecordingChain implements WebFilterChain {
        final AtomicBoolean forwarded = new AtomicBoolean(false);
        @Override public Mono<Void> filter(org.springframework.web.server.ServerWebExchange exchange) {
            forwarded.set(true);
            return Mono.empty();
        }
    }

    private RevocationListService revocations(Set<String> revoked, Map<String, HsToken> tokens) {
        RevocationListService svc = new RevocationListService(null, true);
        svc.primeRevokedForTest(revoked);
        svc.primeHsTokensForTest(tokens);
        return svc;
    }

    private MockServerWebExchange exchange(String path, String bearer) {
        MockServerHttpRequest.BaseBuilder<?> b = MockServerHttpRequest.get(path);
        if (bearer != null) b.header(HttpHeaders.AUTHORIZATION, "Bearer " + bearer);
        return MockServerWebExchange.from(b.build());
    }

    private String hash(String bearer) {
        return HomeserverTokenRevocationFilter.sha256(bearer);
    }

    // ── disabled flag ─────────────────────────────────────────────────────────

    @Test
    void disabled_forwardsEverythingUntouched() {
        // Even a known-revoked token sails through when the seam is off.
        var svc = revocations(Set.of("hs:matrix:alice"),
                Map.of(hash("tok"), new HsToken("alice", "matrix", "brokered", "dev1")));
        var filter = new HomeserverTokenRevocationFilter(svc, false);
        var ex = exchange("/_matrix/client/v3/sync", "tok");
        var chain = new RecordingChain();
        StepVerifier.create(filter.filter(ex, chain)).verifyComplete();
        assertThat(chain.forwarded).isTrue();
        assertThat(ex.getResponse().getStatusCode()).isNull();
    }

    // ── happy path ────────────────────────────────────────────────────────────

    @Test
    void enabled_knownUnrevokedToken_forwards() {
        var svc = revocations(Set.of(),
                Map.of(hash("tok"), new HsToken("alice", "matrix", "brokered", "dev1")));
        var filter = new HomeserverTokenRevocationFilter(svc, true);
        var ex = exchange("/_matrix/client/v3/sync", "tok");
        var chain = new RecordingChain();
        StepVerifier.create(filter.filter(ex, chain)).verifyComplete();
        assertThat(chain.forwarded).isTrue();
    }

    // ── coarse ban kills everything ───────────────────────────────────────────

    @Test
    void coarseBanKey_deniesBrokeredAndPersonalAlike() {
        var brokered = new HsToken("alice", "matrix", "brokered", "dev1");
        var personal = new HsToken("alice", "matrix", "personal", "dev2");
        var svc = revocations(Set.of("hs:matrix:alice"),
                Map.of(hash("b"), brokered, hash("p"), personal));
        var filter = new HomeserverTokenRevocationFilter(svc, true);
        for (String tok : new String[]{"b", "p"}) {
            var ex = exchange("/_matrix/client/v3/sync", tok);
            var chain = new RecordingChain();
            StepVerifier.create(filter.filter(ex, chain)).verifyComplete();
            assertThat(chain.forwarded).as("tok %s denied", tok).isFalse();
            assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }
    }

    // ── per-credential revoke is surgical ─────────────────────────────────────

    @Test
    void perCredentialKey_deniesOnlyThatDeviceOrApp() {
        var dev1 = new HsToken("alice", "matrix", "personal", "dev1");
        var dev2 = new HsToken("alice", "matrix", "personal", "dev2");
        var svc = revocations(Set.of("hs:matrix:alice:dev1"),
                Map.of(hash("t1"), dev1, hash("t2"), dev2));
        var filter = new HomeserverTokenRevocationFilter(svc, true);

        var ex1 = exchange("/_matrix/client/v3/sync", "t1");
        var c1 = new RecordingChain();
        StepVerifier.create(filter.filter(ex1, c1)).verifyComplete();
        assertThat(c1.forwarded).isFalse();
        assertThat(ex1.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        var ex2 = exchange("/_matrix/client/v3/sync", "t2");
        var c2 = new RecordingChain();
        StepVerifier.create(filter.filter(ex2, c2)).verifyComplete();
        assertThat(c2.forwarded).as("the user's other device survives").isTrue();
    }

    // ── external-client key: personal denied, brokered survives ───────────────

    @Test
    void externalClientKey_deniesPersonal_butBrokeredOurUiSurvives() {
        var brokered = new HsToken("alice", "mastodon", "brokered", "app-our-ui");
        var personal = new HsToken("alice", "mastodon", "personal", "app-tusky");
        var svc = revocations(Set.of("external-client:alice:mastodon"),
                Map.of(hash("b"), brokered, hash("p"), personal));
        var filter = new HomeserverTokenRevocationFilter(svc, true);

        // personal native client -> denied
        var exP = exchange("/api/v1/timelines/home", "p");
        var cP = new RecordingChain();
        StepVerifier.create(filter.filter(exP, cP)).verifyComplete();
        assertThat(cP.forwarded).isFalse();
        assertThat(exP.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        // brokered our-UI token for the same localpart -> still works (the headline
        // correctness property: removing the external-client role must NOT break
        // our-UI access).
        var exB = exchange("/api/v1/timelines/home", "b");
        var cB = new RecordingChain();
        StepVerifier.create(filter.filter(exB, cB)).verifyComplete();
        assertThat(cB.forwarded).isTrue();
    }

    // ── fail-closed on an unrecognized token ──────────────────────────────────

    @Test
    void unknownToken_onGatedPath_failsClosed() {
        var svc = revocations(Set.of(), new HashMap<>());
        var filter = new HomeserverTokenRevocationFilter(svc, true);
        var ex = exchange("/api/v1/timelines/home", "never-minted");
        var chain = new RecordingChain();
        StepVerifier.create(filter.filter(ex, chain)).verifyComplete();
        assertThat(chain.forwarded).isFalse();
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    // ── discovery + anonymous + ungated exemptions ────────────────────────────

    @Test
    void discoveryAndUngatedPaths_areExempt() {
        var svc = revocations(Set.of(), new HashMap<>());
        var filter = new HomeserverTokenRevocationFilter(svc, true);
        // unknown token but a discovery/ungated path -> forwarded, never fail-closed
        for (String path : new String[]{
                "/_matrix/client/versions",
                "/.well-known/matrix/client",
                "/api/games/list" /* not a gated homeserver path */}) {
            var ex = exchange(path, "whatever");
            var chain = new RecordingChain();
            StepVerifier.create(filter.filter(ex, chain)).verifyComplete();
            assertThat(chain.forwarded).as("path %s exempt", path).isTrue();
        }
    }

    @Test
    void gatedPathWithNoBearer_isLeftToTheCoarseGate() {
        var svc = revocations(Set.of("hs:matrix:alice"), new HashMap<>());
        var filter = new HomeserverTokenRevocationFilter(svc, true);
        var ex = exchange("/_matrix/client/v3/sync", null);
        var chain = new RecordingChain();
        StepVerifier.create(filter.filter(ex, chain)).verifyComplete();
        assertThat(chain.forwarded).isTrue();
    }
}
