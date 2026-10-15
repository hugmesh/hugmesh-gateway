package net.hugmesh.gateway.filter;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.gateway.cache.RevocationListService;
import net.hugmesh.gateway.cache.RevocationListService.HsToken;

import java.net.URI;
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

    // ── the path the gate reads is the path the router and homeserver read ────

    /** Like {@link #exchange} but the path is taken VERBATIM (no template encoding). */
    private MockServerWebExchange rawExchange(String rawPath, String bearer) {
        MockServerHttpRequest.BaseBuilder<?> b =
                MockServerHttpRequest.method(HttpMethod.GET, URI.create("http://gw" + rawPath));
        if (bearer != null) b.header(HttpHeaders.AUTHORIZATION, "Bearer " + bearer);
        return MockServerWebExchange.from(b.build());
    }

    private HomeserverTokenRevocationFilter bannedAlice() {
        var svc = revocations(Set.of("hs:matrix:alice", "hs:mastodon:alice"),
                Map.of(hash("banned"), new HsToken("alice", "matrix", "brokered", "dev1"),
                        hash("banned-masto"), new HsToken("alice", "mastodon", "brokered", "app1"),
                        hash("good"), new HsToken("bob", "matrix", "brokered", "dev9")));
        return new HomeserverTokenRevocationFilter(svc, true);
    }

    private void assertDenied(HomeserverTokenRevocationFilter filter, String rawPath, String bearer) {
        var ex = rawExchange(rawPath, bearer);
        var chain = new RecordingChain();
        StepVerifier.create(filter.filter(ex, chain)).verifyComplete();
        assertThat(chain.forwarded).as("%s must not be forwarded", rawPath).isFalse();
        assertThat(ex.getResponse().getStatusCode()).as(rawPath).isEqualTo(HttpStatus.FORBIDDEN);
    }

    private void assertForwarded(HomeserverTokenRevocationFilter filter, String rawPath, String bearer) {
        var ex = rawExchange(rawPath, bearer);
        var chain = new RecordingChain();
        StepVerifier.create(filter.filter(ex, chain)).verifyComplete();
        assertThat(chain.forwarded).as("%s must be forwarded", rawPath).isTrue();
        assertThat(ex.getResponse().getStatusCode()).as(rawPath).isNull();
    }

    @Test
    void bannedToken_encodedSegmentBelowTheGatedPrefix_isDeniedLikeThePlainPath() {
        // Regression pin, NOT a bypass: the prefix /_matrix is spelled literally here,
        // so even the raw-path gate already denied this. The bypasses are the
        // spellings that alter the prefix itself, in the parameterised tests below.
        var filter = bannedAlice();
        // the plain spelling is the control: same 403
        assertDenied(filter, "/_matrix/client/v3/sync", "banned");
        // %76 is "v": the router decodes it, so this is /_matrix/client/vr0/sync
        assertDenied(filter, "/_matrix/client/%76r0/sync", "banned");
        assertDenied(filter, "/_matrix/client/%76%33/sync", "banned");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            // percent-encoding of the prefix itself, upper and lower case hex
            "/%5Fmatrix/client/v3/sync",
            "/%5fmatrix/client/v3/sync",
            "/_%6Datrix/client/v3/sync",
            "/%5F%6d%61trix/client/v3/sync",
            // encoded slash inside the prefix
            "/_matrix%2Fclient/v3/sync",
            // double and triple encoding
            "/%255Fmatrix/client/v3/sync",
            "/%25255Fmatrix/client/v3/sync",
            "/_matrix/client/%2576%33/sync",
            // letter case
            "/_MATRIX/client/v3/sync",
            "/_Matrix/Client/V3/Sync",
            // trailing slash, doubled slash, leading doubled slash
            "/_matrix/client/v3/sync/",
            "//_matrix/client/v3/sync",
            "/_matrix//client//v3/sync",
            // dot segments, plain and encoded
            "/./_matrix/client/v3/sync",
            "/x/../_matrix/client/v3/sync",
            "/x/%2e%2e/_matrix/client/v3/sync",
            "/x/%2E%2E/_matrix/client/v3/sync",
            "/x/.%2e/_matrix/client/v3/sync",
            "/%252e/_matrix/client/v3/sync",
            "/_matrix/client/v3/../v3/sync",
            // path parameters, plain and encoded semicolon
            "/_matrix;a=b/client/v3/sync",
            "/_matrix/client;x/v3/sync",
            "/_matrix%3Bx=y/client/v3/sync",
            // backslash read as a separator (a raw backslash is not a legal URI character)
            "/_matrix%5Cclient/v3/sync",
            // leaving the discovery exemption by a dot segment
            "/.well-known/../_matrix/client/v3/sync",
            "/.well-known/%2e%2e/_matrix/client/v3/sync",
            // not the exact discovery path
            "/_matrix/client/%76ersions",
            "/_matrix/client/versions/",
            "/_matrix/client/versions/../v3/sync",
    })
    void bannedToken_everySpellingOfAMatrixPath_isDenied(String rawPath) {
        assertDenied(bannedAlice(), rawPath, "banned");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/%61pi/v1/timelines/home",
            "/api/%76%31/timelines/home",
            "/API/V1/timelines/home",
            "/api;x=1/v1/timelines/home",
            "/api/v2/%73earch",
            "/%6Fauth/token",
            "/x/%2e%2e/api/v1/timelines/home",
    })
    void bannedToken_everySpellingOfAMastodonPath_isDenied(String rawPath) {
        assertDenied(bannedAlice(), rawPath, "banned-masto");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/_matrix/client/%76r0/sync",
            "/%5Fmatrix/client/v3/sync",
            "/api/%76%31/timelines/home",
            "/x/%2e%2e/_matrix/client/v3/sync",
    })
    void unrecognisedBearer_onAnEncodedGatedPath_failsClosed(String rawPath) {
        assertDenied(bannedAlice(), rawPath, "never-minted");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            // no single reading: encoded NUL, deeper nesting than is followed
            "/_matrix/client/v3/sync%00",
            "/_matrix/client/v3/%00/sync",
            "/%2525252575/anything",
            "/_matrix/client/v3/%ff%fe/sync",
    })
    void ambiguousPath_withAKnownGoodBearer_isRefused(String rawPath) {
        assertDenied(bannedAlice(), rawPath, "good");
    }

    @Test
    void ambiguousPath_withoutBearer_isLeftToTheCoarseGate() {
        assertForwarded(bannedAlice(), "/_matrix/client/v3/sync%00", null);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/_matrix/client/v3/sync",
            // legitimate encoded ids: a room id and a base64 event id with an encoded slash
            "/_matrix/client/v3/rooms/%21abc%3Aexample.org/send/m.room.message/txn1",
            "/_matrix/client/v3/rooms/%21abc%3Aexample.org/event/%24ab%2Fcd%2Bef",
            "/api/v1/accounts/lookup",
    })
    void goodToken_onLegitimateEncodedPaths_isForwarded(String rawPath) {
        assertForwarded(bannedAlice(), rawPath, "good");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/api/g%61mes/list",
            "/api/games/%2e%2e/foo",
            "/api;x=1/games/list",
            "/_matrixfoo/x",
            "/apix/v1/timelines/home",
            // ambiguous but not under a gated prefix, and not nested too deep: not this filter's surface
            "/api/games/list%00",
    })
    void ungatedPaths_areNotCaughtByTheWiderMatching(String rawPath) {
        // an unrecognised bearer on an ungated path is not this filter's concern
        assertForwarded(bannedAlice(), rawPath, "never-minted");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/_matrix/client/versions",
            "/.well-known/matrix/client",
            "/.well-known/matrix/server",
    })
    void discoveryPaths_stayExemptInTheirPlainSpelling(String rawPath) {
        assertForwarded(bannedAlice(), rawPath, "never-minted");
    }
}
