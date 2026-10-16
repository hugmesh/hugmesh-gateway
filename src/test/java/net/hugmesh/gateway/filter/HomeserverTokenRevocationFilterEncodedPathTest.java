package net.hugmesh.gateway.filter;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import net.hugmesh.gateway.cache.RevocationListService;
import net.hugmesh.gateway.cache.RevocationListService.HsToken;

import java.net.URI;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A REVOKED homeserver token must be refused on the gated surface however the path is
 * spelled. Matched against the raw string, {@code /%5fmatrix/...} fell outside
 * {@code /_matrix/**} and skipped the revocation check, while the router decoded it
 * onto the same Matrix handler.
 */
class HomeserverTokenRevocationFilterEncodedPathTest {

    private final AtomicBoolean forwarded = new AtomicBoolean();
    private final WebFilterChain chain = ex -> { forwarded.set(true); return Mono.empty(); };

    private HomeserverTokenRevocationFilter filter() {
        var svc = new RevocationListService(null, true);
        svc.primeRevokedForTest(Set.of("hs:matrix:alice"));       // coarse ban
        svc.primeHsTokensForTest(Map.of(HomeserverTokenRevocationFilter.sha256("tok"),
                new HsToken("alice", "matrix", "brokered", "dev1")));
        return new HomeserverTokenRevocationFilter(svc, true);
    }

    private MockServerWebExchange run(String rawPath) {
        forwarded.set(false);
        var ex = MockServerWebExchange.from(MockServerHttpRequest
                .method(HttpMethod.GET, URI.create(rawPath))
                .header(HttpHeaders.AUTHORIZATION, "Bearer tok").build());
        filter().filter(ex, chain).block();
        return ex;
    }

    @Test
    void revokedToken_isRefused_plainAndEncodedAlike() {
        for (String raw : java.util.List.of(
                "/_matrix/client/v3/sync",                       // baseline
                "/%5fmatrix/client/v3/sync",                     // the exploit
                "/_%6Datrix/client/v3/sync",
                "/_matrix/client/%76%33/sync",
                "/api/%76%31/accounts/verify_credentials",
                "/%6fauth/token",
                "/_matrix/x/../client/v3/sync",
                "/_matrix//client///v3/sync",
                "/_matrix;a=b/client/v3/sync")) {
            var ex = run(raw);
            assertThat(forwarded).as("%s must not be forwarded with a revoked token", raw).isFalse();
            assertThat(ex.getResponse().getStatusCode()).as(raw).isEqualTo(HttpStatus.FORBIDDEN);
        }
    }

    @Test
    void ambiguousPath_isTreatedAsGated_notSkipped() {
        for (String raw : java.util.List.of(
                "/_matrix/client%2Fv3/sync", "/%255fmatrix/client/v3/sync", "/_matrix/client/v3%00/sync")) {
            run(raw);
            assertThat(forwarded).as("%s must not skip the revocation check", raw).isFalse();
        }
    }

    @Test
    void discoveryExemptPath_encodedStillExempt() {
        run("/_matrix/client/%76ersions");
        assertThat(forwarded).isTrue();
    }

    @Test
    void ungatedPath_isForwarded() {
        run("/bff/%6Desh/rooms");
        assertThat(forwarded).isTrue();
    }
}
