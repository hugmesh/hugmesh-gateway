package net.hugmesh.gateway.filter;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import net.hugmesh.gateway.cache.RevocationListService;
import net.hugmesh.gateway.cache.RevocationListService.HsToken;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A revoked homeserver token must be refused whichever request channel carries it.
 * Reading only the first {@code Authorization} header let a banned token through as
 * {@code ?access_token=} (a channel the Matrix spec and OAuth bearer usage, RFC 6750,
 * both define), and let a good first header shield a banned second one.
 */
class HomeserverTokenRevocationFilterCredentialChannelTest {

    private final AtomicBoolean forwarded = new AtomicBoolean();
    private final WebFilterChain chain = ex -> { forwarded.set(true); return Mono.empty(); };

    private HomeserverTokenRevocationFilter filter() {
        var svc = new RevocationListService(null, true);
        svc.primeRevokedForTest(Set.of("hs:matrix:alice"));
        svc.primeHsTokensForTest(Map.of(
                HomeserverTokenRevocationFilter.sha256("banned"), new HsToken("alice", "matrix", "brokered", "dev1"),
                HomeserverTokenRevocationFilter.sha256("good"), new HsToken("bob", "matrix", "brokered", "dev9")));
        return new HomeserverTokenRevocationFilter(svc, true);
    }

    private MockServerWebExchange run(String rawUri, String... authorization) {
        forwarded.set(false);
        var b = MockServerHttpRequest.method(HttpMethod.GET, URI.create("http://gw" + rawUri));
        for (String a : authorization) b.header(HttpHeaders.AUTHORIZATION, a);
        var ex = MockServerWebExchange.from(b.build());
        filter().filter(ex, chain).block();
        return ex;
    }

    private void assertRefused(String rawUri, String... authorization) {
        var ex = run(rawUri, authorization);
        assertThat(forwarded).as("%s %s must not be forwarded", rawUri, List.of(authorization)).isFalse();
        assertThat(ex.getResponse().getStatusCode()).as(rawUri).isEqualTo(HttpStatus.FORBIDDEN);
    }

    private void assertForwarded(String rawUri, String... authorization) {
        var ex = run(rawUri, authorization);
        assertThat(forwarded).as("%s %s must be forwarded", rawUri, List.of(authorization)).isTrue();
        assertThat(ex.getResponse().getStatusCode()).as(rawUri).isNull();
    }

    /** The reported exploit: revoked token in the query string, no Authorization header. */
    @ParameterizedTest
    @ValueSource(strings = {
            "/_matrix/client/v3/sync?access_token=banned",
            "/api/v1/accounts/verify_credentials?access_token=banned",
            "/api/v2/search?q=x&access_token=banned",
            "/_matrix/client/v3/sync?since=s1&access_token=banned&timeout=0",
            // spellings of the parameter name and value
            "/_matrix/client/v3/sync?access%5Ftoken=banned",
            "/_matrix/client/v3/sync?ACCESS_TOKEN=banned",
            "/_matrix/client/v3/sync?access_token=%62anned",
            "/_matrix/client/v3/sync?access_token=banned%20",
            // a second parameter after a harmless first one
            "/_matrix/client/v3/sync?access_token=good&access_token=banned",
            "/_matrix/client/v3/sync?access_token=banned&access_token=good",
            // ';' as a separator (older Rack, some parsers)
            "/_matrix/client/v3/sync?a=1;access_token=banned",
            // Doorkeeper's other parameter name
            "/api/v1/accounts/verify_credentials?bearer_token=banned",
            // on an encoded path spelling too
            "/%5fmatrix/client/v3/sync?access_token=banned",
    })
    void revokedToken_inTheQueryString_isRefused(String rawUri) {
        assertRefused(rawUri);
    }

    @Test
    void unrecognisedToken_inTheQueryString_isRefused() {
        assertRefused("/_matrix/client/v3/sync?access_token=never-minted");
    }

    @Test
    void revokedQueryToken_isRefused_evenBehindAGoodHeader() {
        assertRefused("/_matrix/client/v3/sync?access_token=banned", "Bearer good");
    }

    @Test
    void duplicateAuthorizationHeaders_eachIsAdjudicated() {
        assertRefused("/_matrix/client/v3/sync", "Bearer good", "Bearer banned");
        assertRefused("/_matrix/client/v3/sync", "Bearer banned", "Bearer good");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "bearer banned",
            "BEARER banned",
            "Bearer\tbanned",
            "Bearer   banned",
            "  Bearer banned  ",
            "Bearer good, Bearer banned",
    })
    void bearerSchemeSpellings_areAdjudicated(String header) {
        assertRefused("/_matrix/client/v3/sync", header);
    }

    @Test
    void goodToken_inEitherChannel_isForwarded() {
        assertForwarded("/_matrix/client/v3/sync?access_token=good");
        assertForwarded("/_matrix/client/v3/sync?access_token=good", "Bearer good");
        assertForwarded("/_matrix/client/v3/sync", "Bearer good", "Bearer good");
    }

    @Test
    void noCredential_isLeftToTheCoarseGate() {
        assertForwarded("/_matrix/client/v3/sync?since=s1");
        assertForwarded("/_matrix/client/v3/sync?access_token=");
    }

    @Test
    void discoveryPath_staysExempt_withAQueryToken() {
        assertForwarded("/_matrix/client/versions?access_token=never-minted");
    }

    @Test
    void ungatedPath_queryTokenIsNotThisFiltersConcern() {
        assertForwarded("/bff/mesh/rooms?access_token=never-minted");
    }

    // ---- body channel (the Mastodon-API surface parses form / JSON bodies into params) ----

    private final AtomicReference<String> forwardedBody = new AtomicReference<>();

    private MockServerWebExchange post(String rawUri, String contentType, String body, String... authorization) {
        forwarded.set(false);
        forwardedBody.set(null);
        var b = MockServerHttpRequest.method(HttpMethod.POST, URI.create("http://gw" + rawUri));
        if (contentType != null) b.header(HttpHeaders.CONTENT_TYPE, contentType.split(", "));  // ", " = two header lines
        for (String a : authorization) b.header(HttpHeaders.AUTHORIZATION, a);
        var ex = MockServerWebExchange.from(b.body(body));
        WebFilterChain reading = e -> DataBufferUtils.join(e.getRequest().getBody())
                .map(buf -> { String t = buf.toString(StandardCharsets.UTF_8); DataBufferUtils.release(buf); return t; })
                .defaultIfEmpty("")
                .doOnNext(t -> { forwarded.set(true); forwardedBody.set(t); })
                .then();
        filter().filter(ex, reading).block();
        return ex;
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "application/x-www-form-urlencoded|status=hi&access_token=banned",
            "application/x-www-form-urlencoded; charset=UTF-8|access%5Ftoken=banned",
            "Application/X-WWW-Form-Urlencoded|access_token=banned",
            "application/json|{\"status\":\"hi\",\"access_token\":\"banned\"}",
            "application/json; charset=utf-8|{\"access_token\":\"good\",\"access_token\":\"banned\"}",
            "application/activity+json|{\"access_token\":\"banned\"}",
            "APPLICATION/JSON|{\"access_token\":\"banned\"}",
            "application/json|{\"access_token\":\"\\u0062anned\"}",
    })
    void revokedToken_inAFormOrJsonBody_isRefused(String spec) {
        String[] p = spec.split("\\|", 2);
        var ex = post("/api/v1/statuses", p[0], p[1]);
        assertThat(forwarded).as(spec).isFalse();
        assertThat(ex.getResponse().getStatusCode()).as(spec).isEqualTo(HttpStatus.FORBIDDEN);
        // and behind a good header
        ex = post("/api/v1/statuses", p[0], p[1], "Bearer good");
        assertThat(forwarded).as("good header + " + spec).isFalse();
    }

    @Test
    void malformedJsonBody_isRefused_notForwardedUnread() {
        var ex = post("/api/v1/statuses", "application/json", "{\"access_token\":\"banned\"", "Bearer good");
        assertThat(forwarded).isFalse();
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void formAndJsonDeclaredTogether_isRefused() {
        post("/api/v1/statuses", "application/x-www-form-urlencoded, application/json", "access_token=banned", "Bearer good");
        assertThat(forwarded).isFalse();
    }

    @Test
    void oversizedInspectedBody_isRefused() {
        String big = "{\"status\":\"" + "x".repeat((1 << 20)) + "\"}";
        var ex = post("/api/v1/statuses", "application/json", big, "Bearer good");
        assertThat(forwarded).isFalse();
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE);
    }

    @Test
    void multipartBody_withNoHeaderOrQueryCredential_isRefused() {
        var ex = post("/api/v1/media", "multipart/form-data; boundary=b",
                "--b\r\nContent-Disposition: form-data; name=\"access_token\"\r\n\r\nbanned\r\n--b--\r\n");
        assertThat(forwarded).isFalse();
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void multipartBody_withAGoodHeader_isForwarded() {
        post("/api/v1/media", "multipart/form-data; boundary=b", "--b--\r\n", "Bearer good");
        assertThat(forwarded).isTrue();
    }

    @Test
    void inspectedBody_isReplayedDownstreamByteForByte() {
        String body = "{\"status\":\"h\u00e9llo\",\"visibility\":\"public\"}";
        post("/api/v1/statuses", "application/json", body, "Bearer good");
        assertThat(forwarded).isTrue();
        assertThat(forwardedBody.get()).isEqualTo(body);
        String form = "status=hi+there&visibility=public";
        post("/api/v1/statuses", "application/x-www-form-urlencoded", form, "Bearer good");
        assertThat(forwardedBody.get()).isEqualTo(form);
    }

    @Test
    void anonymousOAuthFormPost_isForwarded() {
        post("/oauth/token", "application/x-www-form-urlencoded",
                "grant_type=password&username=a&password=b&client_id=c", "Basic Yzpk");
        assertThat(forwarded).isTrue();
        post("/api/v1/apps", "application/json", "{\"client_name\":\"x\",\"redirect_uris\":\"urn:ietf:wg:oauth:2.0:oob\"}");
        assertThat(forwarded).isTrue();
    }

    @Test
    void matrixBody_isNotBufferedOrInspected() {
        // The Matrix client-server API takes its token from the header or query only;
        // key-backup bodies can exceed the inspection cap and must still forward.
        String big = "{\"rooms\":\"" + "x".repeat((1 << 20)) + "\"}";
        post("/_matrix/client/v3/room_keys/keys", "application/json", big, "Bearer good");
        assertThat(forwarded).isTrue();
    }
}
