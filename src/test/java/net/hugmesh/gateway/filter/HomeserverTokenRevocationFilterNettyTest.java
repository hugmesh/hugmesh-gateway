package net.hugmesh.gateway.filter;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.server.reactive.ReactorHttpHandlerAdapter;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;
import net.hugmesh.gateway.cache.RevocationListService;
import net.hugmesh.gateway.cache.RevocationListService.HsToken;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The credential-channel exploits over a real reactor-netty server and raw sockets, so
 * header duplication, query parsing and body replay are those of the production HTTP
 * stack rather than of the mock request. The handler behind the filter stands in for
 * the router: it answers 200 and echoes the body it received.
 */
class HomeserverTokenRevocationFilterNettyTest {

    private static DisposableServer server;

    @BeforeAll
    static void start() {
        var svc = new RevocationListService(null, true);
        svc.primeRevokedForTest(Set.of("hs:matrix:alice", "hs:mastodon:alice"));
        svc.primeHsTokensForTest(Map.of(
                HomeserverTokenRevocationFilter.sha256("banned"), new HsToken("alice", "matrix", "brokered", "dev1"),
                HomeserverTokenRevocationFilter.sha256("banned-masto"), new HsToken("alice", "mastodon", "brokered", "app1"),
                HomeserverTokenRevocationFilter.sha256("good"), new HsToken("bob", "matrix", "brokered", "dev9")));
        var filter = new HomeserverTokenRevocationFilter(svc, true);
        var handler = WebHttpHandlerBuilder
                .webHandler(ex -> DataBufferUtils.join(ex.getRequest().getBody())
                        .map(b -> { String t = b.toString(StandardCharsets.UTF_8); DataBufferUtils.release(b); return t; })
                        .defaultIfEmpty("")
                        .flatMap(t -> {
                            ex.getResponse().getHeaders().add("X-Router-Hit", "true");
                            return ex.getResponse().writeWith(Mono.just(
                                    ex.getResponse().bufferFactory().wrap(("echo:" + t).getBytes(StandardCharsets.UTF_8))));
                        }))
                .filter(filter)
                .build();
        server = HttpServer.create().host("127.0.0.1").port(0)
                .handle(new ReactorHttpHandlerAdapter(handler)).bindNow();
    }

    @AfterAll
    static void stop() {
        if (server != null) server.disposeNow();
    }

    private static String send(String head, String body) throws Exception {
        try (Socket s = new Socket("127.0.0.1", server.port())) {
            s.setSoTimeout(5000);
            OutputStream out = s.getOutputStream();
            byte[] b = body.getBytes(StandardCharsets.UTF_8);
            String req = head + "Host: gw\r\nConnection: close\r\n"
                    + (b.length > 0 ? "Content-Length: " + b.length + "\r\n" : "") + "\r\n";
            out.write(req.getBytes(StandardCharsets.UTF_8));
            out.write(b);
            out.flush();
            InputStream in = s.getInputStream();
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            in.transferTo(buf);
            return buf.toString(StandardCharsets.UTF_8);
        }
    }

    private static String statusLine(String response) {
        return response.substring(0, response.indexOf("\r\n"));
    }

    @Test
    void queryStringToken_noAuthorizationHeader_isRefused() throws Exception {
        assertThat(statusLine(send("GET /_matrix/client/v3/sync?access_token=banned HTTP/1.1\r\n", "")))
                .isEqualTo("HTTP/1.1 403 Forbidden");
        assertThat(statusLine(send("GET /api/v1/accounts/verify_credentials?access_token=banned-masto HTTP/1.1\r\n", "")))
                .isEqualTo("HTTP/1.1 403 Forbidden");
    }

    @Test
    void duplicateAuthorizationHeaders_goodThenBanned_isRefused() throws Exception {
        assertThat(statusLine(send("GET /_matrix/client/v3/sync HTTP/1.1\r\n"
                + "Authorization: Bearer good\r\nAuthorization: Bearer banned\r\n", "")))
                .isEqualTo("HTTP/1.1 403 Forbidden");
    }

    @Test
    void formBodyToken_isRefused() throws Exception {
        assertThat(statusLine(send("POST /api/v1/statuses HTTP/1.1\r\n"
                + "Content-Type: application/x-www-form-urlencoded\r\n", "status=hi&access_token=banned-masto")))
                .isEqualTo("HTTP/1.1 403 Forbidden");
    }

    @Test
    void goodToken_isForwarded_andTheInspectedBodyReachesTheHandler() throws Exception {
        String r = send("POST /api/v1/statuses?access_token=good HTTP/1.1\r\n"
                + "Content-Type: application/json\r\n", "{\"status\":\"hi\"}");
        assertThat(statusLine(r)).isEqualTo("HTTP/1.1 200 OK");
        assertThat(r).contains("X-Router-Hit: true").contains("echo:{\"status\":\"hi\"}");
    }
}
