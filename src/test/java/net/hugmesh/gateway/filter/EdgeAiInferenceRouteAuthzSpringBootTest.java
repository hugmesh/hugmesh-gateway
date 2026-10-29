package net.hugmesh.gateway.filter;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import net.hugmesh.gateway.cache.GatewayRouteAccessService;
import net.hugmesh.gateway.cache.GatewayRouteAccessService.Decision;
import net.hugmesh.gateway.testsupport.TestIssuer;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * END-TO-END authorization for the edge-AI model API: mesh users reach the
 * OpenAI-compatible inference server at {@code https://ai.<domain>/v1}; anonymous
 * and expired-token requests never reach it.
 *
 * <p>The three routes are declared exactly the way the generator's
 * {@code specs/cluster/apps/20-gateway-be.yaml} declares them on the be-gateway:
 * {@code edge-ai-analysis} (Host + {@code Path=/v1/analyze/**}), {@code edge-ai-tts}
 * (Host + {@code Path=/v1/synthesize/**}), then the {@code edge-ai} CATCHALL with a
 * Host predicate and NO Path predicate. The route-access authority is the
 * be-gateway's baked {@code CanonicalSeed.be()} (no datastore in this context),
 * whose {@code /v1/** -> ROLE_USER} row governs the catchall (pinned against the
 * route-access service itself, because over HTTP an ungoverned path is forwarded
 * exactly like an allowed one; see
 * {@link #theV1Rows_governEveryV1Path_soNoneFallsThroughAsUngoverned}). Every signed-in
 * principal holds {@code ROLE_USER} (the converter floor), so that row admits any
 * signed-in account and anonymous traffic is stopped by the coarse
 * {@code authenticated()} floor; see
 * {@link #everySignedInAccount_holdsTheRoleUserFloor_soTheV1RowAdmitsAMatrixOnlyAccount}.
 *
 * <p>Every request goes through REAL Spring Cloud Gateway routing to a REAL HTTP
 * upstream (an in-process stub that records what reached it), so "forwarded" and
 * "not forwarded" are observed at the upstream, not inferred from a status code.
 *
 * <p><b>Live mode.</b> With {@code EDGE_AI_LIVE_UPSTREAM} set (for example
 * {@code http://127.0.0.1:11434}, an Ollama server) the {@code edge-ai} catchall
 * points there instead of the stub, and {@link #live_roleUser_runsAChatCompletion}
 * runs a real completion through the gateway with {@code EDGE_AI_LIVE_MODEL}
 * (default {@code qwen2.5:0.5b}). With {@code ROUTE_ACCESS_R2DBC_URL} also set the
 * rules come from that Postgres (load the generator's route-access seed into it)
 * instead of the baked seed. Neither variable is set in CI, so the hermetic cases
 * are what CI runs.
 */
// The instance name pins route-access to CanonicalSeed.be(). The three routes are
// registered in props() below, ALL of them there: a list bound from a
// higher-precedence source replaces the whole list, so splitting a route's keys
// between @SpringBootTest properties and @DynamicPropertySource leaves it with no
// predicates and the context refuses to start.
@SpringBootTest(properties = "spring.application.name=hugmesh-be-gateway")
@AutoConfigureWebTestClient(timeout = "PT120S")
class EdgeAiInferenceRouteAuthzSpringBootTest {

    static final String AI_HOST = "ai.mesh.example";

    private static final String LIVE_UPSTREAM = System.getenv("EDGE_AI_LIVE_UPSTREAM");
    private static final String LIVE_R2DBC = System.getenv("ROUTE_ACCESS_R2DBC_URL");

    private static final TestIssuer ISSUER = new TestIssuer();
    private static final Upstream STUB = new Upstream();

    @AfterAll
    static void stop() {
        ISSUER.close();
        STUB.close();
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        String r = "spring.cloud.gateway.server.webflux.routes";
        registry.add(r + "[0].id", () -> "edge-ai-analysis");
        registry.add(r + "[0].uri", STUB::uri);
        registry.add(r + "[0].predicates[0]", () -> "Host=" + AI_HOST);
        registry.add(r + "[0].predicates[1]", () -> "Path=/v1/analyze/**");
        registry.add(r + "[1].id", () -> "edge-ai-tts");
        registry.add(r + "[1].uri", STUB::uri);
        registry.add(r + "[1].predicates[0]", () -> "Host=" + AI_HOST);
        registry.add(r + "[1].predicates[1]", () -> "Path=/v1/synthesize/**");
        registry.add(r + "[2].id", () -> "edge-ai");
        registry.add(r + "[2].uri",
                () -> LIVE_UPSTREAM != null && !LIVE_UPSTREAM.isBlank() ? LIVE_UPSTREAM : STUB.uri());
        registry.add(r + "[2].predicates[0]", () -> "Host=" + AI_HOST);
        registry.add("app.tenancy.issuers", () -> ISSUER.issuerUri() + "=meshx");
        registry.add("app.tenancy.hosts", () -> "mesh.example=meshx");
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", ISSUER::issuerUri);
        registry.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri",
                () -> ISSUER.issuerUri() + "/.well-known/jwks.json");
        registry.add("app.route-access.enabled", () -> "true");
        if (LIVE_R2DBC != null && !LIVE_R2DBC.isBlank()) {
            registry.add("app.route-access.r2dbc-url", () -> LIVE_R2DBC);
        }
        registry.add("app.revocation.enabled", () -> "false");
        registry.add("app.url-registry.enabled", () -> "false");
        registry.add("app.resource-access.enabled", () -> "false");
        registry.add("spring.autoconfigure.exclude", () ->
                "org.springframework.boot.cassandra.autoconfigure.CassandraAutoConfiguration,"
                        + "org.springframework.boot.data.cassandra.autoconfigure.DataCassandraAutoConfiguration,"
                        + "org.springframework.boot.data.cassandra.autoconfigure.DataCassandraReactiveAutoConfiguration");
    }

    @Autowired
    WebTestClient http;

    @Autowired
    GatewayRouteAccessService routeAccess;

    @BeforeEach
    void reset() {
        STUB.hits.clear();
    }

    private static String bearer(String sub, List<String> roles) {
        return "Bearer " + ISSUER.mint(sub, roles);
    }

    private WebTestClient.ResponseSpec get(String path, String authorization) {
        var req = http.get().uri(path).header(HttpHeaders.HOST, AI_HOST);
        if (authorization != null) req = req.header(HttpHeaders.AUTHORIZATION, authorization);
        return req.exchange();
    }

    private WebTestClient.ResponseSpec postJson(String path, String authorization, String body) {
        var req = http.post().uri(path).header(HttpHeaders.HOST, AI_HOST)
                .contentType(MediaType.APPLICATION_JSON).bodyValue(body);
        if (authorization != null) req = req.header(HttpHeaders.AUTHORIZATION, authorization);
        return req.exchange();
    }

    // ── the catchall model API: /v1/models, /v1/chat/completions ────────────────

    @Test
    void anonymous_isRefused401_andNothingReachesTheModelServer() {
        get("/v1/models", null).expectStatus().isUnauthorized();
        postJson("/v1/chat/completions", null, "{\"model\":\"m\",\"messages\":[]}")
                .expectStatus().isUnauthorized();
        assertThat(STUB.hits).isEmpty();
    }

    @Test
    void roleUser_reachesTheModelServer_onTheCatchallRoute() {
        if (LIVE_UPSTREAM != null) {
            get("/v1/models", bearer("mesh-user", List.of("user")))
                    .expectStatus().isOk()
                    .expectBody(String.class).value(b -> assertThat(b).contains("\"object\":\"list\""));
            return;
        }
        get("/v1/models", bearer("mesh-user", List.of("user")))
                .expectStatus().isOk()
                .expectHeader().doesNotExist("X-Route-Denied")
                .expectBody(String.class).value(b -> assertThat(b).contains("stub-model"));
        postJson("/v1/chat/completions", bearer("mesh-user", List.of("user")),
                "{\"model\":\"stub-model\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}")
                .expectStatus().isOk();
        assertThat(STUB.hits).containsExactly("GET /v1/models", "POST /v1/chat/completions");
    }

    @Test
    void everySignedInAccount_holdsTheRoleUserFloor_soTheV1RowAdmitsAMatrixOnlyAccount() {
        // CHARACTERIZATION of what "gated by ROLE_USER" means today. CasdoorAuthorities
        // floors EVERY validated token to ROLE_USER (and BffSessionAuthFilter does the
        // same for bff_ sessions, registration-incomplete ones included), so there is
        // no signed-in principal the /v1/** -> ROLE_USER row can refuse: a token whose
        // only Casdoor role is "matrix" still reaches the model server. The row gates on
        // sign-in, not on a role an admin can withhold. Withholding inference from a
        // user takes an extra route-access row (a casdoor_user-pinned allow=false row
        // on /v1/**, or replacing the ROLE_USER row with a capability role). If a real
        // inference role lands, this test must be rewritten to expect 403.
        // RED when the ROLE_USER floor in CasdoorAuthorities is removed.
        get("/v1/models", bearer("matrix-only", List.of("matrix")))
                .expectStatus().isOk()
                .expectHeader().doesNotExist("X-Route-Denied");
        if (LIVE_UPSTREAM == null) {
            assertThat(STUB.hits).containsExactly("GET /v1/models");
        }
    }

    @Test
    void expiredToken_isRefused401() {
        get("/v1/models", "Bearer " + ISSUER.mintExpired("mesh-user", List.of("user")))
                .expectStatus().isUnauthorized();
        if (LIVE_UPSTREAM == null) {
            assertThat(STUB.hits).isEmpty();
        }
    }

    // ── the two more specific /v1 routes on the same Host ──────────────────────

    @Test
    void analyzeAndSynthesize_followTheSameRoleUserFloor() {
        if (LIVE_UPSTREAM != null) return; // those two routes always point at the stub
        get("/v1/analyze/image", bearer("mesh-user", List.of("user"))).expectStatus().isOk();
        get("/v1/synthesize/voices", bearer("mesh-user", List.of("user"))).expectStatus().isOk();
        get("/v1/analyze/image", null).expectStatus().isUnauthorized();
        get("/v1/synthesize/voices", null).expectStatus().isUnauthorized();
        assertThat(STUB.hits).containsExactly("GET /v1/analyze/image", "GET /v1/synthesize/voices");
    }

    // ── the /v1 rows are GOVERNING, not merely absent-and-forwarded ───────

    @Test
    void theV1Rows_governEveryV1Path_soNoneFallsThroughAsUngoverned() {
        // The HTTP cases above cannot tell ALLOW from NO_RULE: GatewayRouteAccessFilter
        // forwards both, so deleting the /v1/** row from CanonicalSeed.be() left every
        // case green. Ask the same service bean the filter asks. ROLE_USER must be an
        // ALLOW (a row decides), and a principal holding neither ROLE_USER nor any
        // other granting role must be a DENY (a row governs and refuses), on the
        // catchall and on both sub-routes.
        // RED when the /v1/** base row is removed from CanonicalSeed.be(). Removing
        // /v1/analyze/** or /v1/synthesize/** alone stays green, and should: the base
        // row then decides those paths the same way (same single ROLE_USER floor), so
        // no outcome changes. They only become observable if they ever diverge.
        // A live run with ROUTE_ACCESS_R2DBC_URL asks the datastore's rows instead.
        List<String> ids = List.of("mesh-user");
        for (String path : List.of("/v1/models", "/v1/chat/completions", "/v1/embeddings",
                "/v1/analyze/image", "/v1/synthesize/voices")) {
            assertThat(routeAccess.decide(path, "meshx", ids, List.of("ROLE_USER")))
                    .as("ROLE_USER on %s", path).isEqualTo(Decision.ALLOW);
            assertThat(routeAccess.decide(path, "meshx", ids, List.of("ROLE_MATRIX")))
                    .as("ROLE_MATRIX alone on %s", path).isEqualTo(Decision.DENY);
        }
    }

    // ── live: a real completion through the gateway ────────────────────────────

    @Test
    @EnabledIfEnvironmentVariable(named = "EDGE_AI_LIVE_UPSTREAM", matches = ".+")
    void live_roleUser_runsAChatCompletion() {
        String model = System.getenv().getOrDefault("EDGE_AI_LIVE_MODEL", "qwen2.5:0.5b");
        String body = "{\"model\":\"" + model + "\",\"stream\":false,\"max_tokens\":8,"
                + "\"messages\":[{\"role\":\"user\",\"content\":\"Reply with the single word pong.\"}]}";
        postJson("/v1/chat/completions", bearer("mesh-user", List.of("user")), body)
                .expectStatus().isOk()
                .expectBody(String.class).value(b -> {
                    System.out.println("[edge-ai live] completion via gateway: " + b);
                    assertThat(b).contains("\"chat.completion\"").contains("\"choices\"");
                });
    }

    /** A real HTTP server standing in for the inference server; records every hit. */
    static final class Upstream implements AutoCloseable {
        final List<String> hits = new CopyOnWriteArrayList<>();
        private final HttpServer server;

        Upstream() {
            try {
                server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            server.createContext("/", ex -> {
                hits.add(ex.getRequestMethod() + " " + ex.getRequestURI().getPath());
                ex.getRequestBody().readAllBytes();
                byte[] out = ("{\"object\":\"list\",\"data\":[{\"id\":\"stub-model\",\"path\":\""
                        + ex.getRequestURI().getPath() + "\"}]}").getBytes(StandardCharsets.UTF_8);
                ex.getResponseHeaders().add("Content-Type", "application/json");
                ex.sendResponseHeaders(200, out.length);
                ex.getResponseBody().write(out);
                ex.close();
            });
            server.start();
        }

        String uri() {
            return "http://127.0.0.1:" + server.getAddress().getPort();
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }
}
