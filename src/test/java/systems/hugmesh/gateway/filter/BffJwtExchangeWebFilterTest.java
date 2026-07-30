package systems.hugmesh.gateway.filter;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.client.reactive.MockClientHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.reactive.function.BodyInserter;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Behaviour contract for {@link BffJwtExchangeWebFilter} — the pre-security
 * {@code bff_} → custody-JWT swap (the SSO opaque-session bridge). The test list IS
 * the contract: it pins the forward-untouched paths, the happy-path rewrite, the
 * fail-CLOSED posture on EVERY admin-bff failure mode (the highest-risk regression —
 * a fail-open would forward the raw {@code bff_}), the positive-only TTL cache, and
 * the negative-never-cached invariant.
 *
 * <p>Built with a {@link WebClient} backed by a stub {@link ExchangeFunction} (no live
 * admin-bff, no extra test dependency) so each case drives the pure
 * extract-bearer → swap → forward/reject logic. The chain is a {@link RecordingChain}
 * that flips a flag (and captures the mutated exchange) on forward, so a fail-closed
 * case can assert the downstream chain was NEVER subscribed — the load-bearing
 * "the raw bff_ never reaches the JWT decoder or downstream" property.
 */
class BffJwtExchangeWebFilterTest {

    /** A recording chain — flips a flag and captures the (mutated) exchange on forward. */
    private static final class RecordingChain implements WebFilterChain {
        final AtomicBoolean forwarded = new AtomicBoolean(false);
        final AtomicReference<ServerWebExchange> seen = new AtomicReference<>();
        @Override public Mono<Void> filter(ServerWebExchange exchange) {
            forwarded.set(true);
            seen.set(exchange);
            return Mono.empty();
        }
        String forwardedAuth() {
            ServerWebExchange ex = seen.get();
            return ex == null ? null : ex.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        }
    }

    /** Counts outbound calls + records the last X-Internal-Token + body, and answers
     *  with whatever {@link ClientResponse} the supplied responder produces. */
    private static final class StubExchange implements ExchangeFunction {
        final AtomicInteger calls = new AtomicInteger();
        final AtomicReference<String> lastInternalToken = new AtomicReference<>();
        final AtomicReference<String> lastBody = new AtomicReference<>();
        private final Function<Integer, Mono<ClientResponse>> responder;
        StubExchange(Function<Integer, Mono<ClientResponse>> responder) {
            this.responder = responder;
        }
        @Override
        public Mono<ClientResponse> exchange(org.springframework.web.reactive.function.client.ClientRequest request) {
            int n = calls.incrementAndGet();
            lastInternalToken.set(request.headers().getFirst("X-Internal-Token"));
            // Serialize the body so a test can assert the {"token":"bff_…"} shape. The
            // BodyInserter writes through the default message writers into a mock
            // request whose write handler collects the bytes into a String.
            MockClientHttpRequest mock = new MockClientHttpRequest(request.method(), request.url());
            StringBuilder captured = new StringBuilder();
            mock.setWriteHandler(body -> body
                    .map(buf -> {
                        byte[] bytes = new byte[buf.readableByteCount()];
                        buf.read(bytes);
                        org.springframework.core.io.buffer.DataBufferUtils.release(buf);
                        return new String(bytes, StandardCharsets.UTF_8);
                    })
                    .doOnNext(captured::append)
                    .then());
            ExchangeStrategies strategies = ExchangeStrategies.withDefaults();
            BodyInserter.Context ctx = new BodyInserter.Context() {
                @Override public java.util.List<org.springframework.http.codec.HttpMessageWriter<?>> messageWriters() {
                    return strategies.messageWriters();
                }
                @Override public java.util.Optional<org.springframework.http.server.reactive.ServerHttpRequest> serverRequest() {
                    return java.util.Optional.empty();
                }
                @Override public java.util.Map<String, Object> hints() {
                    return java.util.Collections.emptyMap();
                }
            };
            return request.body().insert(mock, ctx)
                    .doOnSuccess(v -> lastBody.set(captured.toString()))
                    .then(responder.apply(n));
        }
    }

    private static ClientResponse jsonResponse(HttpStatus status, String json) {
        return ClientResponse.create(status)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .body(json)
                .build();
    }

    private static BffJwtExchangeWebFilter filter(StubExchange stub) {
        return filter(stub, 60_000L);
    }

    private static BffJwtExchangeWebFilter filter(StubExchange stub, long cacheTtlMs) {
        WebClient client = WebClient.builder()
                .baseUrl("http://admin-bff:8080")
                .exchangeFunction(stub)
                .build();
        return new BffJwtExchangeWebFilter(client, "X-Internal-Token", "secret-internal-token",
                cacheTtlMs, 10_000, 3_000L);
    }

    private static MockServerWebExchange exchange(String bearer) {
        MockServerHttpRequest.BaseBuilder<?> b = MockServerHttpRequest.get("/api/thing");
        if (bearer != null) b.header(HttpHeaders.AUTHORIZATION, "Bearer " + bearer);
        return MockServerWebExchange.from(b.build());
    }

    // ── (i) non-bff bearer ⇒ forwarded untouched ────────────────────────────────

    @Test
    void nonBffBearer_forwardedUntouched_noExchange() {
        var stub = new StubExchange(n -> Mono.error(new AssertionError("must not call admin-bff")));
        var f = filter(stub);
        var ex = exchange("eyJ.native.jwt");   // a real JWT, NOT a bff_ session
        var chain = new RecordingChain();

        StepVerifier.create(f.filter(ex, chain)).verifyComplete();

        assertThat(chain.forwarded).isTrue();
        assertThat(chain.forwardedAuth()).isEqualTo("Bearer eyJ.native.jwt");
        assertThat(stub.calls).hasValue(0);
    }

    // ── (ii) anonymous (no bearer) ⇒ forwarded untouched ────────────────────────

    @Test
    void anonymousNoBearer_forwardedUntouched_noExchange() {
        var stub = new StubExchange(n -> Mono.error(new AssertionError("must not call admin-bff")));
        var f = filter(stub);
        var ex = exchange(null);
        var chain = new RecordingChain();

        StepVerifier.create(f.filter(ex, chain)).verifyComplete();

        assertThat(chain.forwarded).isTrue();
        assertThat(chain.forwardedAuth()).isNull();
        assertThat(stub.calls).hasValue(0);
    }

    // ── (iii) bff_ bearer + stubbed 200 ⇒ Authorization rewritten, forwarded ─────

    @Test
    void bffBearer_swap200_rewritesAuthorizationToCustodyJwt_andForwards() {
        var stub = new StubExchange(n -> Mono.just(jsonResponse(HttpStatus.OK, "{\"bearer\":\"custody.jwt.value\"}")));
        var f = filter(stub);
        var ex = exchange("bff_opaque-session-abc");
        var chain = new RecordingChain();

        StepVerifier.create(f.filter(ex, chain)).verifyComplete();

        assertThat(chain.forwarded).isTrue();
        assertThat(chain.forwardedAuth()).isEqualTo("Bearer custody.jwt.value");
        assertThat(stub.calls).hasValue(1);
    }

    // ── (iv) FAIL-CLOSED on every failure mode ⇒ 401, raw bff_ NEVER forwarded ───

    @Test
    void failClosed_adminBff401_is401_chainNeverSubscribed() {
        var stub = new StubExchange(n -> Mono.just(jsonResponse(HttpStatus.UNAUTHORIZED, "")));
        assertFailClosed(stub);
    }

    @Test
    void failClosed_adminBff500_is401_chainNeverSubscribed() {
        var stub = new StubExchange(n -> Mono.just(jsonResponse(HttpStatus.INTERNAL_SERVER_ERROR, "")));
        assertFailClosed(stub);
    }

    @Test
    void failClosed_timeout_is401_chainNeverSubscribed() {
        // A response that never arrives within the request timeout — the filter's
        // .timeout(...) fires and the error path maps to 401 (never a forward).
        var stub = new StubExchange(n -> Mono.<ClientResponse>never()
                .delaySubscription(Duration.ofSeconds(30)));
        // Use a short request timeout so the test is fast but still exercises .timeout().
        WebClient client = WebClient.builder().baseUrl("http://admin-bff:8080").exchangeFunction(stub).build();
        var f = new BffJwtExchangeWebFilter(client, "X-Internal-Token", "secret-internal-token",
                60_000L, 10_000, 50L /* 50ms request timeout */);
        var ex = exchange("bff_will-time-out");
        var chain = new RecordingChain();

        StepVerifier.create(f.filter(ex, chain)).verifyComplete();

        assertThat(chain.forwarded).as("chain must NOT be subscribed on timeout").isFalse();
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void failClosed_emptyBody_is401_chainNeverSubscribed() {
        // 200 but no/blank bearer in the body — must NOT be treated as a swap.
        var stub = new StubExchange(n -> Mono.just(jsonResponse(HttpStatus.OK, "{\"bearer\":\"\"}")));
        assertFailClosed(stub);
    }

    @Test
    void failClosed_webClientException_is401_chainNeverSubscribed() {
        var stub = new StubExchange(n -> Mono.error(new IOException("connection refused")));
        assertFailClosed(stub);
    }

    private void assertFailClosed(StubExchange stub) {
        var f = filter(stub);
        var ex = exchange("bff_doomed-session");
        var chain = new RecordingChain();

        StepVerifier.create(f.filter(ex, chain)).verifyComplete();

        assertThat(chain.forwarded).as("chain must NOT be subscribed on a failed swap").isFalse();
        assertThat(chain.forwardedAuth()).as("raw bff_ must NEVER be forwarded downstream").isNull();
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    // ── (v) CACHE: two requests same bff_ within TTL ⇒ admin-bff called ONCE ─────

    @Test
    void cache_twoRequestsSameBffWithinTtl_callsAdminBffOnce() {
        var stub = new StubExchange(n -> Mono.just(jsonResponse(HttpStatus.OK, "{\"bearer\":\"custody-1\"}")));
        var f = filter(stub);

        for (int i = 0; i < 2; i++) {
            var ex = exchange("bff_same-session");
            var chain = new RecordingChain();
            StepVerifier.create(f.filter(ex, chain)).verifyComplete();
            assertThat(chain.forwardedAuth()).isEqualTo("Bearer custody-1");
        }
        assertThat(stub.calls).as("second request served from cache").hasValue(1);
    }

    @Test
    void cache_afterTtlExpiry_callsAdminBffAgain() throws InterruptedException {
        var stub = new StubExchange(n -> Mono.just(jsonResponse(HttpStatus.OK, "{\"bearer\":\"custody-" + n + "\"}")));
        var f = filter(stub, 30L /* 30ms TTL */);

        var ex1 = exchange("bff_session-x");
        var c1 = new RecordingChain();
        StepVerifier.create(f.filter(ex1, c1)).verifyComplete();
        assertThat(c1.forwardedAuth()).isEqualTo("Bearer custody-1");

        Thread.sleep(60);   // let the entry expire

        var ex2 = exchange("bff_session-x");
        var c2 = new RecordingChain();
        StepVerifier.create(f.filter(ex2, c2)).verifyComplete();
        assertThat(c2.forwardedAuth()).as("after TTL the swap is re-fetched").isEqualTo("Bearer custody-2");
        assertThat(stub.calls).hasValue(2);
    }

    // ── (v-b) DISABLE: ttl <= 0 ⇒ cache OFF, every request re-consults admin-bff ──

    @Test
    void cache_ttlZero_disablesCache_everyRequestReExchangesForZeroBypassWindow() {
        // The security knob: cache-ttl-ms=0 turns the positive cache OFF so a session
        // suspended between requests is re-checked at admin-bff's exchange gate EVERY time
        // (no ≤TTL bypass window). Each request forwards the freshly-swapped JWT.
        var stub = new StubExchange(n -> Mono.just(jsonResponse(HttpStatus.OK, "{\"bearer\":\"custody-" + n + "\"}")));
        var f = filter(stub, 0L);

        for (int i = 1; i <= 3; i++) {
            var ex = exchange("bff_same-session");
            var chain = new RecordingChain();
            StepVerifier.create(f.filter(ex, chain)).verifyComplete();
            assertThat(chain.forwardedAuth()).isEqualTo("Bearer custody-" + i);
        }
        assertThat(stub.calls).as("cache disabled ⇒ admin-bff re-consulted every request").hasValue(3);
    }

    @Test
    void cache_ttlNegative_alsoDisablesCache() {
        var stub = new StubExchange(n -> Mono.just(jsonResponse(HttpStatus.OK, "{\"bearer\":\"c-" + n + "\"}")));
        var f = filter(stub, -1L);

        for (int i = 1; i <= 2; i++) {
            var ex = exchange("bff_neg-ttl");
            var chain = new RecordingChain();
            StepVerifier.create(f.filter(ex, chain)).verifyComplete();
        }
        assertThat(stub.calls).as("a negative ttl is treated as disabled, not cached").hasValue(2);
    }

    // ── (v-c) the EFFECTIVE wired default — guards Java/YAML drift ────────────────

    @Test
    void applicationYml_cacheTtlDefault_is5000_notTheOld60s_suspensionWindow() throws java.io.IOException {
        // The constructor's @Value(":5000") fallback is DEAD while application.yml supplies the
        // key, so the operative default is whatever the YAML pins. This test fails if the YAML
        // default drifts back to 60000 (or anything but 5000) — which would silently reopen the
        // full-minute suspension-bypass window the security fix exists to close. The other cache
        // tests pass cacheTtlMs straight to the constructor and CANNOT catch this.
        var sources = new org.springframework.boot.env.YamlPropertySourceLoader()
                .load("application.yml", new org.springframework.core.io.ClassPathResource("application.yml"));
        String raw = sources.stream()
                .map(ps -> ps.getProperty("hugmesh.gateway.bff-exchange.cache-ttl-ms"))
                .filter(java.util.Objects::nonNull).map(String::valueOf)
                .findFirst().orElse(null);
        assertThat(raw)
                .as("application.yml must default bff-exchange cache-ttl-ms to 5000ms, not the old 60000ms")
                .isNotNull().contains(":5000}").doesNotContain("60000");
    }

    // ── (vi) NEGATIVE-NEVER-CACHED: failed swap then a successful one ⇒ 2 calls ──

    @Test
    void negativeNeverCached_failedThenSuccessfulSwap_secondCallHitsAdminBff() {
        // First call 401s (fail-closed); the SAME bff_ must NOT have a cached 401, so a
        // subsequent success genuinely re-calls the admin-bff and forwards.
        var stub = new StubExchange(n -> n == 1
                ? Mono.just(jsonResponse(HttpStatus.UNAUTHORIZED, ""))
                : Mono.just(jsonResponse(HttpStatus.OK, "{\"bearer\":\"now-valid\"}")));
        var f = filter(stub);

        var ex1 = exchange("bff_recovers");
        var c1 = new RecordingChain();
        StepVerifier.create(f.filter(ex1, c1)).verifyComplete();
        assertThat(c1.forwarded).as("first swap fails closed").isFalse();
        assertThat(ex1.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        var ex2 = exchange("bff_recovers");
        var c2 = new RecordingChain();
        StepVerifier.create(f.filter(ex2, c2)).verifyComplete();
        assertThat(c2.forwardedAuth()).as("no cached negative — the recovered swap forwards").isEqualTo("Bearer now-valid");
        assertThat(stub.calls).as("the failure was NOT cached, so the admin-bff was re-called").hasValue(2);
    }

    // ── (vii) outbound call stamps X-Internal-Token + the {"token":"bff_…"} body ─

    @Test
    void outboundCall_stampsInternalTokenHeader_andTokenBody() {
        var stub = new StubExchange(n -> Mono.just(jsonResponse(HttpStatus.OK, "{\"bearer\":\"jwt\"}")));
        var f = filter(stub);
        var ex = exchange("bff_inspect-me");
        var chain = new RecordingChain();

        StepVerifier.create(f.filter(ex, chain)).verifyComplete();

        assertThat(stub.lastInternalToken).hasValue("secret-internal-token");
        assertThat(stub.lastBody.get()).contains("\"token\"").contains("bff_inspect-me");
    }
}
