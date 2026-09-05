package net.hugmesh.gateway.filter;

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
        return filter(stub, cacheTtlMs, BffJwtExchangeWebFilter.DEFAULT_CACHE_TTL_CEILING_MS, 10_000);
    }

    /** Full-control factory: TTL, the CEILING the TTL is clamped to, and the entry bound. */
    private static BffJwtExchangeWebFilter filter(StubExchange stub, long cacheTtlMs,
                                                  long cacheTtlMaxMs, int cacheMaxSize) {
        WebClient client = WebClient.builder()
                .baseUrl("http://admin-bff:8080")
                .exchangeFunction(stub)
                .build();
        return new BffJwtExchangeWebFilter(client, "X-Internal-Token", "secret-internal-token",
                cacheTtlMs, cacheTtlMaxMs, cacheMaxSize, 3_000L);
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
                60_000L, BffJwtExchangeWebFilter.DEFAULT_CACHE_TTL_CEILING_MS, 10_000,
                50L /* 50ms request timeout */);
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

    // ── (v-d) THE BOUND ITSELF — the clamp, its configurable ceiling, the entry cap ─
    //
    // These exist because the bound was measurably UNGUARDED: on the pre-change tree,
    // deleting `Math.min(cacheTtlMillis, 60_000L)`, widening it to 600_000L, deleting the
    // cache-max-size check in putCached, and deleting the Math.max floor ALL left this
    // suite green. A bound nothing holds in place is a comment, not a bound.

    @Test
    void cacheTtl_overTheCeiling_isClampedDownToIt_notHonouredAsConfigured() {
        // A chart/env override asking for ten minutes of positive cache must NOT get ten
        // minutes of suspension-staleness: the effective TTL is the ceiling.
        var stub = new StubExchange(n -> Mono.just(jsonResponse(HttpStatus.OK, "{\"bearer\":\"c\"}")));
        var f = filter(stub, 600_000L, BffJwtExchangeWebFilter.DEFAULT_CACHE_TTL_CEILING_MS, 10_000);

        assertThat(f.cacheTtlMillis())
                .as("effective TTL = min(configured, ceiling) — the clamp IS the bound")
                .isEqualTo(BffJwtExchangeWebFilter.DEFAULT_CACHE_TTL_CEILING_MS);
        assertThat(f.cacheEnabled()).isTrue();
    }

    @Test
    void cacheTtlCeiling_documentedDefault_is60000ms() {
        // The ceiling was an anonymous 60_000L literal inside the clamp expression. Naming
        // it is what lets this assertion exist at all; the YAML guard below pins the wired
        // default, this one pins the code-side fallback the @Value falls back to.
        assertThat(BffJwtExchangeWebFilter.DEFAULT_CACHE_TTL_CEILING_MS).isEqualTo(60_000L);
        var stub = new StubExchange(n -> Mono.just(jsonResponse(HttpStatus.OK, "{\"bearer\":\"c\"}")));
        assertThat(filter(stub, 5_000L).cacheTtlCeilingMillis()).isEqualTo(60_000L);
    }

    @Test
    void cacheTtlCeiling_isConfigurable_andCanTightenBelowTheConfiguredTtl() {
        // The point of making the ceiling a property: a ban-critical deployment pins a
        // tighter guaranteed bound ONCE, instead of auditing every chart override of
        // cache-ttl-ms. 5s configured, 1s ceiling ⇒ a 1s staleness window.
        var stub = new StubExchange(n -> Mono.just(jsonResponse(HttpStatus.OK, "{\"bearer\":\"c-" + n + "\"}")));
        var f = filter(stub, 5_000L, 1_000L, 10_000);

        assertThat(f.cacheTtlMillis()).isEqualTo(1_000L);
        assertThat(f.cacheTtlCeilingMillis()).isEqualTo(1_000L);
    }

    @Test
    void cacheTtlCeiling_nonPositive_disablesTheCache_soAMisconfiguredCeilingCannotWiden() {
        // The fail-CLOSED reading of "maximum cache lifetime = 0": no entry may live, so
        // the cache is off and every request re-consults admin-bff's suspension gate. The
        // opposite reading (ignore the bad ceiling, keep the 5s TTL) would let a typo
        // silently REOPEN the window, which is the bug class this bound exists for.
        var stub = new StubExchange(n -> Mono.just(jsonResponse(HttpStatus.OK, "{\"bearer\":\"c-" + n + "\"}")));
        var f = filter(stub, 5_000L, 0L, 10_000);

        assertThat(f.cacheEnabled()).isFalse();
        assertThat(f.cacheTtlMillis()).isZero();
        for (int i = 1; i <= 3; i++) {
            var ex = exchange("bff_ceiling-zero");
            var chain = new RecordingChain();
            StepVerifier.create(f.filter(ex, chain)).verifyComplete();
            assertThat(chain.forwardedAuth()).isEqualTo("Bearer c-" + i);
        }
        assertThat(stub.calls).as("ceiling 0 ⇒ no caching ⇒ the gate is re-consulted every request")
                .hasValue(3);
        assertThat(f.cachedEntryCount()).isZero();
    }

    @Test
    void cacheDisabled_neverWritesTheCacheMap_notEvenExpiredEntries() {
        // Pins the DOCUMENTED disabled posture ("never read OR written") rather than just
        // its externally-identical side effect. Without this, making cacheEnabled always
        // true is invisible: entries written with a 0ms TTL are born expired, so the
        // re-exchange counts match while the map silently fills to cache-max-size.
        var stub = new StubExchange(n -> Mono.just(jsonResponse(HttpStatus.OK, "{\"bearer\":\"c-" + n + "\"}")));
        var f = filter(stub, 0L);

        for (int i = 0; i < 5; i++) {
            StepVerifier.create(f.filter(exchange("bff_off-" + i), new RecordingChain())).verifyComplete();
        }
        assertThat(f.cacheEnabled()).isFalse();
        assertThat(f.cachedEntryCount()).as("the disabled cache is never written").isZero();
        // NOT CLOSED, deliberately: dropping the `cacheEnabled ? … : null` guard on the
        // cache READ stays green, and is an EQUIVALENT mutant given the write guard above —
        // with writes gated off the map is provably empty, so a read of it can only ever
        // return null. Closing it would need a production hook to seed the cache from a
        // test, i.e. production surface added for a test's benefit. Recorded here rather
        // than papered over; the pair (read guard + write guard) is only observable through
        // the write, which IS guarded.
    }

    @Test
    void cacheMaxSize_boundsTheMap_underAFloodOfDistinctSessions_withoutDenyingAnyone() {
        // The entry bound sheds CACHE, never AUTHORIZATION: past capacity each request
        // still swaps and forwards, it just doesn't get memoised. A long TTL keeps every
        // entry live so the expired-sweep cannot mask a missing bound.
        var stub = new StubExchange(n -> Mono.just(jsonResponse(HttpStatus.OK, "{\"bearer\":\"c-" + n + "\"}")));
        var f = filter(stub, 60_000L, 60_000L, 4);

        for (int i = 0; i < 50; i++) {
            var chain = new RecordingChain();
            StepVerifier.create(f.filter(exchange("bff_flood-" + i), chain)).verifyComplete();
            assertThat(chain.forwardedAuth()).as("over-capacity requests are still authorized")
                    .isEqualTo("Bearer c-" + (i + 1));
        }
        assertThat(f.cacheMaxSize()).isEqualTo(4);
        assertThat(f.cachedEntryCount())
                .as("50 distinct sessions must not grow a 4-entry cache")
                .isLessThanOrEqualTo(4);
    }

    @Test
    void cacheMaxSize_nonPositive_isFlooredToOne_notLeftUnbounded() {
        var stub = new StubExchange(n -> Mono.just(jsonResponse(HttpStatus.OK, "{\"bearer\":\"c-" + n + "\"}")));
        var f = filter(stub, 60_000L, 60_000L, 0);

        assertThat(f.cacheMaxSize()).as("a 0/negative bound must floor to 1, never to unbounded")
                .isEqualTo(1);
        for (int i = 0; i < 10; i++) {
            StepVerifier.create(f.filter(exchange("bff_floor-" + i), new RecordingChain())).verifyComplete();
        }
        assertThat(f.cachedEntryCount()).isLessThanOrEqualTo(1);
    }

    @Test
    void applicationYml_cacheTtlCeilingAndMaxSize_areWiredWithTheDocumentedDefaults()
            throws java.io.IOException {
        // Same drift guard as the cache-ttl-ms one above, for the two knobs this change
        // added: the @Value fallbacks are DEAD while application.yml supplies the keys, so
        // an unwired (or re-defaulted) YAML key is what actually ships.
        var sources = new org.springframework.boot.env.YamlPropertySourceLoader()
                .load("application.yml", new org.springframework.core.io.ClassPathResource("application.yml"));
        assertThat(yamlValue(sources, "hugmesh.gateway.bff-exchange.cache-ttl-max-ms"))
                .as("the TTL ceiling must be wired + default to the documented 60000ms")
                .isNotNull().contains(":60000}");
        assertThat(yamlValue(sources, "hugmesh.gateway.bff-exchange.cache-max-size"))
                .as("the entry bound must be wired + default to the documented 10000")
                .isNotNull().contains(":10000}");
    }

    @Test
    void constructorValueFallbacks_matchTheDocumentedConstantAndTheWiredYaml()
            throws java.io.IOException {
        // The @Value fallbacks are what Spring injects when the property is ABSENT — the
        // shape a deployment lands in the moment it REPLACES the config locations
        // (SPRING_CONFIG_LOCATION pointed at a mounted ConfigMap) instead of layering over
        // the packaged application.yml, and the numbers the class javadoc calls "the
        // documented default". Nothing pinned them: on the tree that added the ceiling,
        // widening the `cache-ttl-max-ms` fallback to 600000 and reverting the
        // `cache-ttl-ms` fallback to the old 60000 BOTH left this suite and the cookie
        // suite fully green (measured 2026-09-04, 26-mutation battery) — the YAML guards
        // above cannot see the annotation, and every other case passes the constructor
        // explicit values. Read through the real annotation metadata Spring itself reads
        // (never the source text), and require all THREE statements of each number — the
        // named constant, the @Value fallback, the wired YAML default — to agree, so
        // deleting a YAML key cannot silently drop the effective default onto an
        // unguarded, wider fallback.
        var sources = new org.springframework.boot.env.YamlPropertySourceLoader()
                .load("application.yml", new org.springframework.core.io.ClassPathResource("application.yml"));

        assertThat(valueFallback("hugmesh.gateway.bff-exchange.cache-ttl-max-ms"))
                .as("the ceiling fallback bounds every cache-ttl-ms override, so it is the "
                        + "widest suspension-staleness window this deployment can be configured "
                        + "into — it must equal the documented constant and the wired YAML "
                        + "default. (It is NOT the config-less window: that one is "
                        + "min(cache-ttl-ms, ceiling) = the TTL fallback, pinned below.)")
                .isNotNull()
                .isEqualTo(String.valueOf(BffJwtExchangeWebFilter.DEFAULT_CACHE_TTL_CEILING_MS))
                .isEqualTo(yamlFallback(sources, "hugmesh.gateway.bff-exchange.cache-ttl-max-ms"));

        assertThat(valueFallback("hugmesh.gateway.bff-exchange.cache-ttl-ms"))
                .as("the TTL fallback must stay at 5000ms — reverting it to 60000 reopens "
                        + "the full-minute bypass window with no YAML change to review")
                .isNotNull()
                .isEqualTo("5000")
                .isEqualTo(yamlFallback(sources, "hugmesh.gateway.bff-exchange.cache-ttl-ms"));

        assertThat(valueFallback("hugmesh.gateway.bff-exchange.cache-max-size"))
                .as("the entry-bound fallback must equal the wired YAML default")
                .isNotNull()
                .isEqualTo("10000")
                .isEqualTo(yamlFallback(sources, "hugmesh.gateway.bff-exchange.cache-max-size"));
    }

    @Test
    void everyBffExchangeValueFallback_isWiredInYamlWithTheSameDefault()
            throws java.io.IOException {
        // COMPLETENESS, not a third hand-listed knob: the three-statement principle above
        // was applied to the three knobs this round happened to touch, which left the two
        // it did not — `internal-token-header` and `request-timeout-ms` — unpinned, and an
        // independent battery walked straight through both (measured 2026-09-04: mutating
        // the internal-token-header fallback to X-Bogus-Header, and the request-timeout-ms
        // fallback to 300000, BOTH left this suite and the cookie suite green). Enumerating
        // the constructor's annotations instead of naming knobs means the NEXT knob is
        // pinned the moment it is added, with no test edit to remember.
        //
        // Drift on `internal-token-header` fails CLOSED, not open — admin-bff's
        // InternalTokenWebFilter rejects a swap that arrives under the wrong header name, so
        // every exchange 401s — but a whole-mesh SSO outage whose only symptom is "all
        // sessions 401" is exactly the failure this filter's guards exist to catch early.
        var sources = new org.springframework.boot.env.YamlPropertySourceLoader()
                .load("application.yml", new org.springframework.core.io.ClassPathResource("application.yml"));
        var fallbacks = bffExchangeValueFallbacks();

        assertThat(fallbacks.keySet())
                .as("the constructor's own knobs must all be discovered — an empty or "
                        + "shrunken set would make this guard pass vacuously")
                .contains(BFF_EXCHANGE + "internal-token-header",
                        BFF_EXCHANGE + "internal-token",
                        BFF_EXCHANGE + "cache-ttl-ms",
                        BFF_EXCHANGE + "cache-ttl-max-ms",
                        BFF_EXCHANGE + "cache-max-size",
                        BFF_EXCHANGE + "request-timeout-ms");

        fallbacks.forEach((key, fallback) -> {
            assertThat(yamlValue(sources, key))
                    .as("%s carries an @Value fallback (%s) but is NOT wired in the packaged "
                            + "application.yml — the fallback is then the ONLY statement of the "
                            + "default and nothing reviews a change to it", key, fallback)
                    .isNotNull();
            assertThat(yamlFallback(sources, key))
                    .as("%s: the @Value fallback and the wired YAML default must agree, so "
                            + "deleting the YAML key cannot silently move the effective default",
                            key)
                    .isEqualTo(fallback);
        });
    }

    @Test
    void configLessWindow_isTheTtlFallback_andTheCeilingBoundsEveryOverride() {
        // The ceiling fallback is NOT what a config-less deployment gets: the effective
        // window is min(cache-ttl-ms, cache-ttl-max-ms), i.e. the 5s TTL fallback. Widening
        // the ceiling alone changes nothing until cache-ttl-ms is separately raised. Stated
        // here because the review of the guard above described the ceiling as the config-less
        // window, which overstates it by a factor of twelve — the guard is right, the
        // narrative was not, and an over-claimed bound is how a real one stops being read.
        long ttlFallback = Long.parseLong(valueFallback(BFF_EXCHANGE + "cache-ttl-ms"));
        long ceilingFallback = Long.parseLong(valueFallback(BFF_EXCHANGE + "cache-ttl-max-ms"));
        var stub = new StubExchange(n -> Mono.just(jsonResponse(HttpStatus.OK, "{\"bearer\":\"c\"}")));

        assertThat(filter(stub, ttlFallback, ceilingFallback, 10_000).cacheTtlMillis())
                .as("with NO property source the window is min(%d, %d) = the TTL fallback",
                        ttlFallback, ceilingFallback)
                .isEqualTo(ttlFallback)
                .isEqualTo(5_000L);

        assertThat(filter(stub, Long.MAX_VALUE, ceilingFallback, 10_000).cacheTtlMillis())
                .as("no cache-ttl-ms override can buy a window wider than the ceiling")
                .isEqualTo(ceilingFallback);
    }

    // ── (viii) ORDER — before Spring Security, one slot behind the cookie bridge ──

    @Test
    void order_isBeforeSpringSecurity_andOneSlotBehindTheCookieBridge() {
        // The swap MUST rewrite Authorization before WebFilterChainProxy(-100) hands the
        // value to the JWT decoder, which cannot validate an opaque bff_. Pinned in the
        // ordering Spring Boot slices (BffJwtExchangeFilterOrderingSpringBootTest) but not,
        // until now, in this suite: moving getOrder() to a positive 105 left both filter
        // unit suites green while the SSO bridge was dead. Cheap to hold here too.
        var stub = new StubExchange(n -> Mono.just(jsonResponse(HttpStatus.OK, "{\"bearer\":\"c\"}")));
        var f = filter(stub);

        assertThat(f.getOrder()).isEqualTo(org.springframework.core.Ordered.HIGHEST_PRECEDENCE + 5);
        assertThat(f.getOrder())
                .as("must run BEFORE Spring Security's WebFilterChainProxy (-100)")
                .isLessThan(-100);
        assertThat(new BffCookieToBearerWebFilter().getOrder())
                .as("the cookie bridge must have synthesised the bearer before this filter reads it")
                .isLessThan(f.getOrder());
    }

    /** The {@code @Value} fallback Spring would inject for {@code key} when the property is
     *  absent, read from the REAL constructor parameter annotation (runtime-retained), not
     *  from the source text — a commented-out or reworded annotation cannot satisfy it.
     *
     *  <p>Every declared constructor is scanned and the DISTINCT fallbacks collected, rather
     *  than returning the first hit: {@code getDeclaredConstructors()} has no specified
     *  order, so a second {@code @Value}-carrying constructor would otherwise make this
     *  helper read an arbitrary one of them and pin the wrong number. Two different
     *  fallbacks for one key is itself the defect, so it fails loudly instead. */
    private static String valueFallback(String key) {
        String prefix = "${" + key + ":";
        var found = new java.util.LinkedHashSet<String>();
        for (java.lang.reflect.Constructor<?> ctor
                : BffJwtExchangeWebFilter.class.getDeclaredConstructors()) {
            for (java.lang.annotation.Annotation[] onParam : ctor.getParameterAnnotations()) {
                for (java.lang.annotation.Annotation a : onParam) {
                    if (a instanceof org.springframework.beans.factory.annotation.Value v
                            && v.value().startsWith(prefix) && v.value().endsWith("}")) {
                        found.add(v.value().substring(prefix.length(), v.value().length() - 1));
                    }
                }
            }
        }
        assertThat(found)
                .as("%s must have ONE @Value fallback across all constructors — "
                        + "declared-constructor order is unspecified, so disagreeing "
                        + "fallbacks would be read arbitrarily", key)
                .hasSizeLessThan(2);
        return found.isEmpty() ? null : found.iterator().next();
    }

    /** The filter's own property prefix — the namespace this suite pins end to end. */
    private static final String BFF_EXCHANGE = "hugmesh.gateway.bff-exchange.";

    /** Every {@code @Value} the filter's constructor(s) declare under {@link #BFF_EXCHANGE},
     *  as key -> annotation fallback, read from the runtime annotations Spring itself reads.
     *  A key declared twice with DIFFERENT fallbacks fails loudly (declared-constructor
     *  order is unspecified, so one of them would otherwise be picked arbitrarily), and a
     *  placeholder with no {@code :fallback} fails too — an absent property would then be
     *  a startup failure, not a default, and this guard must not silently skip it. */
    private static java.util.Map<String, String> bffExchangeValueFallbacks() {
        var found = new java.util.TreeMap<String, java.util.LinkedHashSet<String>>();
        for (java.lang.reflect.Constructor<?> ctor
                : BffJwtExchangeWebFilter.class.getDeclaredConstructors()) {
            for (java.lang.annotation.Annotation[] onParam : ctor.getParameterAnnotations()) {
                for (java.lang.annotation.Annotation a : onParam) {
                    if (!(a instanceof org.springframework.beans.factory.annotation.Value v)) continue;
                    String raw = v.value();
                    if (!raw.startsWith("${" + BFF_EXCHANGE) || !raw.endsWith("}")) continue;
                    String body = raw.substring(2, raw.length() - 1);
                    int colon = body.indexOf(':');
                    assertThat(colon)
                            .as("%s declares no :fallback — an absent property would fail "
                                    + "startup rather than default, so it cannot be pinned", raw)
                            .isPositive();
                    found.computeIfAbsent(body.substring(0, colon),
                            k -> new java.util.LinkedHashSet<>()).add(body.substring(colon + 1));
                }
            }
        }
        var out = new java.util.TreeMap<String, String>();
        found.forEach((key, values) -> {
            assertThat(values)
                    .as("%s must have ONE @Value fallback across all constructors", key)
                    .hasSize(1);
            out.put(key, values.iterator().next());
        });
        return out;
    }

    /** The default baked into application.yml's {@code ${ENV_VAR:default}} placeholder for
     *  {@code key} — {@code null} when the key is not wired at all. */
    private static String yamlFallback(
            java.util.List<org.springframework.core.env.PropertySource<?>> sources, String key) {
        String raw = yamlValue(sources, key);
        if (raw == null) return null;
        int colon = raw.lastIndexOf(':');
        int brace = raw.lastIndexOf('}');
        return (colon < 0 || brace < colon) ? raw : raw.substring(colon + 1, brace);
    }

    private static String yamlValue(
            java.util.List<org.springframework.core.env.PropertySource<?>> sources, String key) {
        return sources.stream()
                .map(ps -> ps.getProperty(key))
                .filter(java.util.Objects::nonNull).map(String::valueOf)
                .findFirst().orElse(null);
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
