package net.hugmesh.gateway.filter;

import org.junit.jupiter.api.Test;
import org.springframework.core.Ordered;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Behaviour contract for {@link BffCookieToBearerWebFilter} — the pre-security
 * cookie-mode bridge that synthesises {@code Authorization: Bearer bff_…} from the
 * {@code bff_session} cookie so a cookie-only browser request is visible to the
 * header-only {@link BffJwtExchangeWebFilter} one slot below. The test list IS the
 * contract: the three forward-untouched paths (header wins / no cookie / non-{@code bff_}
 * cookie), the happy-path synth, the load-bearing COOKIE-RETAINED invariant, and the
 * {@code +4}-before-{@code +5} ordering the whole flow depends on.
 *
 * <p>The cookie-retained case is the regression guard, not a nicety: an earlier revision
 * CONSUMED the cookie here, which starved user-bff's permitAll {@code GET /bff/session}
 * (a cookie-read at the app layer) and 401'd every logged-in browser at the front door —
 * verified live 2026-08-13. A test that only checked the synthesised header would have
 * passed against that broken revision.
 *
 * <p>The filter is pure (header + cookie in, mutated request out), so each case drives it
 * directly against a {@link MockServerWebExchange} and a {@link RecordingChain} — no
 * admin-bff, no Spring context, no swap back-channel.
 */
class BffCookieToBearerWebFilterTest {

    /** A recording chain — flips a flag and captures the (possibly mutated) exchange on forward. */
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
        /** Every raw {@code Cookie} request header value, joined — this is what actually
         *  gets proxied downstream (and {@code null} when the header is gone entirely).
         *  Asserted in preference to {@code getRequest().getCookies()} deliberately: a
         *  MUTATED request's {@code getCookies()} delegates to the ORIGINAL request, so it
         *  keeps reporting a cookie the mutation stripped from the header — an assertion on
         *  it passes against the very consume-the-cookie revision this test exists to
         *  reject. Joined rather than {@code getFirst()} because the mock emits one header
         *  per cookie where a browser sends a single combined one. */
        String forwardedCookieHeader() {
            ServerWebExchange ex = seen.get();
            if (ex == null) return null;
            List<String> values = ex.getRequest().getHeaders().get(HttpHeaders.COOKIE);
            return values == null ? null : String.join("; ", values);
        }
    }

    private final BffCookieToBearerWebFilter filter = new BffCookieToBearerWebFilter();

    /** A GET carrying the given Authorization header (null ⇒ none) and bff_session cookie (null ⇒ none). */
    private static MockServerWebExchange exchange(String authorization, String sessionCookie) {
        MockServerHttpRequest.BaseBuilder<?> b = MockServerHttpRequest.get("/api/thing");
        if (authorization != null) b.header(HttpHeaders.AUTHORIZATION, authorization);
        if (sessionCookie != null) {
            b.cookie(new HttpCookie(BffCookieToBearerWebFilter.SESSION_COOKIE, sessionCookie));
        }
        return MockServerWebExchange.from(b.build());
    }

    // ── (i) HEADER WINS: a client-sent credential is never overwritten ───────────

    @Test
    void existingAuthorizationHeader_isNeverOverwritten_evenWithASessionCookie() {
        // The legacy header path must stay byte-identical: a real Casdoor JWT (or an
        // in-memory bff_ bearer) beats the cookie, so a stale cookie can never hijack
        // the identity a caller explicitly presented.
        var ex = exchange("Bearer eyJ.native.jwt", "bff_stale-cookie-session");
        var chain = new RecordingChain();

        StepVerifier.create(filter.filter(ex, chain)).verifyComplete();

        assertThat(chain.forwarded).isTrue();
        assertThat(chain.forwardedAuth()).isEqualTo("Bearer eyJ.native.jwt");
    }

    @Test
    void blankAuthorizationHeader_isTreatedAsAbsent_andTheCookieIsSynthesised() {
        // "" is not a credential — an empty header must not block the bridge, or a
        // cookie-mode browser behind a proxy that stamps a blank Authorization 401s.
        var ex = exchange("", "bff_opaque-session-abc");
        var chain = new RecordingChain();

        StepVerifier.create(filter.filter(ex, chain)).verifyComplete();

        assertThat(chain.forwardedAuth()).isEqualTo("Bearer bff_opaque-session-abc");
    }

    // ── (ii) NOTHING TO SYNTHESISE ⇒ forwarded untouched ─────────────────────────

    @Test
    void noHeaderAndNoCookie_forwardedUntouched() {
        var ex = exchange(null, null);
        var chain = new RecordingChain();

        StepVerifier.create(filter.filter(ex, chain)).verifyComplete();

        assertThat(chain.forwarded).isTrue();
        assertThat(chain.forwardedAuth()).as("anonymous traffic flows exactly as today").isNull();
    }

    @Test
    void nonBffCookieValue_forwardedUntouched_noBearerSynthesised() {
        // Only a bff_-prefixed value is an opaque session. Anything else in that cookie
        // slot must not be promoted into an Authorization header the exchange filter
        // would then try (and fail) to swap.
        var ex = exchange(null, "not-an-opaque-session");
        var chain = new RecordingChain();

        StepVerifier.create(filter.filter(ex, chain)).verifyComplete();

        assertThat(chain.forwarded).isTrue();
        assertThat(chain.forwardedAuth()).isNull();
    }

    @Test
    void differentCookieName_forwardedUntouched() {
        var req = MockServerHttpRequest.get("/api/thing")
                .cookie(new HttpCookie("some_other_session", "bff_looks-right-wrong-slot"))
                .build();
        var chain = new RecordingChain();

        StepVerifier.create(filter.filter(MockServerWebExchange.from(req), chain)).verifyComplete();

        assertThat(chain.forwarded).isTrue();
        assertThat(chain.forwardedAuth()).isNull();
    }

    // ── (iii) HAPPY PATH: cookie-only ⇒ bearer synthesised ───────────────────────

    @Test
    void cookieOnly_synthesisesBearerFromTheCookieValue() {
        var ex = exchange(null, "bff_opaque-session-abc");
        var chain = new RecordingChain();

        StepVerifier.create(filter.filter(ex, chain)).verifyComplete();

        assertThat(chain.forwarded).isTrue();
        assertThat(chain.forwardedAuth())
                .as("the exchange filter at +5 reads the Authorization header ONLY")
                .isEqualTo("Bearer bff_opaque-session-abc");
        assertThat(ex.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
                .as("the synth lands on the mutated request, not the inbound one")
                .isNull();
    }

    // ── (iv) COOKIE RETAINED — the 2026-08-13 regression guard ───────────────────

    @Test
    void cookieOnly_retainsTheSessionCookieOnTheForwardedRequest() {
        // Consuming the cookie here bought nothing gateway-side (the sibling
        // BffSessionAuthFilter consults the Authorization header first) but starved
        // every cookie-terminated BFF surface downstream — user-bff's permitAll
        // GET /bff/session answered 401 "no session" for every logged-in browser.
        // Both carriers describe the SAME session; both must survive the bridge.
        var ex = exchange(null, "bff_opaque-session-abc");
        var chain = new RecordingChain();

        StepVerifier.create(filter.filter(ex, chain)).verifyComplete();

        assertThat(chain.forwardedCookieHeader())
                .as("bff_session must survive the bridge for the cookie-terminated BFF surfaces")
                .contains(BffCookieToBearerWebFilter.SESSION_COOKIE + "=bff_opaque-session-abc");
    }

    @Test
    void cookieOnly_leavesUnrelatedCookiesAlone() {
        var req = MockServerHttpRequest.get("/api/thing")
                .cookie(new HttpCookie(BffCookieToBearerWebFilter.SESSION_COOKIE, "bff_opaque-session-abc"),
                        new HttpCookie("XSRF-TOKEN", "csrf-value"))
                .build();
        var chain = new RecordingChain();

        StepVerifier.create(filter.filter(MockServerWebExchange.from(req), chain)).verifyComplete();

        assertThat(chain.forwardedAuth()).isEqualTo("Bearer bff_opaque-session-abc");
        assertThat(chain.forwardedCookieHeader())
                .contains(BffCookieToBearerWebFilter.SESSION_COOKIE + "=bff_opaque-session-abc")
                .contains("XSRF-TOKEN=csrf-value");
    }

    // ── (v) ORDERING: +4, one slot AHEAD of the exchange filter ──────────────────

    @Test
    void order_isOneSlotAheadOfTheExchangeFilter_andBeforeSpringSecurity() {
        // The whole bridge is inert if it runs after the swap: the exchange filter would
        // see no Authorization header and forward a cookie-only request unauthenticated.
        var exchangeFilter = new BffJwtExchangeWebFilter(WebClient.builder().build(),
                "X-Internal-Token", "secret-internal-token", 5_000L, 10_000, 3_000L);

        assertThat(filter.getOrder()).isEqualTo(Ordered.HIGHEST_PRECEDENCE + 4);
        assertThat(filter.getOrder())
                .as("the synth must exist by the time the swap filter inspects the header")
                .isLessThan(exchangeFilter.getOrder());
        assertThat(filter.getOrder())
                .as("pre-security: before Spring Security's WebFilterChainProxy(-100)")
                .isLessThan(-100);
    }
}
