package net.hugmesh.gateway.filter;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.gateway.config.BffSessionProperties;
import net.hugmesh.gateway.filter.BffSessionAuthFilter.MeResponse;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Focused contract test for {@link BffSessionAuthFilter} covering the four
 * required scenarios:
 *
 * <ol>
 *   <li>bff_ cookie present + BFF returns 200 → SecurityContext populated with
 *       the authenticated principal.</li>
 *   <li>bff_ cookie present + BFF returns 401 → chain proceeds unauthenticated,
 *       SecurityContext NOT populated.</li>
 *   <li>No bff_ cookie → chain proceeds without any BFF introspection call.</li>
 *   <li>Introspect skipped (all paths skipped, effectively a no-op) → chain
 *       proceeds immediately without touching BFF.</li>
 * </ol>
 *
 * <p>Uses Mockito only — no Spring context is loaded. The WebClient is mocked
 * at the {@code ResponseSpec} level. All assertions use StepVerifier for the
 * reactive pipeline and AssertJ for the captured state.
 */
@ExtendWith(MockitoExtension.class)
class BffSessionAuthenticationWebFilterTest {

    // ── WebClient mock plumbing ───────────────────────────────────────────────

    /**
     * Builds a fully-mocked WebClient whose terminal {@code bodyToMono} call
     * returns the provided Mono.
     *
     * <p>{@code doReturn} is used throughout instead of {@code when(...).thenReturn(...)}
     * to avoid the Java compiler wildcard-capture errors that arise from
     * {@code RequestHeadersSpec<?>}'s type parameter when Mockito tries to match
     * the stub return value. This is the standard Mockito pattern for heavily
     * generic Spring WebClient interfaces.
     */
    @SuppressWarnings("rawtypes")
    private static WebClient mockWebClient(Mono<MeResponse> response) {
        WebClient client = mock(WebClient.class);
        WebClient.RequestHeadersUriSpec uriSpec = mock(WebClient.RequestHeadersUriSpec.class);
        WebClient.RequestHeadersSpec headersSpec = mock(WebClient.RequestHeadersSpec.class);
        WebClient.ResponseSpec responseSpec = mock(WebClient.ResponseSpec.class);

        doReturn(uriSpec).when(client).get();
        doReturn(headersSpec).when(uriSpec).uri(anyString());
        // header() is called N times (Authorization, then X-Forwarded-For) — stub
        // all calls on headersSpec to return headersSpec so the chain composes.
        doReturn(headersSpec).when(headersSpec).header(anyString(), anyString());
        doReturn(headersSpec).when(headersSpec).accept(any());
        doReturn(responseSpec).when(headersSpec).retrieve();
        when(responseSpec.bodyToMono(MeResponse.class)).thenReturn(response);

        return client;
    }

    // ── filter factory helpers ────────────────────────────────────────────────

    /** Creates a filter with default skip-paths (the real production set). */
    private static BffSessionAuthFilter filterWithDefaults(WebClient client) {
        BffSessionProperties props = new BffSessionProperties();
        props.setEnabled(true);
        props.setTimeoutMs(2000);
        // Default skip-paths are already populated by BffSessionProperties constructor.
        return new BffSessionAuthFilter(client, props);
    }

    /**
     * Creates a filter whose skip-paths cover ALL requests (wildcard "/**").
     * Every request is therefore a no-op: the filter forwards immediately
     * without calling BFF, regardless of whether a bff_ token is present.
     * This models the "introspect-uri blank / filter is a no-op" scenario.
     */
    private static BffSessionAuthFilter filterAllPathsSkipped(WebClient client) {
        BffSessionProperties props = new BffSessionProperties();
        props.setEnabled(true);
        props.setTimeoutMs(2000);
        props.setSkipPaths(List.of("/**"));
        return new BffSessionAuthFilter(client, props);
    }

    // ── capturing chain helper ────────────────────────────────────────────────

    /**
     * A {@link WebFilterChain} that records whether it was invoked and captures
     * the {@link Authentication} that was present in the downstream
     * {@link SecurityContext} at the time of invocation.
     */
    private static final class CapturingChain implements WebFilterChain {
        final AtomicBoolean forwarded = new AtomicBoolean(false);
        final AtomicReference<Authentication> auth = new AtomicReference<>();

        @Override
        public Mono<Void> filter(ServerWebExchange exchange) {
            forwarded.set(true);
            return ReactiveSecurityContextHolder.getContext()
                    .map(SecurityContext::getAuthentication)
                    .doOnNext(auth::set)
                    .then();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Scenario 1: bff_ cookie present + BFF returns 200 with user info
    //             → authentication is set in the SecurityContext
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void scenario1_cookiePresent_bff200_populatesSecurityContext() {
        // Arrange: BFF returns a valid, active, fully-registered user.
        MeResponse meResponse = new MeResponse(
                "google:user@example.com",
                "google",
                List.of("user", "admin"),
                /* registrationComplete= */ true,
                /* status= */ "active",
                /* mfaSatisfied= */ false
        );
        BffSessionAuthFilter filter = filterWithDefaults(mockWebClient(Mono.just(meResponse)));

        // The request carries a bff_session cookie on a non-skipped path.
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/dashboard")
                .cookie(new HttpCookie(BffSessionAuthFilter.SESSION_COOKIE, "bff_abc123"))
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        CapturingChain chain = new CapturingChain();

        // Act + Assert: the pipeline completes without error.
        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        // The downstream chain was reached.
        assertThat(chain.forwarded.get())
                .as("the downstream chain must be invoked on a successful authentication")
                .isTrue();

        // The SecurityContext carries an authenticated principal.
        Authentication auth = chain.auth.get();
        assertThat(auth)
                .as("an Authentication must be present in the downstream SecurityContext")
                .isNotNull();
        assertThat(auth.isAuthenticated())
                .as("the Authentication must be marked as authenticated")
                .isTrue();
        assertThat(auth.getName())
                .as("the principal name must match the id from the BFF /bff/me response")
                .isEqualTo("google:user@example.com");

        // Authorities: ROLE_USER floor + ROLE_ADMIN from the BFF role list.
        List<String> grantedAuthorities = auth.getAuthorities().stream()
                .map(a -> a.getAuthority())
                .toList();
        assertThat(grantedAuthorities)
                .as("ROLE_USER floor and ROLE_ADMIN from the BFF roles must both be present")
                .contains("ROLE_USER", "ROLE_ADMIN");
        assertThat(grantedAuthorities)
                .as("MFA_SATISFIED must not be present when mfaSatisfied is false")
                .doesNotContain("MFA_SATISFIED");

        // The response status must not have been set (the filter does not touch it on success).
        assertThat(exchange.getResponse().getStatusCode())
                .as("a successful introspection must leave the response status untouched")
                .isNull();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Scenario 2: bff_ cookie present + BFF returns 401
    //             → chain proceeds without authentication (fail-open for expired tokens)
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void scenario2_cookiePresent_bff401_chainProceedsUnauthenticated() {
        // Arrange: BFF responds with 401 (token expired or not found).
        WebClientResponseException ex401 = WebClientResponseException.create(
                401, "Unauthorized", HttpHeaders.EMPTY, new byte[0], null);
        BffSessionAuthFilter filter = filterWithDefaults(mockWebClient(Mono.error(ex401)));

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/dashboard")
                .cookie(new HttpCookie(BffSessionAuthFilter.SESSION_COOKIE, "bff_expiredtoken"))
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        CapturingChain chain = new CapturingChain();

        // Act + Assert: the pipeline completes without error.
        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        // The chain is still invoked — the filter fails open on 401 so that the
        // downstream anyExchange().authenticated() rule can produce its own 401
        // for protected paths, while public/permitAll paths succeed normally.
        assertThat(chain.forwarded.get())
                .as("the downstream chain must be invoked even when the BFF returns 401")
                .isTrue();

        // No authentication was injected into the SecurityContext.
        assertThat(chain.auth.get())
                .as("the SecurityContext must be empty (no Authentication) when BFF returns 401")
                .isNull();

        // The filter must not have stamped a response status — it is the downstream
        // security chain's responsibility to issue a 401 for protected paths.
        assertThat(exchange.getResponse().getStatusCode())
                .as("BffSessionAuthFilter must not set a response status on a BFF 401")
                .isNull();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Scenario 3: no bff_ cookie present
    //             → chain proceeds without any BFF introspection call
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void scenario3_noCookie_chainProceedsWithoutCallingBff() {
        // Arrange: no bff_ token in headers or cookies.
        // The WebClient mock must NOT have its get() called.
        WebClient client = mock(WebClient.class);
        BffSessionAuthFilter filter = filterWithDefaults(client);

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/dashboard").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        AtomicBoolean chainInvoked = new AtomicBoolean(false);
        WebFilterChain chain = ex -> {
            chainInvoked.set(true);
            return Mono.empty();
        };

        // Act + Assert: the pipeline completes without error.
        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        // The downstream chain is invoked — the filter is transparent.
        assertThat(chainInvoked.get())
                .as("the downstream chain must be invoked when no bff_ token is present")
                .isTrue();

        // BFF was never contacted — there was nothing to introspect.
        verify(client, never()).get();

        // No response status was written.
        assertThat(exchange.getResponse().getStatusCode())
                .as("the response status must not be set when there is no bff_ token")
                .isNull();
    }

    /**
     * Companion to scenario 3: a non-bff_ JWT Bearer header (e.g. a Casdoor JWT)
     * is present but the filter must treat it as "no bff_ token" and skip BFF
     * introspection entirely, leaving the Casdoor JWT path undisturbed.
     */
    @Test
    void scenario3_nonBffBearerHeader_chainProceedsWithoutCallingBff() {
        WebClient client = mock(WebClient.class);
        BffSessionAuthFilter filter = filterWithDefaults(client);

        // A conventional Casdoor JWT — does NOT start with "bff_".
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/dashboard")
                .header(HttpHeaders.AUTHORIZATION, "Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        AtomicBoolean chainInvoked = new AtomicBoolean(false);
        WebFilterChain chain = ex -> {
            chainInvoked.set(true);
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        assertThat(chainInvoked.get())
                .as("a non-bff_ bearer header must be left alone; chain must be invoked")
                .isTrue();
        verify(client, never()).get();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Scenario 4: all paths are skipped (introspect effectively disabled / no-op)
    //             → filter is a no-op, chain proceeds immediately without BFF call
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * When every path matches a skip-pattern the filter is effectively a no-op.
     * This models configurations where the BFF introspect URI is blank or where
     * the operator has excluded all traffic — the filter must simply forward every
     * request without consulting BFF, even when a valid bff_ token is present.
     */
    @Test
    void scenario4_allPathsSkipped_filterIsNoOp_chainProceeds() {
        // The WebClient mock must NOT have its get() called even though the request
        // carries a valid-looking bff_session cookie.
        WebClient client = mock(WebClient.class);
        BffSessionAuthFilter filter = filterAllPathsSkipped(client);

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/dashboard")
                .cookie(new HttpCookie(BffSessionAuthFilter.SESSION_COOKIE, "bff_validtoken"))
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        AtomicBoolean chainInvoked = new AtomicBoolean(false);
        WebFilterChain chain = ex -> {
            chainInvoked.set(true);
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        assertThat(chainInvoked.get())
                .as("the downstream chain must be invoked when the path is skipped")
                .isTrue();

        // BFF was never contacted on a skipped path.
        verify(client, never()).get();

        assertThat(exchange.getResponse().getStatusCode())
                .as("the response status must not be set on a skipped path")
                .isNull();
    }

    /**
     * Verifies that the skip-path mechanism is not path-specific — multiple paths
     * all skip BFF when covered by the "/**" wildcard.
     */
    @Test
    void scenario4_multipleSkippedPaths_allForwardWithoutBffCall() {
        WebClient client = mock(WebClient.class);
        BffSessionAuthFilter filter = filterAllPathsSkipped(client);

        for (String path : List.of("/api/anything", "/bff/me", "/_matrix/sync", "/actuator/health")) {
            MockServerHttpRequest request = MockServerHttpRequest.get(path)
                    .cookie(new HttpCookie(BffSessionAuthFilter.SESSION_COOKIE, "bff_tokenvalue"))
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);
            AtomicBoolean chainInvoked = new AtomicBoolean(false);
            WebFilterChain chain = ex -> {
                chainInvoked.set(true);
                return Mono.empty();
            };

            StepVerifier.create(filter.filter(exchange, chain))
                    .verifyComplete();

            assertThat(chainInvoked.get())
                    .as("path %s must be forwarded without a BFF call", path)
                    .isTrue();
        }

        // BFF was never contacted on any of the skipped paths.
        verify(client, never()).get();
    }
}
