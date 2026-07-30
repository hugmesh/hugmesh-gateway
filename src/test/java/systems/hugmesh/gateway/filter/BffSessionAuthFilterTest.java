package systems.hugmesh.gateway.filter;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
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
import systems.hugmesh.gateway.config.BffSessionProperties;
import systems.hugmesh.gateway.filter.BffSessionAuthFilter.MeResponse;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit contract for {@link BffSessionAuthFilter}.
 *
 * <p>The WebClient is mocked at the {@code ResponseSpec} level so all BFF
 * interaction is controlled without a live HTTP server. Tests cover:
 *
 * <ul>
 *   <li>Happy path: {@code bff_} bearer header → authenticated context.</li>
 *   <li>Happy path: {@code bff_session} cookie → authenticated context.</li>
 *   <li>No bff_ token (Casdoor JWT bearer, no cookie) → pass-through unauthenticated.</li>
 *   <li>No Authorization header and no cookie → pass-through unauthenticated.</li>
 *   <li>BFF returns 401 → pass-through unauthenticated (fail-open for expired tokens
 *       on public paths; downstream {@code authenticated()} closes protected paths).</li>
 *   <li>BFF returns 5xx → 503 fail-closed (bff_ token that cannot be validated is
 *       never treated as authenticated).</li>
 *   <li>BFF unreachable (connection refused / timeout) → 503 fail-closed.</li>
 *   <li>BFF returns {@code status:suspended} with 200 → 403 fail-closed.</li>
 *   <li>BFF returns {@code status:banned} with 200 → 403 fail-closed.</li>
 *   <li>Incomplete registration → only {@code ROLE_USER} authority (restricted set).</li>
 *   <li>{@code mfaSatisfied:true} → {@code MFA_SATISFIED} authority added.</li>
 *   <li>Skipped paths bypass the BFF call entirely.</li>
 *   <li>Authority mapping: roles → {@code ROLE_<UPPER>} + {@code ROLE_USER} floor.</li>
 * </ul>
 */
class BffSessionAuthFilterTest {

    // ── WebClient mock plumbing ───────────────────────────────────────────────

    /**
     * Builds a fully-mocked WebClient that returns the given Mono from
     * {@code .retrieve().bodyToMono(MeResponse.class)}.
     *
     * <p>The chain is:
     * {@code WebClient → .get() → .uri() → .header() × N → .accept() → .retrieve() → .bodyToMono()}
     *
     * <p>{@code doReturn} is used instead of {@code when(...).thenReturn(...)} to
     * sidestep the Java compiler's wildcard-capture errors that arise when
     * Mockito's stubbing API infers the wildcard type parameter of
     * {@code RequestHeadersSpec<?>} and then refuses to accept the cast mock as a
     * return value. {@code doReturn} bypasses the type-checking on the return value
     * entirely, which is the standard Mockito pattern for generics-heavy interfaces.
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private static WebClient mockWebClient(Mono<MeResponse> response) {
        WebClient client = mock(WebClient.class);
        WebClient.RequestHeadersUriSpec uriSpec = mock(WebClient.RequestHeadersUriSpec.class);
        WebClient.RequestHeadersSpec headersSpec = mock(WebClient.RequestHeadersSpec.class);
        WebClient.ResponseSpec responseSpec = mock(WebClient.ResponseSpec.class);

        doReturn(uriSpec).when(client).get();
        doReturn(headersSpec).when(uriSpec).uri(anyString());
        doReturn(headersSpec).when(headersSpec).header(anyString(), anyString());
        doReturn(headersSpec).when(headersSpec).accept(any());
        doReturn(responseSpec).when(headersSpec).retrieve();
        when(responseSpec.bodyToMono(MeResponse.class)).thenReturn(response);

        return client;
    }

    /** Like {@link #mockWebClient} but returns the headersSpec too so callers can verify header calls. */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Object[] mockWebClientWithHeadersSpec(Mono<MeResponse> response) {
        WebClient client = mock(WebClient.class);
        WebClient.RequestHeadersUriSpec uriSpec = mock(WebClient.RequestHeadersUriSpec.class);
        WebClient.RequestHeadersSpec headersSpec = mock(WebClient.RequestHeadersSpec.class);
        WebClient.ResponseSpec responseSpec = mock(WebClient.ResponseSpec.class);

        doReturn(uriSpec).when(client).get();
        doReturn(headersSpec).when(uriSpec).uri(anyString());
        doReturn(headersSpec).when(headersSpec).header(anyString(), anyString());
        doReturn(headersSpec).when(headersSpec).accept(any());
        doReturn(responseSpec).when(headersSpec).retrieve();
        when(responseSpec.bodyToMono(MeResponse.class)).thenReturn(response);

        return new Object[]{client, headersSpec};
    }

    // ── filter factory ────────────────────────────────────────────────────────

    private static BffSessionAuthFilter filter(WebClient client) {
        BffSessionProperties props = new BffSessionProperties();
        props.setEnabled(true);
        props.setTimeoutMs(2000);
        return new BffSessionAuthFilter(client, props);
    }

    private static BffSessionAuthFilter filterWithInternalToken(WebClient client, String token) {
        BffSessionProperties props = new BffSessionProperties();
        props.setEnabled(true);
        props.setTimeoutMs(2000);
        props.setInternalToken(token);
        return new BffSessionAuthFilter(client, props);
    }

    // ── recording chain ───────────────────────────────────────────────────────

    /** Captures the Authentication present in the downstream SecurityContext. */
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

    // ── happy path: Authorization header ─────────────────────────────────────

    @Test
    void bearerHeader_validToken_populatesSecurityContext() {
        MeResponse me = new MeResponse("google:user@example.com", "google",
                List.of("user", "admin"), true, "active", false);
        BffSessionAuthFilter f = filter(mockWebClient(Mono.just(me)));

        MockServerHttpRequest req = MockServerHttpRequest.get("/api/dashboard")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_abc123")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain))
                .verifyComplete();

        assertThat(chain.forwarded).isTrue();
        assertThat(chain.auth.get()).isNotNull();
        assertThat(chain.auth.get().isAuthenticated()).isTrue();
        assertThat(chain.auth.get().getName()).isEqualTo("google:user@example.com");

        var authorities = chain.auth.get().getAuthorities().stream()
                .map(a -> a.getAuthority()).toList();
        assertThat(authorities).contains("ROLE_USER", "ROLE_ADMIN");
        assertThat(authorities).doesNotContain("MFA_SATISFIED");
    }

    // ── A5 part-B: the introspect casdoorSub → token details bridge ───────────

    @Test
    void introspectWithCasdoorSub_stampsSessionDetails() {
        // Introspect carried the changeset-292 sub → the token's details slot must carry
        // it (the bridge GatewayRouteAccessFilter's bff_ branch reads to match UUID-form
        // casdoor_user route pins for the native-login carrier).
        MeResponse me = new MeResponse("casdoor:alice@example.test", "casdoor",
                List.of("user"), true, "active", false, "2f3a9c1e-7b4d-4e08-9a21-5c6d7e8f9a0b");
        BffSessionAuthFilter f = filter(mockWebClient(Mono.just(me)));

        MockServerHttpRequest req = MockServerHttpRequest.get("/api/dashboard")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_withsub")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.auth.get()).isNotNull();
        assertThat(chain.auth.get().getDetails())
                .isEqualTo(new BffSessionAuthFilter.SessionDetails(
                        "2f3a9c1e-7b4d-4e08-9a21-5c6d7e8f9a0b"));
    }

    @Test
    void introspectWithoutCasdoorSub_leavesDetailsNull_tokenIdenticalToToday() {
        // Legacy contract (the 6-arg shape — an admin-bff predating the field, or a row
        // not yet re-stamped): details must stay null so the token is byte-identical to
        // the pre-field one; downstream consumers then behave exactly as today.
        MeResponse me = new MeResponse("casdoor:alice@example.test", "casdoor",
                List.of("user"), true, "active", false);
        BffSessionAuthFilter f = filter(mockWebClient(Mono.just(me)));

        MockServerHttpRequest req = MockServerHttpRequest.get("/api/dashboard")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_nosub")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.auth.get()).isNotNull();
        assertThat(chain.auth.get().getDetails()).isNull();
    }

    @Test
    void introspectWithBlankCasdoorSub_leavesDetailsNull() {
        // Blank is "unknown", same as absent — never stamp an empty identity.
        MeResponse me = new MeResponse("casdoor:alice@example.test", "casdoor",
                List.of("user"), true, "active", false, "   ");
        BffSessionAuthFilter f = filter(mockWebClient(Mono.just(me)));

        MockServerHttpRequest req = MockServerHttpRequest.get("/api/dashboard")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_blanksub")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.auth.get()).isNotNull();
        assertThat(chain.auth.get().getDetails()).isNull();
    }

    // ── happy path: cookie ────────────────────────────────────────────────────

    @Test
    void cookie_validToken_populatesSecurityContext() {
        MeResponse me = new MeResponse("discord:someuser", "discord",
                List.of("user"), true, "active", false);
        BffSessionAuthFilter f = filter(mockWebClient(Mono.just(me)));

        MockServerHttpRequest req = MockServerHttpRequest.get("/api/profile")
                .cookie(new HttpCookie(BffSessionAuthFilter.SESSION_COOKIE, "bff_cookieval"))
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain))
                .verifyComplete();

        assertThat(chain.forwarded).isTrue();
        assertThat(chain.auth.get()).isNotNull();
        assertThat(chain.auth.get().getName()).isEqualTo("discord:someuser");
    }

    // ── no bff_ token: Casdoor JWT bearer → pass-through ─────────────────────

    @Test
    void casdoorJwtBearer_isNotABffToken_passesThrough_withoutCallingBff() {
        WebClient client = mock(WebClient.class);
        BffSessionAuthFilter f = filter(client);

        MockServerHttpRequest req = MockServerHttpRequest.get("/api/dashboard")
                .header(HttpHeaders.AUTHORIZATION, "Bearer eyJhbGciOiJSUzI1NiJ9....")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain))
                .verifyComplete();

        assertThat(chain.forwarded).isTrue();
        assertThat(chain.auth.get()).isNull(); // SecurityContext not populated
        // BFF was never contacted — the JWT path handles this request.
        verify(client, never()).get();
    }

    // ── no token at all → pass-through ────────────────────────────────────────

    @Test
    void noToken_passesThrough_unauthenticated() {
        WebClient client = mock(WebClient.class);
        BffSessionAuthFilter f = filter(client);

        MockServerHttpRequest req = MockServerHttpRequest.get("/api/dashboard").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain))
                .verifyComplete();

        assertThat(chain.forwarded).isTrue();
        assertThat(chain.auth.get()).isNull();
        verify(client, never()).get();
    }

    // ── BFF returns 401 → pass-through unauthenticated ───────────────────────

    @Test
    void bff401_passesThrough_unauthenticated() {
        WebClientResponseException ex401 = WebClientResponseException.create(
                401, "Unauthorized", HttpHeaders.EMPTY, new byte[0], null);
        BffSessionAuthFilter f = filter(mockWebClient(Mono.error(ex401)));

        MockServerHttpRequest req = MockServerHttpRequest.get("/api/dashboard")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_expiredtoken")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain))
                .verifyComplete();

        // Downstream is reached (security chain will 401 if path requires auth).
        assertThat(chain.forwarded).isTrue();
        assertThat(chain.auth.get()).isNull(); // no authentication injected
        assertThat(exchange.getResponse().getStatusCode()).isNull(); // not set by this filter
    }

    // ── BFF returns 5xx → fail-closed 503 ────────────────────────────────────

    @Test
    void bff5xx_failsClosed_returns503() {
        WebClientResponseException ex500 = WebClientResponseException.create(
                500, "Internal Server Error", HttpHeaders.EMPTY, new byte[0], null);
        BffSessionAuthFilter f = filter(mockWebClient(Mono.error(ex500)));

        MockServerHttpRequest req = MockServerHttpRequest.get("/api/dashboard")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_sometoken")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        AtomicBoolean downstream = new AtomicBoolean(false);
        WebFilterChain chain = ex -> { downstream.set(true); return Mono.empty(); };

        StepVerifier.create(f.filter(exchange, chain))
                .verifyComplete();

        assertThat(downstream).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }

    // ── BFF unreachable → fail-closed 503 ────────────────────────────────────

    @Test
    void bffUnreachable_failsClosed_returns503() {
        RuntimeException connRefused = new RuntimeException("Connection refused");
        BffSessionAuthFilter f = filter(mockWebClient(Mono.error(connRefused)));

        MockServerHttpRequest req = MockServerHttpRequest.get("/api/dashboard")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_sometoken")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        AtomicBoolean downstream = new AtomicBoolean(false);
        WebFilterChain chain = ex -> { downstream.set(true); return Mono.empty(); };

        StepVerifier.create(f.filter(exchange, chain))
                .verifyComplete();

        assertThat(downstream).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }

    // ── suspended account → 403, even on a 200 BFF response ──────────────────

    @Test
    void suspendedStatus_returns403() {
        MeResponse me = new MeResponse("google:baduser", "google",
                List.of("user"), true, "suspended", false);
        BffSessionAuthFilter f = filter(mockWebClient(Mono.just(me)));

        MockServerHttpRequest req = MockServerHttpRequest.get("/api/dashboard")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_suspendedtoken")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        AtomicBoolean downstream = new AtomicBoolean(false);
        WebFilterChain chain = ex -> { downstream.set(true); return Mono.empty(); };

        StepVerifier.create(f.filter(exchange, chain))
                .verifyComplete();

        assertThat(downstream).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(exchange.getResponse().getHeaders().getFirst("X-BFF-Denied"))
                .isEqualTo("account-suspended");
    }

    // ── banned account → 403 ─────────────────────────────────────────────────

    @Test
    void bannedStatus_returns403() {
        MeResponse me = new MeResponse("google:banneduser", "google",
                List.of("user"), true, "banned", false);
        BffSessionAuthFilter f = filter(mockWebClient(Mono.just(me)));

        MockServerHttpRequest req = MockServerHttpRequest.get("/api/dashboard")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_bannedtoken")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        AtomicBoolean downstream = new AtomicBoolean(false);
        WebFilterChain chain = ex -> { downstream.set(true); return Mono.empty(); };

        StepVerifier.create(f.filter(exchange, chain))
                .verifyComplete();

        assertThat(downstream).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(exchange.getResponse().getHeaders().getFirst("X-BFF-Denied"))
                .isEqualTo("account-banned");
    }

    // ── incomplete registration → restricted authority set ────────────────────

    @Test
    void incompleteRegistration_onlyRoleUser_noAdminAuthority() {
        // registrationComplete=false — the roles list is deliberately non-empty to
        // prove the filter ignores it and grants only the ROLE_USER floor.
        MeResponse me = new MeResponse("google:newuser", "google",
                List.of("user", "admin"), false, "active", false);
        BffSessionAuthFilter f = filter(mockWebClient(Mono.just(me)));

        // Use a non-skipped path — /api/registration/** is in the skip list and
        // would bypass the BFF call entirely, making the auth capture null.
        MockServerHttpRequest req = MockServerHttpRequest.get("/api/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_newusertoken")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain))
                .verifyComplete();

        assertThat(chain.forwarded).isTrue();
        var authorities = chain.auth.get().getAuthorities().stream()
                .map(a -> a.getAuthority()).toList();
        // Only the floor — the roles from the BFF response are not applied when
        // registration is incomplete, so an admin-role cookie can't bypass the gate.
        assertThat(authorities).containsExactly("ROLE_USER");
        assertThat(authorities).doesNotContain("ROLE_ADMIN");
    }

    // ── MFA satisfied → MFA_SATISFIED authority added ─────────────────────────

    @Test
    void mfaSatisfied_addsMfaSatisfiedAuthority() {
        MeResponse me = new MeResponse("google:mfauser", "google",
                List.of("user", "admin"), true, "active", true);
        BffSessionAuthFilter f = filter(mockWebClient(Mono.just(me)));

        MockServerHttpRequest req = MockServerHttpRequest.get("/api/admin/sensitive")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_mfatoken")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain))
                .verifyComplete();

        assertThat(chain.forwarded).isTrue();
        var authorities = chain.auth.get().getAuthorities().stream()
                .map(a -> a.getAuthority()).toList();
        assertThat(authorities).contains("MFA_SATISFIED", "ROLE_USER", "ROLE_ADMIN");
    }

    // ── MFA not satisfied → MFA_SATISFIED absent ──────────────────────────────

    @Test
    void mfaNotSatisfied_mfaSatisfiedAuthorityAbsent() {
        MeResponse me = new MeResponse("google:user", "google",
                List.of("user"), true, "active", false);
        BffSessionAuthFilter f = filter(mockWebClient(Mono.just(me)));

        MockServerHttpRequest req = MockServerHttpRequest.get("/api/dashboard")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_nomfatoken")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain))
                .verifyComplete();

        assertThat(chain.forwarded).isTrue();
        var authorities = chain.auth.get().getAuthorities().stream()
                .map(a -> a.getAuthority()).toList();
        assertThat(authorities).doesNotContain("MFA_SATISFIED");
    }

    // ── skipped paths bypass BFF ───────────────────────────────────────────────

    @Test
    void skippedPaths_noBffCall_forwardImmediately() {
        WebClient client = mock(WebClient.class);
        BffSessionAuthFilter f = filter(client);

        for (String path : new String[]{
                "/api/auth/token",
                "/api/registration/start",
                "/api/login/page",
                "/_matrix/client/v3/sync",
                "/actuator/health",
                "/.well-known/matrix/client",
                "/bff/public/announcements/login"
        }) {
            MockServerHttpRequest req = MockServerHttpRequest.get(path)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer bff_sometoken")
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(req);
            AtomicBoolean downstream = new AtomicBoolean(false);
            WebFilterChain chain = ex -> { downstream.set(true); return Mono.empty(); };

            StepVerifier.create(f.filter(exchange, chain))
                    .verifyComplete();

            assertThat(downstream).as("skipped path %s should forward", path).isTrue();
        }
        // BFF was never contacted on any of the skipped paths.
        verify(client, never()).get();
    }

    // ── authority mapping unit tests ──────────────────────────────────────────

    @Test
    void buildAuthorities_rolesMappedToUppercase_withFloor() {
        MeResponse me = new MeResponse("google:admin", "google",
                List.of("user", "admin", "mod"), true, "active", false);
        var authorities = BffSessionAuthFilter.buildAuthorities(me).stream()
                .map(a -> a.getAuthority()).toList();

        assertThat(authorities).containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN", "ROLE_MOD");
    }

    @Test
    void buildAuthorities_roleUserInBffResponse_notDuplicated() {
        MeResponse me = new MeResponse("google:u", "google",
                List.of("user"), true, "active", false);
        var authorities = BffSessionAuthFilter.buildAuthorities(me).stream()
                .map(a -> a.getAuthority()).toList();

        // ROLE_USER appears exactly once even though it came from both the floor
        // and the "user" role in the BFF response.
        assertThat(authorities).containsExactly("ROLE_USER");
    }

    @Test
    void buildAuthorities_superadmin_isMapped() {
        MeResponse me = new MeResponse("google:sa", "google",
                List.of("superadmin"), true, "active", false);
        var authorities = BffSessionAuthFilter.buildAuthorities(me).stream()
                .map(a -> a.getAuthority()).toList();

        assertThat(authorities).contains("ROLE_SUPERADMIN", "ROLE_USER");
    }

    // ── token extraction unit tests ───────────────────────────────────────────

    @Test
    void extractToken_bearerHeader_returnsBffToken() {
        MockServerHttpRequest req = MockServerHttpRequest.get("/")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_abc")
                .build();
        String token = BffSessionAuthFilter.extractToken(MockServerWebExchange.from(req));
        assertThat(token).isEqualTo("bff_abc");
    }

    @Test
    void extractToken_nonBffBearer_returnsNull() {
        MockServerHttpRequest req = MockServerHttpRequest.get("/")
                .header(HttpHeaders.AUTHORIZATION, "Bearer eyJhbGciOiJSUzI1NiJ9.xyz")
                .build();
        String token = BffSessionAuthFilter.extractToken(MockServerWebExchange.from(req));
        assertThat(token).isNull();
    }

    @Test
    void extractToken_cookie_returnsBffToken() {
        MockServerHttpRequest req = MockServerHttpRequest.get("/")
                .cookie(new HttpCookie(BffSessionAuthFilter.SESSION_COOKIE, "bff_cookieval"))
                .build();
        String token = BffSessionAuthFilter.extractToken(MockServerWebExchange.from(req));
        assertThat(token).isEqualTo("bff_cookieval");
    }

    @Test
    void extractToken_bearerTakesPrecedenceOverCookie() {
        MockServerHttpRequest req = MockServerHttpRequest.get("/")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_fromheader")
                .cookie(new HttpCookie(BffSessionAuthFilter.SESSION_COOKIE, "bff_fromcookie"))
                .build();
        String token = BffSessionAuthFilter.extractToken(MockServerWebExchange.from(req));
        assertThat(token).isEqualTo("bff_fromheader");
    }

    @Test
    void extractToken_noTokenAnywhere_returnsNull() {
        MockServerHttpRequest req = MockServerHttpRequest.get("/").build();
        String token = BffSessionAuthFilter.extractToken(MockServerWebExchange.from(req));
        assertThat(token).isNull();
    }

    // ── internal token header ─────────────────────────────────────────────────

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void internalToken_configured_sentAsHeader() {
        MeResponse me = new MeResponse("google:u@x.com", "google", List.of("user"), true, "active", false);
        Object[] pair = mockWebClientWithHeadersSpec(Mono.just(me));
        WebClient client = (WebClient) pair[0];
        WebClient.RequestHeadersSpec headersSpec = (WebClient.RequestHeadersSpec) pair[1];

        BffSessionAuthFilter f = filterWithInternalToken(client, "super-secret-tok");
        MockServerHttpRequest req = MockServerHttpRequest.get("/api/data")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_tok123")
                .build();

        StepVerifier.create(f.filter(MockServerWebExchange.from(req), new CapturingChain()))
                .verifyComplete();

        verify(headersSpec).header(eq("X-Internal-Token"), eq("super-secret-tok"));
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void internalToken_blank_headerNotSent() {
        MeResponse me = new MeResponse("google:u@x.com", "google", List.of("user"), true, "active", false);
        Object[] pair = mockWebClientWithHeadersSpec(Mono.just(me));
        WebClient client = (WebClient) pair[0];
        WebClient.RequestHeadersSpec headersSpec = (WebClient.RequestHeadersSpec) pair[1];

        BffSessionAuthFilter f = filterWithInternalToken(client, "");
        MockServerHttpRequest req = MockServerHttpRequest.get("/api/data")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_tok456")
                .build();

        StepVerifier.create(f.filter(MockServerWebExchange.from(req), new CapturingChain()))
                .verifyComplete();

        // Blank internal token → only Authorization + X-Forwarded-For headers, never X-Internal-Token.
        verify(headersSpec, never()).header(eq("X-Internal-Token"), anyString());
    }

    // ── filter order ──────────────────────────────────────────────────────────

    @Test
    void order_isHighestPrecedencePlus50() {
        BffSessionAuthFilter f = filter(mock(WebClient.class));
        assertThat(f.getOrder()).isEqualTo(org.springframework.core.Ordered.HIGHEST_PRECEDENCE + 50);
    }
}
