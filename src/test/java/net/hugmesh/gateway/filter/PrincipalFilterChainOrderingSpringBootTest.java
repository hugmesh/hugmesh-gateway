package net.hugmesh.gateway.filter;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.gateway.cache.GatewayRouteAccessService;
import net.hugmesh.gateway.cache.GatewayRouteAccessService.Rule;
import net.hugmesh.gateway.cache.RevocationListService;
import net.hugmesh.gateway.testsupport.TestIssuer;

import java.util.List;
import java.util.Set;

/**
 * END-TO-END filter-ordering keystone — drives a REAL RSA-signed JWT through the
 * FULL production filter chain (the OAuth2 resource-server authentication, the
 * {@code SecurityWebFilterChain}, AND the principal-dependent gateway WebFilters)
 * and proves the security filters actually FIRE on an authenticated principal.
 *
 * <p><b>Why this exists (the bug it pins).</b> {@link RevocationGatewayFilter},
 * {@link ExternalAuthHeaderFilter}, {@link GatewayRouteAccessFilter} and
 * {@link ResourceAccessFilter} read {@code exchange.getPrincipal()}. They are plain
 * {@code @Component WebFilter} beans, so {@code WebHttpHandlerBuilder} merges them
 * into the SAME ascending {@code @Order} namespace as Spring Security's
 * {@code WebFilterChainProxy} (order {@code -100}). When they were ordered at
 * {@code Ordered.HIGHEST_PRECEDENCE + N} (= {@code Integer.MIN_VALUE + N}, far below
 * {@code -100}) they ran BEFORE Spring Security populated the {@code SecurityContext}
 * — so {@code getPrincipal()} was {@code Mono.empty()} in every one and they ALL
 * fell through their {@code switchIfEmpty}/{@code defaultIfEmpty(empty)} anonymous
 * branch and FORWARDED. The revocation check, the cross-tenant domain HARD-DENY and
 * the route-access DENY all silently failed OPEN.
 *
 * <p><b>Fail-first.</b> Every assertion here expects a {@code 403}. Against the
 * pre-fix ordering the principal is invisible to the filters, so each case FORWARDS
 * to the local probe handler and returns {@code 200} — these tests FAIL. After the
 * filters are moved to run AFTER Spring Security (so the {@code SecurityContext}-
 * wrapped exchange carries the authenticated principal) they fire and return
 * {@code 403} — these tests PASS. The {@link #positiveControl_cleanSameTenantToken_isForwardedToHandler}
 * case proves the chain is an ordered ALLOW (a clean token still reaches the
 * handler), so the 403 assertions are not vacuous.
 *
 * <p>This is deliberately NOT the {@code ExchangeWithPrincipal}-decorator unit style
 * (those keep their own coverage in {@link RevocationGatewayFilterTest} /
 * {@link GatewayRouteAccessFilterTest}): a hand-decorated exchange ALWAYS exposes the
 * principal, so it can never catch an ordering bug where the real chain never wraps
 * the exchange with a {@code SecurityContext} before these filters run. Only a full
 * {@code @SpringBootTest} that boots the genuine {@code WebHttpHandlerBuilder}-merged
 * filter order exercises that.
 *
 * <p>Categories per the comprehensive test standard: the revoked-subject 403, the
 * cross-tenant 403 and the route-DENY 403 are CROSS-USER DENY (the privilege /
 * tenant boundary); the clean-token forward is USER-SITUATIONAL ALLOW (the positive
 * control).
 */
@SpringBootTest(properties = {
        // Pin the gateway instance name so route-access seeds a known tier and our
        // primed rules are the authority. (application.yml's own default is
        // hugmesh-be-gateway; pinned explicitly here so the test doesn't depend
        // on that default staying unchanged.)
        "spring.application.name=hugmesh-be-gateway",
})
@AutoConfigureWebTestClient
class PrincipalFilterChainOrderingSpringBootTest {

    /** Two in-process issuers => the registry is genuinely multi-issuer (the swap is
     *  taken) so brand-X and brand-Y tokens are cryptographically distinct and the
     *  cross-tenant hard-deny has a real other-brand token to deny. */
    private static final TestIssuer BRAND_X = new TestIssuer();
    private static final TestIssuer BRAND_Y = new TestIssuer();

    @AfterAll
    static void stopIssuers() {
        BRAND_X.close();
        BRAND_Y.close();
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        // Multi-issuer mode: brand-X + brand-Y are trusted per-brand Casdoors, each
        // validated against its in-process JWKS (no network, no live Casdoor).
        registry.add("app.tenancy.issuers",
                () -> BRAND_X.issuerUri() + "=brandx," + BRAND_Y.issuerUri() + "=brandy");
        // Host -> domain map so GatewayRouteAccessFilter's Host-derived targetDomain
        // can disagree with the token's issuer-derived principalDomain (the
        // cross-tenant hard-deny). brandx.example -> brandx, brandy.example -> brandy.
        registry.add("app.tenancy.hosts",
                () -> "brandx.example=brandx,brandy.example=brandy");
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", BRAND_X::issuerUri);
        registry.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri",
                () -> BRAND_X.issuerUri() + "/.well-known/jwks.json");
        // Revocation + route-access ENABLED so the principal-dependent filters run
        // their real logic; their datastores are absent (cql/postgres null) so the
        // snapshots are primed by the test seams below. url-registry + resource-access
        // off (no per-resource paths exercised here). Cassandra excluded -> no
        // CqlSession; identical no-external-services recipe as the smoke test.
        registry.add("app.revocation.enabled", () -> "true");
        registry.add("app.route-access.enabled", () -> "true");
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
    RevocationListService revocations;
    @Autowired
    GatewayRouteAccessService routeAccess;

    /** The probe path: ungoverned by any route-access rule (so revocation and the
     *  cross-tenant gate are the only things that can deny it) and served by the
     *  local {@link ProbeController} (200) when forwarded. */
    private static final String PROBE = "/probe/ping";
    /** A path with an explicit route-access DENY rule (primed below). */
    private static final String LOCKED = "/probe/locked/thing";

    @BeforeEach
    void primeSnapshots() {
        // Revocation list: one revoked internal subject.
        revocations.primeRevokedForTest(Set.of("subject:revoked-sub"));
        // Route-access: an explicit DENY of the locked path for ROLE_USER on THIS
        // gateway. The probe path is intentionally left UNGOVERNED (NO_RULE) so it is
        // forwarded by the route-access layer — isolating the revocation / cross-tenant
        // assertions from the route-access one.
        routeAccess.primeForTest(List.of(
                new Rule("deny-locked", "hugmesh-be-gateway", "/probe/locked/**",
                        GatewayRouteAccessService.ROLE_USER, null, false, null, false)));
    }

    private static String bearer(TestIssuer issuer, String sub, List<String> roles) {
        return "Bearer " + issuer.mint(sub, roles);
    }

    // ── (a) REVOCATION FIRES — a revoked JWT subject is 403'd at the gateway ─────

    @Test
    void revokedSubjectJwt_is403_revocationFilterFires() {
        // A genuinely authenticated brand-X user whose subject is on the revocation
        // list. The RevocationGatewayFilter must short-circuit with 403 + X-Revoked.
        // PRE-FIX: the filter ran before Spring Security, saw no principal, forwarded
        // -> the probe handler returns 200 and this assertion FAILS.
        http.get().uri(PROBE)
                .header(HttpHeaders.HOST, "brandx.example")     // same tenant as the token
                .header("Authorization", bearer(BRAND_X, "revoked-sub", List.of("user")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().exists("X-Revoked");
    }

    // ── (b) CROSS-TENANT HARD-DENY — a brand-X token on brand-Y's Host is denied ──

    @Test
    void crossTenantAuthenticatedJwt_isHardDenied_domainMismatchFires() {
        // A brand-X admin (NOT superadmin) addressed to brand-Y's Host: the token's
        // issuer-derived domain (brandx) does NOT match the Host-derived targetDomain
        // (brandy), so GatewayRouteAccessFilter HARD-DENIES with 403 + X-Route-Denied
        // BEFORE the route-access grant layer. Admin role does NOT save it — the
        // mismatch is rejected outright (only SUPERADMIN crosses domains).
        // PRE-FIX: no principal visible -> the filter forwards as anonymous -> 200,
        // so this FAILS.
        http.get().uri(PROBE)
                .header(HttpHeaders.HOST, "brandy.example")     // brand-Y surface
                .header("Authorization", bearer(BRAND_X, "brandx-admin", List.of("admin")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().exists("X-Route-Denied");
    }

    @Test
    void sameTenantAdmin_isNotHardDenied_forwardsToHandler() {
        // Belt-and-suspenders companion proving the hard-deny is a TENANT check, not a
        // blanket admin deny: the SAME admin token addressed to its OWN brand-X Host
        // matches (brandx == brandx) and is forwarded to the handler (200). Makes the
        // cross-tenant 403 above a genuine isolation assertion, not a vacuous one.
        http.get().uri(PROBE)
                .header(HttpHeaders.HOST, "brandx.example")
                .header("Authorization", bearer(BRAND_X, "brandx-admin", List.of("admin")))
                .exchange()
                .expectStatus().isOk();
    }

    // ── (c) ROUTE-ACCESS DENY ROW IS ENFORCED ────────────────────────────────────

    @Test
    void routeAccessDenyRow_is403_routeAccessFilterFires() {
        // A brand-X user on brand-X's Host hitting a path carrying an explicit
        // allow=false rule for ROLE_USER. Same tenant (no hard-deny), not admin (no
        // bypass), so the request falls through to routeAccess.decide(...) -> DENY ->
        // 403 + X-Route-Denied. PRE-FIX: no principal -> the filter takes its anonymous
        // branch (chain.filter) and forwards -> 200, so this FAILS.
        http.get().uri(LOCKED)
                .header(HttpHeaders.HOST, "brandx.example")
                .header("Authorization", bearer(BRAND_X, "brandx-user", List.of("user")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().exists("X-Route-Denied");
    }

    // ── POSITIVE CONTROL — a clean same-tenant token reaches the handler ─────────

    @Test
    void positiveControl_cleanSameTenantToken_isForwardedToHandler() {
        // A non-revoked brand-X user on brand-X's Host hitting the ungoverned probe
        // path: nothing denies it, so it is forwarded to the local handler and returns
        // 200. This proves the filter chain is an ordered ALLOW (the 403 cases above
        // are real denies, not the chain rejecting everything) AND that the ordering
        // fix did not break the forward path.
        http.get().uri(PROBE)
                .header(HttpHeaders.HOST, "brandx.example")
                .header("Authorization", bearer(BRAND_X, "clean-user", List.of("user")))
                .exchange()
                .expectStatus().isOk();
    }

    /** Local probe controller — when the gateway filter chain FORWARDS a request, it
     *  reaches this handler (200/"pong"). A 403 from a filter never gets here. The
     *  RequestMappingHandlerMapping out-precedes the gateway's RoutePredicateHandler
     *  so this is served locally, exactly as the gateway's own controllers are. */
    @TestConfiguration
    static class ProbeConfig {
        @Bean
        ProbeController probeController() {
            return new ProbeController();
        }
    }

    @RestController
    static class ProbeController {
        // Returns a BODILESS 200 — a body would be written by EncoderHttpMessageWriter,
        // which sets Content-Length on the (by-then read-only) gateway response headers
        // and surfaces a benign post-completion error in WebTestClient. A bodiless
        // ResponseEntity gives a clean, unambiguous "the filter chain FORWARDED here"
        // signal (200) with no encoder write.
        @GetMapping({"/probe/ping", "/probe/locked/thing"})
        Mono<ResponseEntity<Void>> ping() {
            return Mono.just(ResponseEntity.ok().build());
        }
    }
}
