package net.hugmesh.gateway.filter;

import org.junit.jupiter.api.AfterAll;
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
import net.hugmesh.gateway.config.SecurityConfig;
import net.hugmesh.gateway.testsupport.TestIssuer;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * END-TO-END authorization keystone for the PKI gateway's headscale control plane
 * (bug #15, then decision 79 = B on hugmesh-admin-bff-api#57, 2026-09-23) — drives
 * REAL RSA-signed JWTs through the FULL production stack (the OAuth2 resource-server
 * authentication, the {@code SecurityWebFilterChain}, AND the principal-dependent
 * {@link GatewayRouteAccessFilter}) under the {@code hugmesh-pki-gateway} instance
 * name, with a {@code headscale} route declared exactly the way
 * hugmesh-pki-gateway's {@code application-pki.yml} declares it: a {@code Host}
 * predicate and NO {@code Path} predicate.
 *
 * <p><b>What decision 79 = B changed.</b> headscale used to be floored by a bare
 * {@code /** -> ROLE_SUPERADMIN} row in {@code CanonicalSeed.pki()}. That row stopped
 * ordinary users, moderators and other-brand admins, but NOT a same-brand
 * {@code ROLE_ADMIN} / {@code ROLE_GAME-MASTER}: {@link GatewayRouteAccessFilter}
 * forwards those two in their own domain BEFORE any rule is read. The row is gone;
 * {@code SecurityConfig} now requires {@code ROLE_SUPERADMIN} for EVERY request whose
 * {@code Host} matches the headscale route's own Host predicate, as the FIRST
 * {@code authorizeExchange} rule — ahead of {@code PUBLIC_PATHS}, so no path on that
 * Host is public. Anonymous gets 401, every other authenticated principal 403.
 *
 * <p><b>Which layer answered.</b> A deny from the SecurityConfig host gate carries NO
 * {@code X-Route-Denied} header (that header is only ever written by
 * {@link GatewayRouteAccessFilter}), so {@code doesNotExist("X-Route-Denied")} on a 403
 * is the proof the host gate fired rather than the route-access layer.
 *
 * <p><b>RED on origin/main 22663fe</b> (before the host gate): the same-brand
 * {@code ROLE_ADMIN} and {@code ROLE_GAME-MASTER} cases were FORWARDED (200) by the
 * filter's own-domain bypass, and the anonymous {@code /api/auth/**} request on the
 * headscale Host was FORWARDED (200) by the {@code PUBLIC_PATHS} permitAll.
 *
 * <p>Why a full {@code @SpringBootTest}: a hand-decorated exchange always exposes the
 * principal, so a slice would pass vacuously; only a real boot exercises the genuine
 * merged filter order AND the real {@code GatewayProperties} binding the host is
 * derived from. Same recipe as {@link PrincipalFilterChainOrderingSpringBootTest}.
 */
@SpringBootTest(properties = {
        // Pin the gateway instance name to the PKI tier so route-access seeds
        // CanonicalSeed.pki() and that is the enforced authority (no primed rules).
        "spring.application.name=hugmesh-pki-gateway",
        // The headscale route, shaped like hugmesh-pki-gateway application-pki.yml:40-43
        // (Host predicate, no Path). Index 0 on purpose: a higher-precedence source
        // REPLACES the whole list, and an index gap would not bind. The base
        // application.yml's api-default route is dropped in this context, which is
        // harmless: the ProbeController (handler-mapping order 0) serves every probe
        // path ahead of Spring Cloud Gateway's route mapping (order 1).
        "spring.cloud.gateway.server.webflux.routes[0].id=headscale",
        "spring.cloud.gateway.server.webflux.routes[0].uri=http://127.0.0.1:9",
        "spring.cloud.gateway.server.webflux.routes[0].predicates[0]=Host=" + PkiHeadscaleControlPlaneAuthzSpringBootTest.HEADSCALE_HOST,
})
@AutoConfigureWebTestClient
class PkiHeadscaleControlPlaneAuthzSpringBootTest {

    /** The headscale Host for brand-X. Suffix-matches the {@code brandx.example} entry
     *  in {@code app.tenancy.hosts}, so it resolves to brand-X — a brand-X admin on this
     *  Host is SAME-tenant and reaches the filter's own-domain bypass (the case the old
     *  row could not stop). */
    static final String HEADSCALE_HOST = "scale.brandx.example";
    /** brand-X's ordinary (non-headscale) Host on the same pki gateway. */
    static final String ID_HOST = "brandx.example";

    /** Two in-process issuers ⇒ a genuinely multi-issuer registry; brand-X is the
     *  pki gateway's own brand for the same-tenant assertions. */
    private static final TestIssuer BRAND_X = new TestIssuer();
    private static final TestIssuer BRAND_Y = new TestIssuer();

    @AfterAll
    static void stopIssuers() {
        BRAND_X.close();
        BRAND_Y.close();
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("app.tenancy.issuers",
                () -> BRAND_X.issuerUri() + "=brandx," + BRAND_Y.issuerUri() + "=brandy");
        // Host -> domain map (suffix match) so both brand-X hosts resolve to brandx and
        // a brand-X token on either is same-tenant — otherwise the cross-tenant
        // HARD-DENY would 403 for the WRONG reason and mask the verdict under test.
        registry.add("app.tenancy.hosts",
                () -> "brandx.example=brandx,brandy.example=brandy");
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", BRAND_X::issuerUri);
        registry.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri",
                () -> BRAND_X.issuerUri() + "/.well-known/jwks.json");
        registry.add("app.route-access.enabled", () -> "true");
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
    SecurityConfig securityConfig;

    /** headscale's noise-key endpoint. */
    private static final String HEADSCALE_KEY = "/key";
    /** headscale's poll/map stream. */
    private static final String HEADSCALE_MAP = "/machine/map";

    private static String bearer(TestIssuer issuer, String sub, List<String> roles) {
        return "Bearer " + issuer.mint(sub, roles);
    }

    private WebTestClient.ResponseSpec get(String host, String path, String authorization) {
        var req = http.get().uri(path).header(HttpHeaders.HOST, host);
        if (authorization != null) req = req.header("Authorization", authorization);
        return req.exchange();
    }

    // ── WIRING SANITY — the host really was derived from the route definition ──

    @Test
    void headscaleHost_isDerivedFromTheHeadscaleRoutesHostPredicate() {
        // If GatewayProperties failed to bind the route (or the derivation read the
        // wrong field), every headscale-Host assertion below would be testing the
        // route-access layer instead — this pins that the gate is armed with exactly
        // the route's Host pattern and nothing else.
        assertThat(securityConfig.headscaleHostPatterns())
            .containsExactly(HEADSCALE_HOST);
    }

    // ── HEADSCALE HOST — every non-superadmin is refused by the host gate ───────

    @Test
    void headscaleHost_roleUser_is403_byTheHostGate() {
        for (String path : List.of(HEADSCALE_KEY, HEADSCALE_MAP)) {
            get(HEADSCALE_HOST, path, bearer(BRAND_X, "ordinary-user", List.of("user")))
                .expectStatus().isForbidden()
                .expectHeader().doesNotExist("X-Route-Denied");
        }
    }

    @Test
    void headscaleHost_roleMod_is403_byTheHostGate() {
        get(HEADSCALE_HOST, HEADSCALE_KEY, bearer(BRAND_X, "a-mod", List.of("mod")))
            .expectStatus().isForbidden()
            .expectHeader().doesNotExist("X-Route-Denied");
    }

    @Test
    void headscaleHost_otherBrandAdmin_is403_byTheHostGate() {
        // A brand-Y admin on brand-X's headscale Host. Before decision 79 the filter's
        // cross-domain HARD-DENY answered (403 + X-Route-Denied); the host gate now
        // refuses it one layer earlier, so the header is absent.
        get(HEADSCALE_HOST, HEADSCALE_KEY, bearer(BRAND_Y, "brandy-admin", List.of("admin")))
            .expectStatus().isForbidden()
            .expectHeader().doesNotExist("X-Route-Denied");
    }

    @Test
    void headscaleHost_sameBrandAdmin_is403_theBypassNoLongerReachesHeadscale() {
        // THE decision-79 case. A brand-X ROLE_ADMIN on brand-X's headscale Host is
        // same-tenant, so GatewayRouteAccessFilter's own-domain admin bypass would
        // forward it before any rule is read. RED on origin/main 22663fe: 200.
        for (String path : List.of(HEADSCALE_KEY, HEADSCALE_MAP)) {
            get(HEADSCALE_HOST, path, bearer(BRAND_X, "brandx-admin", List.of("admin")))
                .expectStatus().isForbidden()
                .expectHeader().doesNotExist("X-Route-Denied");
        }
    }

    @Test
    void headscaleHost_sameBrandGameMaster_is403_theBypassNoLongerReachesHeadscale() {
        // Same bypass, the other role it covers. RED on origin/main 22663fe: 200.
        get(HEADSCALE_HOST, HEADSCALE_KEY, bearer(BRAND_X, "brandx-gm", List.of("game-master")))
            .expectStatus().isForbidden()
            .expectHeader().doesNotExist("X-Route-Denied");
    }

    @Test
    void headscaleHost_anonymous_is401() {
        get(HEADSCALE_HOST, HEADSCALE_KEY, null)
            .expectStatus().isUnauthorized();
    }

    @Test
    void headscaleHost_anonymous_onAPublicPath_is401_theHostGateRunsBeforePublicPaths() {
        // ORDERING DISCRIMINATOR. /api/auth/** is in SecurityConfig.PUBLIC_PATHS. On the
        // headscale Host the host gate must win (first-match-wins in authorizeExchange),
        // so no path on that Host is public. RED on origin/main 22663fe: 200. The id-Host
        // twin below proves the same path IS still public off the headscale Host.
        get(HEADSCALE_HOST, "/api/auth/whoami", null)
            .expectStatus().isUnauthorized();
    }

    @Test
    void headscaleHost_withPortAndMixedCase_isStillGated() {
        // The route predicate matches the raw Host header; the gate also matches the
        // port-stripped, lower-cased form, so it is a SUPERSET of what reaches headscale.
        get("SCALE.BrandX.example:8443", HEADSCALE_KEY,
                bearer(BRAND_X, "brandx-admin", List.of("admin")))
            .expectStatus().isForbidden()
            .expectHeader().doesNotExist("X-Route-Denied");
    }

    // ── POSITIVE CONTROL — SUPERADMIN reaches the headscale control plane ────────

    @Test
    void headscaleHost_superadmin_isForwarded() {
        for (String path : List.of(HEADSCALE_KEY, HEADSCALE_MAP)) {
            get(HEADSCALE_HOST, path, bearer(BRAND_X, "an-operator", List.of("superadmin")))
                .expectStatus().isOk()
                .expectHeader().doesNotExist("X-Route-Denied");
        }
    }

    // ── NON-HEADSCALE HOST on the pki tier — still governed by its own rows ─────

    @Test
    void idHost_anonymous_publicPath_stillForwarded() {
        // Twin of the ordering discriminator: off the headscale Host, /api/auth/** is
        // still anonymous-reachable (PUBLIC_PATHS) — the gate is Host-scoped, not a
        // tier-wide lockdown.
        get(ID_HOST, "/api/auth/whoami", null)
            .expectStatus().isOk()
            .expectHeader().doesNotExist("X-Route-Denied");
    }

    @Test
    void idHost_apiAuth_roleUser_forwardedByItsRow() {
        get(ID_HOST, "/api/auth/whoami", bearer(BRAND_X, "ordinary-user", List.of("user")))
            .expectStatus().isOk()
            .expectHeader().doesNotExist("X-Route-Denied");
    }

    @Test
    void idHost_login_andWellKnown_roleUser_forwardedByTheirPublicRows() {
        for (String path : List.of("/login/index", "/.well-known/probe-openid")) {
            get(ID_HOST, path, bearer(BRAND_X, "ordinary-user", List.of("user")))
                .expectStatus().isOk()
                .expectHeader().doesNotExist("X-Route-Denied");
        }
    }

    @Test
    void idHost_otherBrandUser_isStillHardDeniedByTheRouteAccessFilter() {
        // The route-access layer is still in charge off the headscale Host: a brand-Y
        // principal on brand-X's id Host is refused by the filter's cross-domain
        // HARD-DENY, which is the layer that writes X-Route-Denied.
        get(ID_HOST, "/api/auth/whoami", bearer(BRAND_Y, "brandy-user", List.of("user")))
            .expectStatus().isForbidden()
            .expectHeader().exists("X-Route-Denied");
    }

    @Test
    void idHost_sameBrandAdmin_onAHeadscalePath_isNotHostGated() {
        // The gate keys on Host, never on path: /key on the id Host is not headscale
        // (no route sends it there), so a same-brand admin is forwarded by the filter's
        // own-domain bypass exactly as before.
        get(ID_HOST, HEADSCALE_KEY, bearer(BRAND_X, "brandx-admin", List.of("admin")))
            .expectStatus().isOk()
            .expectHeader().doesNotExist("X-Route-Denied");
    }

    @Test
    void idHost_roleUser_onPathsNoPkiRowGoverns_isForwarded_theDroppedFloorIsNoRule() {
        // PINS THE WIDENING decision 79 = B chose. Dropping the bare pki '/**'
        // ROLE_SUPERADMIN row means a path no pki row matches is NO_RULE again on every
        // NON-headscale Host, so the authenticated() floor is the only gate and ANY
        // signed-in principal is forwarded (as before bug #15). That reaches every such
        // path the pki gateway serves, url_registry routes included, not only these two.
        // RED on origin/main 7aabd34 by construction: the '/**' row answered DENY, so
        // both requests were 403 + X-Route-Denied.
        for (String path : List.of("/api/signup", HEADSCALE_KEY)) {
            get(ID_HOST, path, bearer(BRAND_X, "ordinary-user", List.of("user")))
                .expectStatus().isOk()
                .expectHeader().doesNotExist("X-Route-Denied");
        }
    }

    @Test
    void idHost_anonymous_onANoRulePath_isStill401_theAuthenticatedFloorHolds() {
        // The widening above is to AUTHENTICATED principals only: off PUBLIC_PATHS the
        // SecurityConfig authenticated() floor still refuses anonymous traffic.
        get(ID_HOST, "/api/signup", null)
            .expectStatus().isUnauthorized();
    }

    @Test
    void headscaleUriHost_withARewrittenHostHeader_isStillGated() {
        // The URI-host branch of the matcher. With a forwarded-headers strategy the
        // server derives the request URI host from X-Forwarded-Host, so a relayed
        // request can carry Host = some internal name while its URI host is the
        // headscale Host. Here the Host header is brand-X's id Host (same tenant, so the
        // filter's own-domain admin bypass would forward it) and the URI host is the
        // headscale Host: only the URI-host check can refuse it. Without that branch:
        // 200 via the bypass.
        http.get().uri("http://" + HEADSCALE_HOST + HEADSCALE_KEY)
            .header(HttpHeaders.HOST, ID_HOST)
            .header("Authorization", bearer(BRAND_X, "brandx-admin", List.of("admin")))
            .exchange()
            .expectStatus().isForbidden()
            .expectHeader().doesNotExist("X-Route-Denied");
    }

    /** Local probe controller — a FORWARDED request reaches this handler (bodiless 200).
     *  A bodiless ResponseEntity avoids the EncoderHttpMessageWriter Content-Length write
     *  on the read-only gateway response headers (see
     *  PrincipalFilterChainOrderingSpringBootTest.ProbeController). */
    @TestConfiguration
    static class ProbeConfig {
        @Bean
        ProbeController probeController() {
            return new ProbeController();
        }
    }

    @RestController
    static class ProbeController {
        @GetMapping({
                "/key",                       // headscale noise key (control plane)
                "/machine/map",               // headscale poll/map stream (control plane)
                "/api/auth/whoami",           // pki ROLE_USER surface (and PUBLIC_PATHS)
                "/api/signup",                // no pki row governs it: NO_RULE since decision 79
                "/login/index",               // pki PUBLIC surface
                "/.well-known/probe-openid",  // pki PUBLIC surface
        })
        Mono<ResponseEntity<Void>> probe() {
            return Mono.just(ResponseEntity.ok().build());
        }
    }
}
