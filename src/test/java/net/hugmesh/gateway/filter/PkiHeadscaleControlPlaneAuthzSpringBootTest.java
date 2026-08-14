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
import net.hugmesh.gateway.testsupport.TestIssuer;

import java.util.List;

/**
 * END-TO-END route-access keystone for the PKI gateway's headscale control plane
 * (bug #15) — drives REAL RSA-signed JWTs through the FULL production stack (the
 * OAuth2 resource-server authentication, the {@code SecurityWebFilterChain}, AND the
 * principal-dependent {@link GatewayRouteAccessFilter}) under the
 * {@code hugmesh-pki-gateway} instance name, so the REAL {@code CanonicalSeed.pki()}
 * fallback is the authority (no datastore wired ⇒ the in-memory canonical seed is the
 * enforced rule set, exactly as it is at runtime for the pki gateway).
 *
 * <p><b>The bug.</b> The pki gateway also fronts the cross-domain headscale control
 * plane on its own Host (pki-gateway {@code application-pki.yml}: the {@code headscale}
 * route is matched by {@code Host=scale.hugmesh.net} with NO Path predicate).
 * Before the fix {@code CanonicalSeed.pki()} seeded ONLY {@code /api/auth/** → ROLE_USER},
 * {@code /login/** → PUBLIC} and {@code /.well-known/** → PUBLIC}, so a headscale
 * control-plane path matched NO rule → {@link net.hugmesh.gateway.cache.GatewayRouteAccessService.Decision#NO_RULE}
 * → the {@link GatewayRouteAccessFilter} FORWARDED, and ANY authenticated same-domain
 * ROLE_USER reached the superadmin-tier headscale control plane. The fix adds a
 * {@code /** → ROLE_SUPERADMIN} catch-all; longest-pattern-match keeps the three rows
 * above intact for their own paths while everything else (headscale) floors to
 * SUPERADMIN.
 *
 * <p><b>Why a full {@code @SpringBootTest} and not an {@code ExchangeWithPrincipal}
 * slice.</b> A hand-decorated exchange ALWAYS exposes the principal, so a slice would
 * PASS vacuously regardless of the rule (and regardless of the filter ordering). Only
 * a real boot exercising the genuine {@code WebHttpHandlerBuilder}-merged filter order
 * — now correct after the merged ordering fix (the gateway WebFilters run AFTER Spring
 * Security at positive orders) — proves the seed row is actually ENFORCED on a real
 * request. Same recipe as {@link PrincipalFilterChainOrderingSpringBootTest} /
 * {@code ControlPlaneWriteAuthzSpringBootTest}.
 *
 * <p><b>Fail-first proof.</b> {@link #headscaleControlPlane_roleUser_is403_superadminGateFires}
 * is the headline DENY: with the {@code /** → ROLE_SUPERADMIN} row REMOVED the headscale
 * path is NO_RULE → forwarded → the probe handler returns 200 and this assertion goes
 * RED; with the row present the same-tenant ROLE_USER is governed-but-ungranted → 403 +
 * {@code X-Route-Denied} → GREEN. The positive controls (SUPERADMIN forwarded;
 * {@code /api/auth/**} still ROLE_USER; {@code /login/**} + {@code /.well-known/**} still
 * PUBLIC) prove the row is NOT a blanket lockdown and the three pre-existing rows are
 * NOT over-broadened.
 *
 * <p>Categories per the comprehensive test standard: the ROLE_USER-on-headscale 403 is
 * CROSS-USER / CROSS-TIER DENY (the infra-control-plane privilege boundary); the
 * SUPERADMIN forward + the {@code /api/auth/**} ROLE_USER forward are USER-SITUATIONAL
 * ALLOW; the anonymous-public forwards are PUBLIC-floor preservation (no over-broadening).
 */
@SpringBootTest(properties = {
        // Pin the gateway instance name to the PKI tier so route-access seeds
        // CanonicalSeed.pki() and that is the enforced authority (no primed rules).
        "spring.application.name=hugmesh-pki-gateway",
})
@AutoConfigureWebTestClient
class PkiHeadscaleControlPlaneAuthzSpringBootTest {

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
        // Multi-issuer mode: brand-X + brand-Y are trusted per-brand Casdoors, each
        // validated against its in-process JWKS (no network, no live Casdoor).
        registry.add("app.tenancy.issuers",
                () -> BRAND_X.issuerUri() + "=brandx," + BRAND_Y.issuerUri() + "=brandy");
        // Host -> domain map so the request's target domain matches the brand-X
        // token's issuer-derived domain (same-tenant) — otherwise the cross-tenant
        // HARD-DENY would 403 for the WRONG reason and mask the route-access verdict.
        registry.add("app.tenancy.hosts",
                () -> "brandx.example=brandx,brandy.example=brandy");
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", BRAND_X::issuerUri);
        registry.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri",
                () -> BRAND_X.issuerUri() + "/.well-known/jwks.json");
        // Route-access ENABLED so GatewayRouteAccessFilter runs its real logic against
        // the canonical pki seed; revocation/url-registry/resource-access off + Cassandra
        // excluded ⇒ no external services (identical recipe to the smoke test).
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

    /** A headscale control-plane path served by the `headscale` route on the pki
     *  gateway's scale.<domain> Host — NO Path predicate, so it is NOT covered by the
     *  three pki rows ({@code /api/auth/**}, {@code /login/**}, {@code /.well-known/**}).
     *  {@code /key} is headscale's noise-key endpoint; the {@code /**} catch-all is the
     *  longest (and only) matching pki rule for it. */
    private static final String HEADSCALE_KEY = "/key";
    /** A second headscale control-plane path (the poll/map stream) — same NO_RULE-before-fix
     *  shape, governed ONLY by the new {@code /**} row. */
    private static final String HEADSCALE_MAP = "/machine/map";

    private static String bearer(TestIssuer issuer, String sub, List<String> roles) {
        return "Bearer " + issuer.mint(sub, roles);
    }

    // ── HEADLINE DENY (bug #15) — a same-tenant ROLE_USER is 403'd on headscale ──

    @Test
    void headscaleControlPlane_roleUser_is403_superadminGateFires() {
        // A genuinely authenticated SAME-TENANT (brand-X token on brand-X Host) plain
        // ROLE_USER hitting a headscale control-plane path. Not superadmin, not admin,
        // domain matches (no hard-deny) — so the request falls through to
        // routeAccess.decide(...). The new /** → ROLE_SUPERADMIN row is the longest
        // (only) match; the user does NOT hold ROLE_SUPERADMIN ⇒ governed-but-ungranted
        // ⇒ DENY ⇒ 403 + X-Route-Denied.
        //
        // FAIL-FIRST: with the /** row REMOVED from CanonicalSeed.pki() this path is
        // NO_RULE ⇒ forwarded ⇒ the probe handler returns 200 and this FAILS.
        http.get().uri(HEADSCALE_KEY)
                .header(HttpHeaders.HOST, "brandx.example")     // same tenant as the token
                .header("Authorization", bearer(BRAND_X, "ordinary-user", List.of("user")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().exists("X-Route-Denied");
    }

    @Test
    void headscaleControlPlane_roleUser_secondPath_is403() {
        // Belt-and-suspenders: a second headscale path (the map/poll stream) is governed
        // by the same /** floor and 403s the same ROLE_USER — proving the catch-all
        // covers the whole headscale surface, not just the one probed endpoint.
        http.get().uri(HEADSCALE_MAP)
                .header(HttpHeaders.HOST, "brandx.example")
                .header("Authorization", bearer(BRAND_X, "ordinary-user", List.of("user")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().exists("X-Route-Denied");
    }

    @Test
    void headscaleControlPlane_roleMod_is403_modIsNotSuperadmin() {
        // A privileged-but-not-superadmin role (mod) is ALSO denied — the catch-all is
        // SUPERADMIN, not ROLE_ADMIN/ROLE_MOD, so no per-domain elevated role reaches the
        // cross-domain infra control plane.
        http.get().uri(HEADSCALE_KEY)
                .header(HttpHeaders.HOST, "brandx.example")
                .header("Authorization", bearer(BRAND_X, "a-mod", List.of("mod")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().exists("X-Route-Denied");
    }

    @Test
    void headscaleControlPlane_crossDomainAdmin_is403_otherBrandAdminCannotReachInfra() {
        // THE ROLE_ADMIN-vs-ROLE_SUPERADMIN distinction (the explicit non-negotiable):
        // an admin of ANOTHER brand must NEVER reach this brand's headscale cross-domain
        // infra control plane. A brand-Y admin token presented to the brand-X headscale
        // Host: the token's issuer-derived domain (brandy) does NOT match the Host-derived
        // target (brandx), so GatewayRouteAccessFilter HARD-DENIES with 403 +
        // X-Route-Denied BEFORE route-access — admin role does NOT save it, only
        // SUPERADMIN crosses domains. This is the layer that keeps the cross-domain infra
        // plane closed to per-domain admins.
        //
        // (A SAME-domain admin on its OWN brand's pki gateway is forwarded by the filter's
        // in-domain admin bypass — that is by design and unchanged by this fix; the seed's
        // /** → ROLE_SUPERADMIN row deliberately carries NO ROLE_ADMIN allow row, and the
        // cross-DOMAIN reach an admin could abuse is what this assertion pins shut.)
        http.get().uri(HEADSCALE_KEY)
                .header(HttpHeaders.HOST, "brandx.example")               // brand-X headscale surface
                .header("Authorization", bearer(BRAND_Y, "brandy-admin", List.of("admin")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().exists("X-Route-Denied");
    }

    // ── POSITIVE CONTROL — SUPERADMIN reaches the headscale control plane ────────

    @Test
    void headscaleControlPlane_superadmin_isForwardedToHandler_notRouteDenied() {
        // The authorized operator of the cross-domain infra control plane. SUPERADMIN
        // short-circuits the GatewayRouteAccessFilter's cross-domain bypass BEFORE
        // route evaluation, so it is forwarded to the local probe handler (200) and is
        // NOT route-access-denied. Proves the /** floor is a SUPERADMIN GATE, not a
        // blanket lockdown of every headscale path.
        http.get().uri(HEADSCALE_KEY)
                .header(HttpHeaders.HOST, "brandx.example")
                .header("Authorization", bearer(BRAND_X, "an-operator", List.of("superadmin")))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("X-Route-Denied");
    }

    // ── POSITIVE CONTROLS — the three pre-existing pki rows are NOT over-broadened ──

    @Test
    void apiAuth_roleUser_stillForwarded_notBroadenedToSuperadmin() {
        // /api/auth/** keeps its own ROLE_USER row (a LONGER, more-specific pattern than
        // /**), so an ordinary same-tenant ROLE_USER still reaches it (200). Proves the
        // /** catch-all did NOT swallow the auth surface up to SUPERADMIN — login/token
        // exchange still works for ordinary users.
        http.get().uri("/api/auth/whoami")
                .header(HttpHeaders.HOST, "brandx.example")
                .header("Authorization", bearer(BRAND_X, "ordinary-user", List.of("user")))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("X-Route-Denied");
    }

    @Test
    void login_roleUser_staysPublic_notBroadenedToSuperadmin() {
        // /login/** keeps its own PUBLIC row (a LONGER, more-specific pattern than /**),
        // so it is NOT swallowed by the SUPERADMIN catch-all: an ordinary same-tenant
        // ROLE_USER reaches it (200, not route-denied) because route-access treats the
        // longest-match PUBLIC row as ALLOW for any principal. If /** had over-broadened
        // /login/** to SUPERADMIN this ROLE_USER would be 403'd. (Anonymous reachability
        // of /login is governed by the coarse SecurityConfig gate, a separate layer; this
        // assertion isolates the route-access row's non-over-broadening.)
        http.get().uri("/login/index")
                .header(HttpHeaders.HOST, "brandx.example")
                .header("Authorization", bearer(BRAND_X, "ordinary-user", List.of("user")))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("X-Route-Denied");
    }

    @Test
    void wellKnown_roleUser_staysPublic_notBroadenedToSuperadmin() {
        // /.well-known/** keeps its own PUBLIC row (OIDC discovery / jwks), LONGER than
        // /**, so it wins longest-pattern-match and an ordinary ROLE_USER reaches it
        // (200, not route-denied). Proves the catch-all did NOT lock OIDC discovery
        // behind SUPERADMIN.
        http.get().uri("/.well-known/probe-openid")
                .header(HttpHeaders.HOST, "brandx.example")
                .header("Authorization", bearer(BRAND_X, "ordinary-user", List.of("user")))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("X-Route-Denied");
    }

    /** Local probe controller — when the gateway filter chain FORWARDS a request it
     *  reaches this handler (bodiless 200). A 403 from the route-access filter never
     *  gets here. Serves the headscale probe paths AND the three pki rule paths so a
     *  FORWARD on any of them is an unambiguous 200. A bodiless ResponseEntity avoids
     *  the EncoderHttpMessageWriter Content-Length write on the read-only gateway
     *  response headers (see PrincipalFilterChainOrderingSpringBootTest.ProbeController). */
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
                "/api/auth/whoami",           // pki ROLE_USER surface
                "/login/index",               // pki PUBLIC surface
                "/.well-known/probe-openid",  // pki PUBLIC surface
        })
        Mono<ResponseEntity<Void>> probe() {
            return Mono.just(ResponseEntity.ok().build());
        }
    }
}
