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
 * END-TO-END route-access keystone for the SUPERADMIN PLATFORM CONSOLE at the
 * PUBLIC BROWSER DOOR — the fe half of hugmesh-generator#244, answered ACCEPT
 * (decision 41, 2026-09-17).
 *
 * <p>Drives REAL RSA-signed JWTs through the FULL production stack (OAuth2
 * resource-server authentication, the {@code SecurityWebFilterChain} AND the
 * principal-dependent {@link GatewayRouteAccessFilter}) under the
 * {@code hugmesh-fe-gateway} instance name with NO datastore wired, so the REAL
 * {@code CanonicalSeed.fe()} fallback IS the enforced rule set — exactly what the
 * gateway holds whenever Postgres and the Cassandra read-cache are both
 * unreachable. Same recipe as {@link FeInternalIngestDenyAuthzSpringBootTest} and
 * {@link PkiHeadscaleControlPlaneAuthzSpringBootTest}.
 *
 * <p><b>The gap this closes.</b> The cluster Postgres seed gained
 * {@code ('hugmesh-fe-gateway','/bff/superadmin/**','ROLE_SUPERADMIN',true)} when
 * #244 was answered, and that file names its DUAL-WRITE PARTNER as still missing:
 * {@code CanonicalSeed.fe()} carried NO {@code /bff/superadmin} rule at all. On
 * the datastore-unreachable fallback the superadmin platform console at the public
 * browser door therefore reverted to the pre-#244 posture — the gateway answered
 * {@code NO_RULE}, FORWARDED on the coarse {@code authenticated()} floor, and the
 * refusal happened one layer in (admin-bff's own
 * {@code pathMatchers("/bff/superadmin/**").hasRole("SUPERADMIN")}) with NO
 * {@code X-Route-Denied} header and nothing in the gateway's denial log.
 *
 * <p><b>Fail-first proof.</b> {@link #superadminDoor_roleUser_is403_notForwarded}
 * and the ROLE_MOD case are RED without the seed row: the path matches no fe seed
 * pattern ⇒ NO_RULE ⇒ forwarded ⇒ the probe handler answers 200 with no header.
 * The over-breadth control ({@code /bff/superadmins-club}) and the ROLE_USER
 * {@code /bff/me/**} read are the non-over-broadening counterparts — they must
 * keep their pre-change behaviour, so the row is additive rather than a blanket
 * lockdown of the {@code /bff/} space.
 *
 * <p><b>What this does NOT assert, deliberately.</b> The row does not change what
 * a privileged principal reaches: ROLE_ADMIN and ROLE_SUPERADMIN short-circuit in
 * {@link GatewayRouteAccessFilter} BEFORE {@code decide()} is consulted, so a
 * plain ROLE_ADMIN is still forwarded here and is still refused by admin-bff's own
 * {@code hasRole("SUPERADMIN")} one layer in. That residual is CHARACTERIZED below
 * rather than left to be rediscovered. ACCEPT is defence-in-depth and a clearer
 * failure mode, not the closing of an open door.
 */
@SpringBootTest(properties = {
        // Pin the gateway instance name to the FE tier so route-access seeds
        // CanonicalSeed.fe() and that is the enforced authority (no primed rules,
        // no datastore) — the datastore-unreachable fallback this row hardens.
        "spring.application.name=hugmesh-fe-gateway",
})
@AutoConfigureWebTestClient
class FeSuperadminDoorAuthzSpringBootTest {

    /** Two in-process issuers ⇒ a genuinely multi-issuer registry; brand-X is the
     *  fe gateway's own brand for the same-tenant assertions. */
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
        // Host -> domain map so the request's target domain matches the brand-X
        // token's issuer-derived domain (same-tenant) — otherwise the cross-tenant
        // HARD-DENY would 403 for the WRONG reason and mask the route-access verdict.
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

    /** The shipped admin-ui superadmin pages ride the public fe {@code /bff/**}
     *  catch-all to admin-bff. One representative path per console surface named in
     *  #244: the service store, the workload console and the fleet pages. */
    private static final String SERVICE_STORE = "/bff/superadmin/service-store/catalog";
    private static final String WORKLOADS = "/bff/superadmin/workloads";
    /** The subtree the carrier commit wanted a separate DENY row for. #244's ACCEPT
     *  is stated WITHOUT that refinement, so this path must be governed by the SAME
     *  {@code /bff/superadmin/**} row as its siblings. */
    private static final String GAMES_SERVICES = "/bff/superadmin/games-services/catalog";

    private static String bearer(TestIssuer issuer, String sub, List<String> roles) {
        return "Bearer " + issuer.mint(sub, roles);
    }

    // ── HEADLINE DENY — the door refuses at the gateway, with the header ─────────

    @Test
    void superadminDoor_roleUser_is403_notForwarded() {
        // A genuinely authenticated SAME-TENANT plain ROLE_USER at the superadmin
        // platform console. Not admin, not superadmin, domain matches (no hard-deny)
        // ⇒ the request reaches routeAccess.decide(), where /bff/superadmin/** is the
        // longest (and only) matching pattern and the principal holds no granting row
        // at that length ⇒ governed-but-ungranted ⇒ DENY ⇒ 403 + X-Route-Denied.
        //
        // FAIL-FIRST: without the seed row this path matches nothing in
        // CanonicalSeed.fe(), decide() is NO_RULE, the filter FORWARDS and the probe
        // returns 200 with no header.
        for (String path : List.of(SERVICE_STORE, WORKLOADS, GAMES_SERVICES)) {
            http.get().uri(path)
                    .header(HttpHeaders.HOST, "brandx.example")
                    .header("Authorization", bearer(BRAND_X, "ordinary-user", List.of("user")))
                    .exchange()
                    .expectStatus().isForbidden()
                    .expectHeader().exists("X-Route-Denied");
        }
    }

    @Test
    void superadminDoor_roleMod_is403_elevatedButNonBypassRolesAreDeniedToo() {
        // A privileged-but-non-bypassing role (mod) is ALSO denied: the platform
        // console is an INFRA surface, not a moderation surface. ROLE_MOD does not
        // short-circuit the filter, so this is a real route-access verdict.
        http.get().uri(SERVICE_STORE)
                .header(HttpHeaders.HOST, "brandx.example")
                .header("Authorization", bearer(BRAND_X, "a-mod", List.of("user", "mod")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().exists("X-Route-Denied");
    }

    @Test
    void superadminDoor_crossDomainUser_is403_otherBrandCannotReachThisBrandsConsole() {
        // Defence in depth: a brand-Y token presented to the brand-X fe front door is
        // HARD-DENIED on the domain mismatch BEFORE route-access is consulted.
        http.get().uri(SERVICE_STORE)
                .header(HttpHeaders.HOST, "brandx.example")
                .header("Authorization", bearer(BRAND_Y, "brandy-user", List.of("user")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().exists("X-Route-Denied");
    }

    // ── POSITIVE CONTROLS — the row is additive, not a blanket /bff/ lockdown ────

    @Test
    void superadminHolder_isForwarded_theGrantingRoleStillReachesTheConsole() {
        // ROLE_SUPERADMIN reaches the console. (Two independent reasons agree here:
        // the cross-domain SUPERADMIN bypass short-circuits the filter, AND the seed
        // row grants exactly this role — so the assertion holds whichever fires
        // first, and a regression that denied superadmins would show up as a 403.)
        http.get().uri(SERVICE_STORE)
                .header(HttpHeaders.HOST, "brandx.example")
                .header("Authorization", bearer(BRAND_X, "the-superadmin", List.of("superadmin")))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("X-Route-Denied");
    }

    @Test
    void prefixLookalike_roleUser_stillForwarded_theRowIsNotOverBroad() {
        // Ant `/bff/superadmin/**` matches the prefix itself and its SUBPATHS only.
        // A path that merely shares the leading string must keep its pre-change
        // behaviour (no fe pattern matches ⇒ NO_RULE ⇒ forward). If the row had been
        // written as `/bff/superadmin**` this would start 403ing.
        http.get().uri("/bff/superadmins-club")
                .header(HttpHeaders.HOST, "brandx.example")
                .header("Authorization", bearer(BRAND_X, "ordinary-user", List.of("user")))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("X-Route-Denied");
    }

    @Test
    void neighbouringAllowRows_roleUser_stillForwarded_longestPatternWalkUndisturbed() {
        // The pre-existing ROLE_USER /bff allow rows in CanonicalSeed.fe() are
        // untouched — proving the new row is additive and did not perturb the
        // longest-pattern walk for its neighbours.
        for (String path : List.of("/bff/me/profile", "/bff/character-forge/characters")) {
            http.get().uri(path)
                    .header(HttpHeaders.HOST, "brandx.example")
                    .header("Authorization", bearer(BRAND_X, "ordinary-user", List.of("user")))
                    .exchange()
                    .expectStatus().isOk()
                    .expectHeader().doesNotExist("X-Route-Denied");
        }
    }

    // ── CHARACTERIZATION — the residual this row deliberately does NOT close ─────

    @Test
    void superadminDoor_sameDomainAdmin_isStillForwarded_documentedBypassResidual() {
        // HONEST CHARACTERIZATION, not an endorsement. ROLE_ADMIN short-circuits in
        // GatewayRouteAccessFilter with chain.filter() BEFORE decide() is ever
        // called, so NO route-access row — seed or Postgres — can deny it. A plain
        // per-domain admin therefore still reaches admin-bff and is still refused
        // there by hasRole("SUPERADMIN"), exactly as before this row. The cluster
        // Postgres row behaves identically; this seed copy reaches parity with it,
        // no more and no less.
        //
        // Pinned here so nobody reads #244's ACCEPT as "the door is now shut to
        // admins", and so a future change to the bypass ORDER shows up as a test
        // change rather than a silent posture shift.
        http.get().uri(SERVICE_STORE)
                .header(HttpHeaders.HOST, "brandx.example")
                .header("Authorization", bearer(BRAND_X, "an-admin", List.of("admin")))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("X-Route-Denied");
    }

    /** Local probe controller — when the gateway filter chain FORWARDS a request it
     *  reaches this handler (bodiless 200). A 403 from the route-access filter never
     *  gets here, so a FORWARD on any probe path is an unambiguous 200. A bodiless
     *  ResponseEntity avoids the EncoderHttpMessageWriter Content-Length write on the
     *  read-only gateway response headers (see PrincipalFilterChainOrderingSpringBootTest). */
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
                "/bff/superadmin/service-store/catalog",   // superadmin platform console
                "/bff/superadmin/workloads",               // workload console
                "/bff/superadmin/games-services/catalog",  // no separate DENY refinement
                "/bff/superadmins-club",                   // prefix look-alike (control)
                "/bff/me/profile",                         // fe seed ROLE_USER allow row
                "/bff/character-forge/characters",         // fe seed ROLE_USER allow row
        })
        Mono<ResponseEntity<Void>> probe() {
            return Mono.just(ResponseEntity.ok().build());
        }
    }
}
