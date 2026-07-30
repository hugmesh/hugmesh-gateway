package systems.hugmesh.gateway.filter;

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
import systems.hugmesh.gateway.testsupport.TestIssuer;

import java.util.List;

/**
 * END-TO-END route-access keystone for the fe gateway's SERVICE-ONLY
 * {@code /…/internal/**} ingest surfaces — drives REAL RSA-signed JWTs through the
 * FULL production stack (the OAuth2 resource-server authentication, the
 * {@code SecurityWebFilterChain}, AND the principal-dependent
 * {@link GatewayRouteAccessFilter}) under the {@code hugmesh-fe-gateway} instance
 * name, so the REAL {@code CanonicalSeed.fe()} fallback is the enforced authority
 * (no datastore wired ⇒ the in-memory canonical seed IS the rule set, exactly as it
 * is at runtime whenever Postgres AND the Cassandra read-cache are both unreachable).
 *
 * <p><b>The bug.</b> The cluster Postgres seed
 * ({@code generator specs/cluster/manifests/route-access/initdb/20-schema.sql})
 * gained three explicit DENY rows — {@code /bff/user/internal/**},
 * {@code /bff/mesh/internal/**}, {@code /bff/internal/**} — because the fe route
 * table Ant-matches those service-to-service receivers under its {@code /bff/user/**},
 * {@code /bff/mesh/**} and {@code /bff/**} predicates. Those rows were seeded into
 * POSTGRES ONLY. {@code CanonicalSeed} is the in-image fail-CLOSED fallback the
 * gateway enforces when neither datastore answers, and it carried NO pattern
 * matching any of the three — so on that path
 * {@link systems.hugmesh.gateway.cache.GatewayRouteAccessService#decide} returned
 * {@link systems.hugmesh.gateway.cache.GatewayRouteAccessService.Decision#NO_RULE}
 * and {@link GatewayRouteAccessFilter} FORWARDED on the coarse
 * {@code authenticated()} floor. A datastore outage therefore made the gateway
 * WEAKER than its steady state and re-opened the very hole the Postgres rows close:
 * any logged-in user reaching user-bff's meshdevice registry + the PENDING→ACTIVE
 * character-moderation flip, mesh-bff's bridge-sync ingest, and admin-bff's internal
 * API (which permitAll()s that prefix app-side, leaving an unset
 * {@code app.internal.token} as the only wall).
 *
 * <p><b>Why a full {@code @SpringBootTest} and not an {@code ExchangeWithPrincipal}
 * slice.</b> A hand-decorated exchange ALWAYS exposes the principal, so a slice would
 * PASS vacuously regardless of the filter ordering. Only a real boot exercising the
 * genuine {@code WebHttpHandlerBuilder}-merged filter order proves the seed row is
 * actually ENFORCED on a real request. Same recipe as
 * {@link PkiHeadscaleControlPlaneAuthzSpringBootTest} /
 * {@link PrincipalFilterChainOrderingSpringBootTest}.
 *
 * <p><b>Fail-first proof.</b> Every {@code *_is403} case below is RED without the
 * seed rows: the path matches no fe seed pattern ⇒ NO_RULE ⇒ forwarded ⇒ the probe
 * handler answers 200. With the rows present the deciding (longest, and only)
 * matching rule is an {@code allow=false} row ⇒ DENY ⇒ 403 + {@code X-Route-Denied}.
 * The positive controls prove the rows are NOT a blanket lockdown of the tiers they
 * sit under: {@code /bff/user/profile} and {@code /bff/mesh/rooms} are still
 * forwarded (they are governed by the Postgres tier floors, not by this baked seed),
 * and {@code /bff/me/**} + {@code /bff/character-forge/**} keep their own ROLE_USER
 * ALLOW rows.
 *
 * <p>Categories per the comprehensive test standard: the ROLE_USER / ROLE_MESH /
 * ROLE_MOD 403s on the internal receivers are CROSS-TIER DENY (the
 * external-vs-service privilege boundary); the forwarded sibling paths and the
 * {@code /bff/me/**} + character-forge reads are USER-SITUATIONAL ALLOW
 * (non-over-broadening controls).
 */
@SpringBootTest(properties = {
        // Pin the gateway instance name to the FE tier so route-access seeds
        // CanonicalSeed.fe() and that is the enforced authority (no primed rules,
        // no datastore) — the datastore-unreachable fallback this fix hardens.
        "spring.application.name=hugmesh-fe-gateway",
})
@AutoConfigureWebTestClient
class FeInternalIngestDenyAuthzSpringBootTest {

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
        // the canonical fe seed; revocation/url-registry/resource-access off + Cassandra
        // excluded ⇒ no external services (identical recipe to the pki keystone).
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

    /** user-bff's SERVICE-only ingest: the meshdevice registry + the
     *  InternalCharacterModerationController PENDING→ACTIVE part/sticker flip. Routed
     *  by the fe `/bff/user/**` predicate. */
    private static final String USER_INTERNAL = "/bff/user/internal/mesh-devices";
    /** mesh-bff's SERVICE-only bridge-sync ingest (meshbridge node directory /
     *  mesh-room). Routed by the fe `/bff/mesh/**` predicate. */
    private static final String MESH_INTERNAL = "/bff/mesh/internal/bridge-sync";
    /** admin-bff's internal API — reached through the fe `/bff/**` admin-bff
     *  catch-all and permitAll()'d app-side by admin-bff's SecurityConfig. */
    private static final String ADMIN_INTERNAL = "/bff/internal/session/introspect";

    private static String bearer(TestIssuer issuer, String sub, List<String> roles) {
        return "Bearer " + issuer.mint(sub, roles);
    }

    // ── HEADLINE DENY — a same-tenant ROLE_USER is 403'd on every internal ingest ──

    @Test
    void userInternalIngest_roleUser_is403_notForwardedOnTheAuthenticatedFloor() {
        // A genuinely authenticated SAME-TENANT plain ROLE_USER hitting user-bff's
        // SERVICE-only ingest. Not superadmin, not admin, domain matches (no
        // hard-deny) — so the request falls through to routeAccess.decide(...), where
        // the new allow=false row is the longest (and only) match and the principal
        // HOLDS its ROLE_USER role ⇒ explicit deny wins ⇒ 403 + X-Route-Denied.
        //
        // FAIL-FIRST: without the row this path matches nothing in CanonicalSeed.fe(),
        // so decide() is NO_RULE, the filter FORWARDS and the probe returns 200.
        http.get().uri(USER_INTERNAL)
                .header(HttpHeaders.HOST, "brandx.example")
                .header("Authorization", bearer(BRAND_X, "ordinary-user", List.of("user")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().exists("X-Route-Denied");
    }

    @Test
    void meshInternalIngest_roleMesh_is403_meshAccessIsNotBridgeIdentity() {
        // The mesh bridge-sync ingest is for the meshbridge DAEMON (ROLE_SERVICE +
        // mTLS in-cluster), NOT for a human ROLE_MESH holder. Holding the mesh-access
        // capability must NOT open the node-directory / mesh-room ingest from outside.
        http.get().uri(MESH_INTERNAL)
                .header(HttpHeaders.HOST, "brandx.example")
                .header("Authorization", bearer(BRAND_X, "mesh-holder", List.of("user", "mesh")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().exists("X-Route-Denied");
    }

    @Test
    void adminBffInternalApi_roleUser_is403_theUngovernedPrefixIsNowGoverned() {
        // The worst of the three before the fix: /bff/internal/** had NO row on EITHER
        // side, so decide() returned NO_RULE and the gateway forwarded into a prefix
        // admin-bff permitAll()s app-side (accounts/ensure, session/introspect,
        // device-enrollment, phone ingest, go-live, image-build ingest) — its
        // InternalTokenWebFilter being the only wall, and inert when
        // app.internal.token is unset.
        http.get().uri(ADMIN_INTERNAL)
                .header(HttpHeaders.HOST, "brandx.example")
                .header("Authorization", bearer(BRAND_X, "ordinary-user", List.of("user")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().exists("X-Route-Denied");
    }

    @Test
    void userInternalIngest_roleMod_is403_elevatedButNonBypassRolesAreDeniedToo() {
        // A privileged-but-non-bypassing role (mod) is ALSO denied — the internal
        // ingest is a SERVICE surface, not a moderation surface, and the
        // PENDING→ACTIVE character flip behind it is exactly what a mod must reach
        // through the MODERATION BFF (/bff/mod/**), never through user-bff's
        // service-to-service door.
        http.get().uri(USER_INTERNAL)
                .header(HttpHeaders.HOST, "brandx.example")
                .header("Authorization", bearer(BRAND_X, "a-mod", List.of("user", "mod")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().exists("X-Route-Denied");
    }

    @Test
    void internalIngest_crossDomainUser_is403_otherBrandCannotReachThisBrandsIngest() {
        // Defense in depth: a brand-Y token presented to the brand-X fe front door is
        // HARD-DENIED on the domain mismatch BEFORE route-access is consulted, so the
        // internal surfaces stay shut on the cross-tenant leg as well.
        http.get().uri(USER_INTERNAL)
                .header(HttpHeaders.HOST, "brandx.example")
                .header("Authorization", bearer(BRAND_Y, "brandy-user", List.of("user")))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().exists("X-Route-Denied");
    }

    // ── POSITIVE CONTROLS — the deny rows did NOT swallow their tiers ────────────

    @Test
    void userTierSibling_roleUser_stillForwarded_denyRowIsScopedToTheInternalSegment() {
        // /bff/user/profile is the ORDINARY user-BFF surface sitting under the same
        // /bff/user/** route predicate. It must stay reachable: the deny row is
        // /bff/user/INTERNAL/**, which does not match it, and CanonicalSeed.fe()
        // deliberately carries no /bff/user/** tier floor (that floor lives in the
        // admin-managed Postgres rows). So the layer reports NO_RULE and forwards.
        // If the deny had been written as a bare /bff/user/** row this would 403.
        http.get().uri("/bff/user/profile")
                .header(HttpHeaders.HOST, "brandx.example")
                .header("Authorization", bearer(BRAND_X, "ordinary-user", List.of("user")))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("X-Route-Denied");
    }

    @Test
    void meshTierSibling_roleMesh_stillForwarded_denyRowIsScopedToTheInternalSegment() {
        // Same non-over-broadening control on the mesh tier: an ordinary mesh-room
        // read is NOT the bridge-sync ingest and must keep working.
        http.get().uri("/bff/mesh/rooms")
                .header(HttpHeaders.HOST, "brandx.example")
                .header("Authorization", bearer(BRAND_X, "mesh-holder", List.of("user", "mesh")))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("X-Route-Denied");
    }

    @Test
    void bffMeAndCharacterForge_roleUser_stillForwarded_existingAllowRowsIntact() {
        // The two pre-existing ROLE_USER /bff allow rows in CanonicalSeed.fe() are
        // untouched — proving the three new rows are additive and did not perturb the
        // longest-pattern walk for their neighbours.
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
    void internalIngest_sameDomainAdmin_isStillForwarded_documentedBypassResidual() {
        // HONEST CHARACTERIZATION, not an endorsement. ROLE_ADMIN (and SUPERADMIN /
        // GAME-MASTER) short-circuit in GatewayRouteAccessFilter with chain.filter()
        // BEFORE decide() is ever called, so NO route-access row — seed or Postgres —
        // can deny them. The generator's Postgres rows behave identically; this seed
        // copy reaches exact parity with them, no more and no less. The
        // every-logged-in-user hole is what the rows close; an admin reaching an
        // internal receiver is gated only by that receiver's OWN app-side
        // @PreAuthorize("hasRole('SERVICE')") / InternalTokenWebFilter.
        //
        // Pinned here so nobody "fixes" the seed believing a deny row stops admins,
        // and so a future change to the bypass order shows up as a test change.
        http.get().uri(USER_INTERNAL)
                .header(HttpHeaders.HOST, "brandx.example")
                .header("Authorization", bearer(BRAND_X, "an-admin", List.of("admin")))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("X-Route-Denied");
    }

    /** Local probe controller — when the gateway filter chain FORWARDS a request it
     *  reaches this handler (bodiless 200). A 403 from the route-access filter never
     *  gets here. Serves the three internal probe paths AND the sibling/control paths
     *  so a FORWARD on any of them is an unambiguous 200. A bodiless ResponseEntity
     *  avoids the EncoderHttpMessageWriter Content-Length write on the read-only
     *  gateway response headers (see PrincipalFilterChainOrderingSpringBootTest). */
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
                "/bff/user/internal/mesh-devices",   // user-bff SERVICE-only ingest
                "/bff/mesh/internal/bridge-sync",    // mesh-bff SERVICE-only ingest
                "/bff/internal/session/introspect",  // admin-bff internal API
                "/bff/user/profile",                 // ordinary user-tier sibling
                "/bff/mesh/rooms",                   // ordinary mesh-tier sibling
                "/bff/me/profile",                   // fe seed ROLE_USER allow row
                "/bff/character-forge/characters",   // fe seed ROLE_USER allow row
        })
        Mono<ResponseEntity<Void>> probe() {
            return Mono.just(ResponseEntity.ok().build());
        }
    }
}
