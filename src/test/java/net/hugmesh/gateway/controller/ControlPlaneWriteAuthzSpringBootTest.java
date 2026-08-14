package net.hugmesh.gateway.controller;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import net.hugmesh.gateway.testsupport.TestIssuer;

import java.util.List;

/**
 * WAVE-2 control-plane WRITE authz at the HTTP BOUNDARY — the gateway's own
 * mutation surface {@code /api/gateway/revocations}, driven through the FULL
 * production stack: the OAuth2 resource-server authentication, the
 * {@link net.hugmesh.gateway.config.SecurityConfig#filterChain}
 * {@code authorizeExchange} policy, AND {@code @EnableReactiveMethodSecurity}'s
 * {@code @PreAuthorize} interceptor on {@link GatewayRevocationController}.
 *
 * <p><b>Why a full {@code @SpringBootTest} and not a security-slice.</b> The
 * existing {@link GatewayRevocationControllerTest} invokes controller METHODS
 * directly (proving the cross-tenant gate logic) and the {@code SecuritySliceSupport}
 * {@code bindToController} slice exercises the {@code authorizeExchange} path policy —
 * but NEITHER installs the reactive method-security interceptor, so NEITHER proves the
 * class-level {@code @PreAuthorize("hasRole('ADMIN')")} and the method-level
 * {@code @PreAuthorize("hasRole('SUPERADMIN')")} on {@link GatewayRevocationController#snapshot}
 * are actually ENFORCED on a real request. This test closes that gap: it boots the real
 * context (Cassandra excluded, pollers off — the same recipe as the smoke test) with the
 * resource server pointed at an in-process {@link TestIssuer} (multi-issuer mode), mints
 * real RSA-signed role-bearing tokens, and asserts the HTTP-boundary verdict.
 *
 * <p><b>Assertions (the control-plane WRITE role matrix).</b>
 * <ul>
 *   <li><b>ANONYMOUS → 401</b> on POST / DELETE / GET — the
 *       {@code anyExchange().authenticated()} floor rejects an unauthenticated mutation
 *       BEFORE any handler runs (no control-plane write without a credential);</li>
 *   <li><b>WRONG-ROLE (ROLE_USER, ROLE_MOD) → 403</b> on POST / DELETE — a non-admin
 *       authenticated principal is FORBIDDEN by {@code @PreAuthorize("hasRole('ADMIN')")}
 *       (cross-tier DENY: a mod/user can never write the revocation list);</li>
 *   <li><b>ADMIN → 204</b> on POST / DELETE — the authorized writer succeeds
 *       (no Cassandra wired, so the persist is a no-op, but the verdict is 204);</li>
 *   <li><b>SUPERADMIN-only (no explicit admin) → 204</b> on POST / DELETE — the
 *       documented cascade {@code SUPERADMIN >= ADMIN} satisfies
 *       {@code @PreAuthorize("hasRole('ADMIN')")} through the role hierarchy now WIRED
 *       into reactive method security (the historic FINDING — 403 because the
 *       {@code RoleHierarchy} bean was inert for {@code @PreAuthorize} — is now FIXED
 *       and this assertion is flipped to 204);</li>
 *   <li><b>NO over-broadening</b> — a {@code user}-only token and a {@code mod}-only
 *       token STAY 403 on the write gate (the hierarchy has ONLY superadmin-superset
 *       edges; USER never climbs to ADMIN, and ADMIN/MOD remain siblings);</li>
 *   <li><b>GET snapshot</b> — ADMIN is 403 (the method demands SUPERADMIN, a STRICTER
 *       gate than the class default), SUPERADMIN is 200. The hierarchy does NOT promote
 *       admin UP to superadmin — snapshot leaks user identifiers and is
 *       superadmin-only;</li>
 *   <li><b>domain from the VALIDATED issuer, never the request</b> — a body / query
 *       param claiming another brand does NOT change the verdict; authz is decided on
 *       the token's cryptographic issuer alone.</li>
 * </ul>
 *
 * <p>Categories per the comprehensive test standard: anonymous-401 + wrong-role-403
 * (incl. the user/mod no-over-broadening pair) are CROSS-USER DENY (the privilege
 * boundary); admin-204 + superadmin-only-204 (the hierarchy cascade) + superadmin-200
 * are USER-SITUATIONAL ALLOW; the snapshot admin-403 vs superadmin-200 pair is a
 * CROSS-USER isolation assertion (admin must NOT see another tier's identifier dump,
 * and the hierarchy must not promote it there).
 */
@SpringBootTest
@AutoConfigureWebTestClient
class ControlPlaneWriteAuthzSpringBootTest {

    /** Two in-process issuers so the registry is genuinely multi-issuer (the swap is
     *  taken) and we can prove cross-issuer tokens are scoped to their own brand. */
    private static final TestIssuer BRAND_X = new TestIssuer();
    private static final TestIssuer BRAND_Y = new TestIssuer();

    @AfterAll
    static void stopIssuers() {
        BRAND_X.close();
        BRAND_Y.close();
    }

    @DynamicPropertySource
    static void resourceServerProps(DynamicPropertyRegistry registry) {
        // Multi-issuer mode: brand-X + brand-Y are trusted per-brand Casdoors. The
        // resource server validates real RSA tokens against the in-process JWKS — no
        // network, no live Casdoor.
        registry.add("app.tenancy.issuers",
                () -> BRAND_X.issuerUri() + "=brandx," + BRAND_Y.issuerUri() + "=brandy");
        // Host -> domain map so the (now-active, post-ordering-fix) GatewayRouteAccessFilter
        // resolves a brand Host to the brand whose admin is calling — otherwise an unmapped
        // Host falls back to "default", which never matches a brandx/brandy issuer-domain
        // and the cross-tenant HARD-DENY (correctly) 403s every per-brand admin write. The
        // admin-write tests below send a matching Host so the request is same-tenant; the
        // cross-tenant isolation itself is proven in GatewayRouteAccessFilter's own tests
        // and PrincipalFilterChainOrderingSpringBootTest. (Before the ordering fix this
        // filter was inert — getPrincipal() was empty — so no Host was needed.)
        registry.add("app.tenancy.hosts",
                () -> "brandx.example=brandx,brandy.example=brandy");
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", BRAND_X::issuerUri);
        // A non-empty placeholder jwk-set-uri so the back-compat decoder bean builds
        // without a network call (it is never used — isMultiIssuer() takes the resolver
        // path — but the property must be present-and-valid for the context to wire).
        registry.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri",
                () -> BRAND_X.issuerUri() + "/.well-known/jwks.json");
        // Turn OFF the background pollers + exclude Cassandra so the context boots with
        // NO external services — identical recipe to HugMeshGatewayApplicationTests.
        registry.add("app.revocation.enabled", () -> "false");
        registry.add("app.url-registry.enabled", () -> "false");
        registry.add("app.resource-access.enabled", () -> "false");
        registry.add("app.route-access.enabled", () -> "false");
        registry.add("spring.autoconfigure.exclude", () ->
                "org.springframework.boot.cassandra.autoconfigure.CassandraAutoConfiguration,"
                        + "org.springframework.boot.data.cassandra.autoconfigure.DataCassandraAutoConfiguration,"
                        + "org.springframework.boot.data.cassandra.autoconfigure.DataCassandraReactiveAutoConfiguration");
    }

    @Autowired
    WebTestClient http;

    private static final String REVOCATIONS = "/api/gateway/revocations";

    private static String bearer(TestIssuer issuer, String sub, List<String> roles) {
        return "Bearer " + issuer.mint(sub, roles);
    }

    private static String body(String key) {
        return "{\"key\":\"" + key + "\",\"reason\":\"wave2\",\"ttlSeconds\":3600}";
    }

    // ── ANONYMOUS → 401 (the authenticated() floor, before any handler) ─────────

    @Test
    void anonymous_post_is401() {
        http.post().uri(REVOCATIONS)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body("subject:anon-write"))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void anonymous_delete_is401() {
        http.delete().uri(REVOCATIONS + "/subject:anon-clear")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void anonymous_getSnapshot_is401() {
        http.get().uri(REVOCATIONS)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // ── WRONG-ROLE → 403 (cross-tier DENY via @PreAuthorize hasRole('ADMIN')) ───

    @Test
    void user_post_is403_crossTierDeny() {
        // ROLE_USER authenticates fine but is FORBIDDEN to write the control plane.
        http.post().uri(REVOCATIONS)
                .header("Authorization", bearer(BRAND_X, "plain-user", List.of("user")))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body("subject:user-tried-to-write"))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void mod_post_is403_crossTierDeny() {
        // ROLE_MOD is a privileged USER role but is NOT an admin — the control plane
        // is closed to it (the infra-isolation invariant: mods never mutate the
        // revocation list).
        http.post().uri(REVOCATIONS)
                .header("Authorization", bearer(BRAND_X, "a-mod", List.of("mod")))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body("subject:mod-tried-to-write"))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void user_delete_is403_crossTierDeny() {
        http.delete().uri(REVOCATIONS + "/subject:user-tried-to-clear")
                .header("Authorization", bearer(BRAND_X, "plain-user", List.of("user")))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void mod_delete_is403_crossTierDeny() {
        http.delete().uri(REVOCATIONS + "/subject:mod-tried-to-clear")
                .header("Authorization", bearer(BRAND_X, "a-mod", List.of("mod")))
                .exchange()
                .expectStatus().isForbidden();
    }

    // ── ADMIN → 204 (USER-SITUATIONAL ALLOW; the authorized writer) ─────────────

    @Test
    void admin_post_is204() {
        // The contract verdict for the authorized control-plane writer. No Cassandra
        // wired (pollers off), so revoke() is a persist no-op, but the HTTP verdict is
        // 204 — proving the @PreAuthorize('ADMIN') gate ADMITS admin and the write
        // path runs to completion.
        http.post().uri(REVOCATIONS)
                .header(org.springframework.http.HttpHeaders.HOST, "brandx.example")  // same tenant as the token
                .header("Authorization", bearer(BRAND_X, "svc-admin", List.of("admin")))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body("subject:admin-wrote-this"))
                .exchange()
                .expectStatus().isNoContent();
    }

    @Test
    void admin_delete_is204() {
        http.delete().uri(REVOCATIONS + "/subject:admin-cleared-this")
                .header(org.springframework.http.HttpHeaders.HOST, "brandx.example")  // same tenant as the token
                .header("Authorization", bearer(BRAND_X, "svc-admin", List.of("admin")))
                .exchange()
                .expectStatus().isNoContent();
    }

    @Test
    void superadmin_only_post_is204_viaRoleHierarchy() {
        // FLIPPED PIN (was superadmin_only_post_is403_roleHierarchyNotAppliedToPreAuthorize_FINDING).
        //
        // A token carrying ONLY `superadmin` (no explicit `admin` role) now SATISFIES
        // @PreAuthorize("hasRole('ADMIN')") and writes the control plane (204), because
        // SecurityConfig now contributes a MethodSecurityExpressionHandler with the
        // `ROLE_SUPERADMIN > ROLE_ADMIN` RoleHierarchy SET on it. Before the fix this
        // path was 403 (the historic FINDING): @EnableReactiveMethodSecurity did NOT
        // auto-wire the stray RoleHierarchy bean into the reactive method-security
        // expression handler, so hasRole('ADMIN') was evaluated against the RAW
        // authorities and a hierarchy-only superadmin did not satisfy it. The bean
        // existed and RoleHierarchyTest proved it resolved SUPERADMIN -> ADMIN, but it
        // never reached @PreAuthorize — which made the SecurityConfig javadoc ("smooths
        // @PreAuthorize ergonomics") inaccurate. The fix wires the existing (unchanged)
        // hierarchy into method security; the javadoc was corrected to match.
        //
        // This proves the documented cascade SUPERADMIN >= ADMIN end-to-end through the
        // REAL chain (resource server -> authorizeExchange -> reactive @PreAuthorize),
        // not just at the bean level. NO hierarchy SEMANTICS changed — only the (already
        // declared) edges now take effect.
        http.post().uri(REVOCATIONS)
                .header("Authorization", bearer(BRAND_X, "svc-sa-only", List.of("superadmin")))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body("subject:sa-only-wrote-this"))
                .exchange()
                .expectStatus().isNoContent();
    }

    @Test
    void superadmin_only_delete_is204_viaRoleHierarchy() {
        // The DELETE half of the same class-level hasRole('ADMIN') gate: a
        // superadmin-only token clears a key (the restore path) via the hierarchy edge.
        http.delete().uri(REVOCATIONS + "/subject:sa-only-cleared-this")
                .header("Authorization", bearer(BRAND_X, "svc-sa-only", List.of("superadmin")))
                .exchange()
                .expectStatus().isNoContent();
    }

    // ── NO OVER-BROADENING — the privilege boundary the hierarchy must NOT cross ──

    @Test
    void user_only_post_stays403_noUpwardPromotion() {
        // The headline no-over-broadening guard: wiring SUPERADMIN >= ADMIN must NEVER
        // let a lower role climb. A token carrying ONLY `user` is still FORBIDDEN on
        // @PreAuthorize("hasRole('ADMIN')") — the hierarchy has only superadmin-superset
        // edges, so USER does NOT reach ADMIN. (Was 403 before the fix; MUST remain 403
        // after — this is the assertion that proves the change did not broaden access.)
        http.post().uri(REVOCATIONS)
                .header("Authorization", bearer(BRAND_X, "plain-user-after-fix", List.of("user")))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body("subject:user-still-cannot-write"))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void mod_only_post_stays403_siblingNotPromotedToAdmin() {
        // ROLE_MOD and ROLE_ADMIN are documented SIBLINGS in the hierarchy (NO
        // ADMIN>MOD / MOD>ADMIN edge). A mod-only token stays FORBIDDEN on the
        // hasRole('ADMIN') control-plane write — the hierarchy fix did not collapse the
        // sibling boundary.
        http.post().uri(REVOCATIONS)
                .header("Authorization", bearer(BRAND_X, "a-mod-after-fix", List.of("mod")))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body("subject:mod-still-cannot-write"))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void superadmin_withAdminRole_post_is204() {
        // The PRODUCTION shape: a superadmin principal that ALSO carries the explicit
        // `admin` role (as Casdoor seeds it) satisfies hasRole('ADMIN') DIRECTLY (raw
        // authority) and writes the control plane — so it would succeed even without the
        // hierarchy. Kept as the belt-and-suspenders companion to
        // superadmin_only_post_is204_viaRoleHierarchy (which proves the hierarchy edge
        // ALSO admits a superadmin that lacks the explicit `admin` role).
        http.post().uri(REVOCATIONS)
                .header("Authorization", bearer(BRAND_X, "svc-sa", List.of("superadmin", "admin")))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body("subject:sa-wrote-this"))
                .exchange()
                .expectStatus().isNoContent();
    }

    // ── GET snapshot — SUPERADMIN-only (STRICTER than the class default) ────────

    @Test
    void admin_getSnapshot_is403_notLeakedToAdmin() {
        // The snapshot returns user identifiers and is gated SUPERADMIN-only at the
        // method level. A plain ADMIN — who CAN write — must NOT read it. This pins
        // that the method-level @PreAuthorize('SUPERADMIN') OVERRIDES the class-level
        // hasRole('ADMIN'), and that the role hierarchy does NOT promote admin upward.
        http.get().uri(REVOCATIONS)
                .header("Authorization", bearer(BRAND_X, "svc-admin", List.of("admin")))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void mod_getSnapshot_is403() {
        http.get().uri(REVOCATIONS)
                .header("Authorization", bearer(BRAND_X, "a-mod", List.of("mod")))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void superadmin_getSnapshot_is200() {
        // The authorized reader of the identifier dump.
        http.get().uri(REVOCATIONS)
                .header("Authorization", bearer(BRAND_X, "svc-sa", List.of("superadmin")))
                .exchange()
                .expectStatus().isOk();
    }

    // ── domain comes from the VALIDATED ISSUER, never the request body/param ────

    @Test
    void domainIsFromValidatedIssuer_notRequestBody() {
        // A brand-Y admin's token: the issuer (brand-Y) is the tenant discriminator.
        // The body embeds a key that name-drops "brandx" — a request-controlled string
        // that must NOT influence the verdict. brand-Y admin writing a brand-Y-scoped
        // key (no pre-existing owner -> unscoped) succeeds (204); the authz NEVER reads
        // the body for the tenant. The cross-tenant DENY itself is covered at the
        // method level in GatewayRevocationControllerTest; here we assert the HTTP-layer
        // invariant that the request body is not a tenant input.
        http.post().uri(REVOCATIONS + "?domain=brandx")          // attacker-set query param
                .header(org.springframework.http.HttpHeaders.HOST, "brandy.example")  // real tenant = brand-Y (the token's issuer)
                .header("Authorization", bearer(BRAND_Y, "brandy-admin", List.of("admin")))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"key\":\"subject:claims-to-be-brandx\",\"reason\":\"brandx\"}")
                .exchange()
                // Verdict is decided on the brand-Y issuer (admin in own brand,
                // unscoped key) -> 204. The "brandx" strings in the param/body/reason
                // are inert.
                .expectStatus().isNoContent();
    }

    @Test
    void unknownIssuerToken_is401_evenWithAdminClaim_failClosed() {
        // A well-formed, correctly-signed token from an issuer NOT in
        // app.tenancy.issuers, carrying admin+superadmin, still 401s — the multi-issuer
        // resolver returns no manager for an untrusted iss (fail-closed), so a forged
        // role claim never reaches the control plane.
        try (TestIssuer rogue = new TestIssuer()) {
            http.post().uri(REVOCATIONS)
                    .header("Authorization",
                            "Bearer " + rogue.mint("rogue", List.of("admin", "superadmin")))
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(body("subject:rogue-write"))
                    .exchange()
                    .expectStatus().isUnauthorized();
        }
    }

    @Test
    void garbageBearer_is401() {
        http.post().uri(REVOCATIONS)
                .header("Authorization", "Bearer not-a-jwt")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body("subject:garbage"))
                .exchange()
                .expectStatus().isUnauthorized();
    }
}
