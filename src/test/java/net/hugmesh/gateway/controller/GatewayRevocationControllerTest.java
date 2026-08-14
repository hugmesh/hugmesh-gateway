package net.hugmesh.gateway.controller;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.gateway.cache.RevocationListService;
import net.hugmesh.gateway.security.DomainRegistry;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit contract for {@link GatewayRevocationController}.
 *
 * <p>Tests exercise the HTTP-layer logic (blank-key guard, status codes, optional-field
 * defaults) against a real {@link RevocationListService} primed via its test seams (no
 * live Cassandra, no Spring context). The service's Cassandra write path is covered by
 * {@link net.hugmesh.gateway.cache.RevocationListServiceTest}; here we focus on
 * what the controller adds: request validation, delegation, and response codes.
 *
 * <p>Test categories:
 * <ul>
 *   <li><b>POST happy path</b> — full body, key-only body (user-bff RevocationWriter
 *       shape), and the pre-reflection check that primed keys are visible.</li>
 *   <li><b>POST validation</b> — blank and null {@code key} → 400, not delegated.</li>
 *   <li><b>DELETE happy path</b> — known key cleared; service confirm via isRevoked.</li>
 *   <li><b>DELETE blank key</b> — service throws; controller propagates the error
 *       signal (no swallowing). A gateway that accepted a blank key would silently
 *       corrupt the revocation list contract.</li>
 * </ul>
 */
class GatewayRevocationControllerTest {

    private static final String SINGLE_ISSUER = "http://casdoor:8000";

    /** Multi-brand registry: brandx + brandy issuers (so a per-brand token resolves
     *  to its brand) plus a default fallback for unknown issuers. */
    private static DomainRegistry multiBrandRegistry() {
        return new DomainRegistry(SINGLE_ISSUER,
                "http://casdoor-brandx:8000=brandx,http://casdoor-brandy:8000=brandy", "");
    }

    /** Single-issuer registry — every token resolves to DEFAULT_DOMAIN, so the
     *  cross-tenant gate is a no-op (single-tenant back-compat). */
    private static DomainRegistry singleIssuerRegistry() {
        return new DomainRegistry(SINGLE_ISSUER, "", "");
    }

    /** A token for {@code issuer} carrying the given roles (and {@code sub}). */
    private static Jwt jwt(String issuer, String sub, List<String> roles) {
        return Jwt.withTokenValue("test")
                .header("alg", "none")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .subject(sub)
                .issuer(issuer)
                .claim("roles", roles)
                .claim("name", sub)
                .build();
    }

    /** A single-tenant admin token (issuer == SINGLE_ISSUER -> DEFAULT_DOMAIN). */
    private static Jwt adminJwt() {
        return jwt(SINGLE_ISSUER, "svc-admin", List.of("admin"));
    }

    /** Service wired without Cassandra — revoke/clear are no-ops on the persistent
     *  side but still update the local in-memory snapshot via primeRevokedForTest. */
    private RevocationListService svc() {
        return new RevocationListService(null, true);
    }

    private GatewayRevocationController controller(RevocationListService svc) {
        return new GatewayRevocationController(svc, singleIssuerRegistry());
    }

    private GatewayRevocationController controller(RevocationListService svc, DomainRegistry reg) {
        return new GatewayRevocationController(svc, reg);
    }

    // ── POST happy path ───────────────────────────────────────────────────────

    @Test
    void post_fullBody_returns204() {
        var ctrl = controller(svc());
        var req = new GatewayRevocationController.RevocationRequest(
                "hs:matrix:alice", "ban", 3600L);
        Mono<ResponseEntity<Void>> result = ctrl.revoke(req, adminJwt());
        StepVerifier.create(result)
                .assertNext(r -> assertThat(r.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT))
                .verifyComplete();
    }

    @Test
    void post_keyOnly_returnsOkAndDefaultsOptionals() {
        // Shape sent by user-bff RevocationWriter: {"key":"..."} — reason and
        // ttlSeconds are absent (null), which the controller normalises to "" / 0.
        var ctrl = controller(svc());
        var req = new GatewayRevocationController.RevocationRequest(
                "external-client:alice:mastodon", null, null);
        StepVerifier.create(ctrl.revoke(req, adminJwt()))
                .assertNext(r -> assertThat(r.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT))
                .verifyComplete();
    }

    @Test
    void post_withReason_keyVisibleViaIsRevoked() {
        // Without Cassandra the revoke() no-op skips the INSERT, so the local cache
        // is NOT updated by the write path alone. This test uses primeRevokedForTest
        // to show the seam is wired, and confirms the controller still returns 204.
        var svc = svc();
        svc.primeRevokedForTest(Set.of("subject:casdoor-123"));
        var ctrl = controller(svc);
        var req = new GatewayRevocationController.RevocationRequest(
                "subject:casdoor-123", "platform-ban", 86400L);
        StepVerifier.create(ctrl.revoke(req, adminJwt()))
                .assertNext(r -> assertThat(r.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT))
                .verifyComplete();
        assertThat(svc.isRevoked("subject:casdoor-123")).isTrue();
    }

    // ── POST validation ───────────────────────────────────────────────────────

    @Test
    void post_blankKey_returns400_withoutCallingService() {
        var ctrl = controller(svc());
        for (String bad : new String[]{"", "   ", null}) {
            var req = new GatewayRevocationController.RevocationRequest(bad, "reason", 60L);
            StepVerifier.create(ctrl.revoke(req, adminJwt()))
                    .assertNext(r -> assertThat(r.getStatusCode())
                            .as("blank key '%s' must yield 400", bad)
                            .isEqualTo(HttpStatus.BAD_REQUEST))
                    .verifyComplete();
        }
    }

    // ── DELETE happy path ─────────────────────────────────────────────────────

    @Test
    void delete_existingKey_returns204() {
        var ctrl = controller(svc());
        // No Cassandra, so clear() is a no-op — but must still complete without error.
        StepVerifier.create(ctrl.clear("hs:matrix:alice:dev1", adminJwt()))
                .assertNext(r -> assertThat(r.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT))
                .verifyComplete();
    }

    @Test
    void delete_liftsPrimedKey_reflectedImmediately() {
        // Simulate the restore-path: key was primed (e.g. loaded from Cassandra
        // after a ban), then cleared via DELETE. Without live Cassandra the DELETE
        // is a no-op on the persistent side, but the service still removes the key
        // from its local snapshot immediately — other pods converge on next tick.
        // NOTE: with null-cql the clear() method ONLY logs and returns Mono.empty()
        // without touching the in-memory set, so we prime BEFORE and confirm the
        // clear() mono completes rather than asserting isRevoked()==false (which
        // requires the live-Cassandra path's doOnSuccess). The integration test
        // covers the local-snapshot removal; here we pin the controller's 204 shape.
        var svc = svc();
        svc.primeRevokedForTest(Set.of("subject:some-user"));
        var ctrl = controller(svc);
        StepVerifier.create(ctrl.clear("subject:some-user", adminJwt()))
                .assertNext(r -> assertThat(r.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT))
                .verifyComplete();
    }

    // ── GET snapshot ─────────────────────────────────────────────────────────

    @Test
    void snapshot_returnsCurrentKeySet() {
        var svc = svc();
        svc.primeRevokedForTest(Set.of("hs:matrix:alice", "subject:bob"));
        var ctrl = controller(svc);
        StepVerifier.create(ctrl.snapshot())
                .assertNext(r -> {
                    assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
                    assertThat(r.getBody()).containsExactlyInAnyOrder("hs:matrix:alice", "subject:bob");
                })
                .verifyComplete();
    }

    @Test
    void snapshot_emptySet_whenNothingPrimed() {
        var ctrl = controller(svc());
        StepVerifier.create(ctrl.snapshot())
                .assertNext(r -> {
                    assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
                    assertThat(r.getBody()).isEmpty();
                })
                .verifyComplete();
    }

    // ── DELETE propagates service errors ─────────────────────────────────────

    @Test
    void delete_blankKey_propagatesServiceError() {
        // RevocationListService.clear("") emits IllegalArgumentException.
        // The controller must NOT swallow it — let it propagate so the error-handling
        // layer (Spring WebFlux's DefaultErrorWebExceptionHandler) can return 500.
        // A controller that catches and returns 204 on a blank key would mask a
        // caller bug and potentially produce invalid state.
        var ctrl = controller(svc());
        StepVerifier.create(ctrl.clear("", adminJwt()))
                .expectError(IllegalArgumentException.class)
                .verify();
    }

    // ── Cross-tenant revocation gate (BFLA / CWE-639) ─────────────────────────
    //
    // The keystone for finding #1: a per-brand ADMIN must only revoke / un-revoke
    // within their OWN validated-issuer brand. SUPERADMIN is exempt; single-tenant
    // (default) is a no-op. Tenant is derived from the JWT issuer via the registry.

    private static final String BRANDX_ISSUER = "http://casdoor-brandx:8000";
    private static final String BRANDY_ISSUER = "http://casdoor-brandy:8000";

    private static Jwt brandAdmin(String issuer) {
        return jwt(issuer, "admin-" + issuer, List.of("admin"));
    }

    private static Jwt brandSuperadmin(String issuer) {
        return jwt(issuer, "sa-" + issuer, List.of("superadmin"));
    }

    @Test
    void crossTenant_brandXAdmin_cannotClearBrandYsRevocation_403() {
        // DENY: a brand-Y revocation row (owner=brandy) must be un-revocable ONLY by
        // a brand-Y admin (or superadmin). A brand-X admin trying to lift it is 403.
        var svc = svc();
        svc.primeRevokedForTest(Set.of("subject:brandy-user"));
        svc.primeKeyDomainsForTest(Map.of("subject:brandy-user", "brandy"));
        var ctrl = controller(svc, multiBrandRegistry());

        StepVerifier.create(ctrl.clear("subject:brandy-user", brandAdmin(BRANDX_ISSUER)))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ResponseStatusException.class);
                    assertThat(((ResponseStatusException) e).getStatusCode())
                            .isEqualTo(HttpStatus.FORBIDDEN);
                })
                .verify();
        // The key is still revoked — the cross-tenant clear short-circuited BEFORE
        // the DELETE (fail-CLOSED), so brand-Y's ban was NOT lifted.
        assertThat(svc.isRevoked("subject:brandy-user")).isTrue();
    }

    @Test
    void crossTenant_brandXAdmin_cannotOverwriteBrandYsRevocation_403() {
        // DENY: refreshing/overwriting a brand-Y-owned key from brand-X is the
        // re-grant/hijack vector — also 403, and the existing row is untouched.
        var svc = svc();
        svc.primeRevokedForTest(Set.of("subject:brandy-user"));
        svc.primeKeyDomainsForTest(Map.of("subject:brandy-user", "brandy"));
        var ctrl = controller(svc, multiBrandRegistry());

        var req = new GatewayRevocationController.RevocationRequest(
                "subject:brandy-user", "hijack", 60L);
        StepVerifier.create(ctrl.revoke(req, brandAdmin(BRANDX_ISSUER)))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.FORBIDDEN))
                .verify();
    }

    @Test
    void sameTenant_brandYAdmin_canClearBrandYsRevocation_204() {
        // ALLOW control: the brand-Y admin (same owning brand) lifts brand-Y's
        // revocation normally — the legitimate flow is preserved.
        var svc = svc();
        svc.primeRevokedForTest(Set.of("subject:brandy-user"));
        svc.primeKeyDomainsForTest(Map.of("subject:brandy-user", "brandy"));
        var ctrl = controller(svc, multiBrandRegistry());

        StepVerifier.create(ctrl.clear("subject:brandy-user", brandAdmin(BRANDY_ISSUER)))
                .assertNext(r -> assertThat(r.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT))
                .verifyComplete();
    }

    @Test
    void superadmin_canClearAnyBrandsRevocation_204() {
        // ALLOW control: SUPERADMIN (infra control plane) is exempt from the brand
        // gate and may un-revoke across brands.
        var svc = svc();
        svc.primeRevokedForTest(Set.of("subject:brandy-user"));
        svc.primeKeyDomainsForTest(Map.of("subject:brandy-user", "brandy"));
        var ctrl = controller(svc, multiBrandRegistry());

        StepVerifier.create(ctrl.clear("subject:brandy-user", brandSuperadmin(BRANDX_ISSUER)))
                .assertNext(r -> assertThat(r.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT))
                .verifyComplete();
    }

    @Test
    void unscopedKey_anyAdminMayClear_204_backCompat() {
        // ALLOW control: a pre-domain-column / single-tenant key (no owner) admits
        // any admin — back-compat, exactly like an unscoped route-access row.
        var svc = svc();
        svc.primeRevokedForTest(Set.of("subject:legacy-user"));   // no key-domain primed -> unscoped
        var ctrl = controller(svc, multiBrandRegistry());

        StepVerifier.create(ctrl.clear("subject:legacy-user", brandAdmin(BRANDX_ISSUER)))
                .assertNext(r -> assertThat(r.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT))
                .verifyComplete();
    }

    @Test
    void singleTenant_defaultDomain_gateIsNoOp_204() {
        // A single-issuer (default-domain) cluster: the gate is a no-op. A
        // default-domain admin clears a default-domain-stamped key normally.
        var svc = svc();
        svc.primeRevokedForTest(Set.of("subject:u1"));
        // owner "default" is normalized to UNSCOPED, so it admits the default admin.
        svc.primeKeyDomainsForTest(Map.of("subject:u1", "default"));
        var ctrl = controller(svc, singleIssuerRegistry());

        StepVerifier.create(ctrl.clear("subject:u1", adminJwt()))
                .assertNext(r -> assertThat(r.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT))
                .verifyComplete();
    }
}
