package systems.hugmesh.gateway.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import systems.hugmesh.gateway.security.DomainRegistry;
import systems.hugmesh.gateway.testsupport.TestIssuer;

import java.util.List;

/**
 * DEFENSIVE CSRF-DOC GUARD (Tier-1 meta-test) — proves the gateway's production
 * {@link SecurityConfig#filterChain} keeps CSRF protection DISABLED, end-to-end
 * through the real reactive filter chain.
 *
 * <p><b>Why this guard exists.</b> The gateway is a pure Casdoor-JWT BEARER
 * resource server, so {@code csrf.disable()} is CORRECT BY DESIGN — CSRF is a
 * cookie-session concern, defended at the COOKIE-TERMINATING admin-bff (the
 * double-submit cookie + {@code X-CSRF} header on the httpOnly {@code bff_session},
 * enforced where the session cookie is actually minted and read). A bearer token
 * travels in the {@code Authorization} header, which a cross-site form/img/script
 * CANNOT set by construction, so the bearer gateway is immune to CSRF and Spring's
 * reactive {@code CsrfWebFilter} would add ZERO protection while (1) rejecting every
 * bearer POST lacking a token it never issued and (2) breaking the SSE/WebSocket
 * upgrade handshakes (Matrix/Mastodon). This is a KNOWN false-finding from security
 * scanners — do NOT "fix" it by enabling CSRF on the gateway (the rationale lives
 * inline at {@code SecurityConfig.filterChain}'s {@code .csrf(csrf -> csrf.disable())},
 * D6/D8). This meta-test FAILS LOUDLY if a future agent / reviewer / scan-remediation
 * ever re-enables CSRF here, because that would break every state-changing API call
 * through the gateway.
 *
 * <p><b>How it proves it.</b> The reactive {@code CsrfWebFilter} runs BEFORE
 * authorization and returns {@code 403} for any unsafe HTTP method (POST/PUT/DELETE)
 * that arrives WITHOUT a valid CSRF token. So driving token-less POSTs through the
 * REAL chain and asserting they are NEVER 403'd-for-CSRF is a behavioral oracle for
 * "CSRF is off":
 * <ul>
 *   <li><b>PUBLIC POST</b> — a token-less anonymous POST to a {@code permitAll} path
 *       reaches the controller (200). With CSRF on it would be a pre-authz 403;</li>
 *   <li><b>BEARER POST</b> — an AUTHENTICATED bearer POST to a gated path reaches the
 *       controller (200). With CSRF on it would be a 403, breaking every state-changing
 *       bearer call — the load-bearing assertion;</li>
 *   <li><b>ANONYMOUS GATED POST</b> — a token-less anonymous POST to a gated path is
 *       {@code 401} (the auth floor), NOT {@code 403} — proving the rejection is the
 *       authentication floor, not a CSRF rejection.</li>
 * </ul>
 *
 * <p>Deterministic + offline: the chain is built from a fresh {@link ServerHttpSecurity}
 * via {@link SecuritySliceSupport} and tokens come from an in-process
 * {@link TestIssuer} (loopback only, no network). The CSRF behaviour is
 * auth-decoder-agnostic; this slice drives the multi-issuer resolver path (the only
 * no-network decoder seam) — CSRF is identically disabled on the single-issuer path.
 */
class CsrfDocGuardTest extends SecuritySliceSupport {

    private TestIssuer issuer;
    private TestIssuer issuer2;   // a second trusted issuer so isMultiIssuer() holds
    private WebTestClient client;

    @BeforeEach
    void setUp() {
        issuer = new TestIssuer();
        issuer2 = new TestIssuer();
        String issuersCsv = issuer.issuerUri() + "=brandx," + issuer2.issuerUri() + "=brandy";
        DomainRegistry registry = new DomainRegistry(issuer.issuerUri(), issuersCsv, "");
        TenancyResourceServerConfig tenancy = new TenancyResourceServerConfig(registry, "", "");
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                tenancy.tenantAuthManagerResolver();
        client = sliceClient(registry, provider(resolver), new ProbeController());
    }

    @AfterEach
    void tearDown() {
        issuer.close();
        issuer2.close();
    }

    // ── PUBLIC POST — token-less POST is NOT CSRF-403'd ───────────────────────

    @Test
    void csrfDisabled_publicPost_reachesController_notCsrf403() {
        // A token-less anonymous POST to a permitAll path. CSRF protection, if it were
        // enabled, runs BEFORE authorization and would 403 this (no CSRF token). With
        // CSRF disabled by design it sails through to the controller (200). This
        // isolates CSRF from authz: the path is public, so the only thing that could
        // reject it is the CSRF filter.
        client.post().uri("/api/auth/token").exchange()
                .expectStatus().isOk();
    }

    // ── BEARER POST — authenticated state-change is NOT CSRF-403'd ────────────

    @Test
    void csrfDisabled_authenticatedBearerPost_reachesController_notCsrf403() {
        // The LOAD-BEARING assertion: an authenticated bearer POST (the normal
        // state-changing API call through the gateway) reaches the controller (200).
        // If CSRF were re-enabled, the reactive CsrfWebFilter would 403 this bearer
        // POST (it carries no CSRF token the gateway never issues), breaking every
        // state-changing call. A 403 here means CSRF was wrongly re-enabled.
        String token = issuer.mint("p-admin", List.of("admin"));
        client.post().uri("/api/admin/cluster/nodes")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk();
    }

    // ── ANONYMOUS GATED POST — the rejection is the AUTH FLOOR (401), not CSRF (403)

    @Test
    void csrfDisabled_anonymousGatedPost_is401_not403() {
        // A token-less anonymous POST to a gated path. With CSRF disabled the request
        // reaches the authentication floor and is 401 (no credentials). With CSRF
        // ENABLED it would be a pre-authz 403 (CSRF rejection happens before auth).
        // Asserting 401 — and explicitly NOT 403 — proves CSRF is off even on the
        // authenticated floor, not just on permitAll paths.
        client.post().uri("/api/admin/cluster/nodes").exchange()
                .expectStatus().value(status -> {
                    if (status == 403) {
                        throw new AssertionError(
                                "gateway CSRF appears RE-ENABLED: anonymous token-less POST to a "
                                + "gated path was 403 (CSRF rejection) instead of the expected 401 "
                                + "(auth floor). CSRF is DISABLED BY DESIGN on the bearer gateway "
                                + "(defended at the cookie-terminating BFF) — do NOT re-enable it.");
                    }
                    if (status != 401) {
                        throw new AssertionError(
                                "expected 401 (auth floor) on anonymous gated POST but got " + status);
                    }
                });
    }

    /** Maps the two paths this guard exercises (a public path + a gated path) for both
     *  GET and POST so an ALLOWED request resolves to 200 rather than a 404 that could
     *  mask a missing/changed security decision. */
    @RestController
    static class ProbeController {
        @RequestMapping({"/api/auth/token", "/api/admin/cluster/nodes"})
        Mono<String> ok() {
            return Mono.just("ok");
        }
    }
}
