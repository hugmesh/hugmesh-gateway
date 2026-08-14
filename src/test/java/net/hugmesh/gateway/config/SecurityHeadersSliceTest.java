package net.hugmesh.gateway.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import net.hugmesh.gateway.security.DomainRegistry;
import net.hugmesh.gateway.testsupport.TestIssuer;

import java.net.URI;
import java.util.List;

/**
 * HARDENED HTTP SECURITY HEADERS slice (Tier-1) — proves the OWASP/NIST browser
 * policy set the gateway front door adds in {@link SecurityConfig#filterChain}
 * is actually emitted on a real response THROUGH the production filter chain,
 * AND that the additive header block did not weaken the deny-by-default floor.
 *
 * <p>Asserts:
 * <ul>
 *   <li><b>HEADERS PRESENT</b> — on an AUTHENTICATED 200, the 4 genuinely-missing
 *       headers (CSP, HSTS, Referrer-Policy, Permissions-Policy) plus COOP/CORP are
 *       present with the hardened values, and Spring's secure defaults
 *       (X-Frame-Options: DENY, X-Content-Type-Options: nosniff) are STILL present
 *       (not disabled);</li>
 *   <li><b>HEADERS ON 401</b> — the same browser-policy set is emitted even on the
 *       anonymous 401 (headers writers run on the response regardless of authz
 *       outcome), so a redirected/erroring browser is still protected;</li>
 *   <li><b>UNAUTH STILL 401</b> — an arbitrary gated path still 401s anonymously:
 *       the additive header block changed NO authz rule.</li>
 * </ul>
 *
 * <p>The header policy is auth-decoder-agnostic; this slice drives a token through
 * the multi-issuer resolver path (the only no-network decoder seam — backed by an
 * in-process {@link TestIssuer}). The headers under test are identical on the
 * single-issuer path.
 */
class SecurityHeadersSliceTest extends SecuritySliceSupport {

    private TestIssuer issuer;
    private TestIssuer issuer2;   // second trusted issuer so isMultiIssuer() holds
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

    /** The browser-policy headers emitted on EVERY request regardless of scheme.
     *  HSTS is checked separately (it is HTTPS-only by design — see below). */
    private void assertBrowserPolicyHeaders(WebTestClient.ResponseSpec resp) {
        resp.expectHeader().valueEquals("Content-Security-Policy",
                        "default-src 'self'; script-src 'self'; style-src 'self'; "
                        + "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
                        + "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; "
                        + "object-src 'none'; upgrade-insecure-requests")
                .expectHeader().valueEquals("Referrer-Policy", "no-referrer")
                .expectHeader().valueEquals("Permissions-Policy",
                        "geolocation=(), camera=(self), microphone=(self), payment=(), usb=(), "
                        + "accelerometer=(), gyroscope=(), magnetometer=(), autoplay=(self), "
                        + "display-capture=(), fullscreen=(self)")
                .expectHeader().valueEquals("Cross-Origin-Opener-Policy", "same-origin")
                .expectHeader().valueEquals("Cross-Origin-Resource-Policy", "same-origin")
                // Spring secure DEFAULTS must remain (NOT disabled by the additive block).
                .expectHeader().valueEquals("X-Frame-Options", "DENY")
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff");
    }

    // ── HEADERS PRESENT on an authenticated 200 ───────────────────────────────

    @Test
    void hardenedHeaders_presentOn_authenticated200() {
        String token = issuer.mint("p-admin", List.of("admin"));
        WebTestClient.ResponseSpec resp = client.get().uri("/api/reports/q3")
                .header("Authorization", "Bearer " + token)
                .exchange();
        resp.expectStatus().isOk();
        assertBrowserPolicyHeaders(resp);
    }

    // ── HEADERS PRESENT even on the anonymous 401 ─────────────────────────────

    @Test
    void hardenedHeaders_presentOn_anonymous401() {
        WebTestClient.ResponseSpec resp = client.get().uri("/api/reports/q3").exchange();
        resp.expectStatus().isUnauthorized();
        assertBrowserPolicyHeaders(resp);
    }

    // ── HSTS PRESENT over HTTPS (and ABSENT over plaintext — by design) ───────

    @Test
    void hsts_presentOn_httpsRequest() {
        // The reactive HSTS writer emits ONLY on a secure (HTTPS) request — HSTS
        // over plaintext is meaningless and the gateway is the TLS edge. Drive an
        // absolute https:// URI so the exchange is secure.
        String token = issuer.mint("p-admin", List.of("admin"));
        client.get().uri(URI.create("https://gateway.example/api/reports/q3"))
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("Strict-Transport-Security",
                        "max-age=63072000 ; includeSubDomains ; preload");
    }

    @Test
    void hsts_absentOn_plaintextRequest() {
        // Over plaintext HTTP the HSTS header must NOT be emitted (meaningless and
        // misleading) — the other browser-policy headers still are.
        String token = issuer.mint("p-admin", List.of("admin"));
        client.get().uri("/api/reports/q3")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("Strict-Transport-Security");
    }

    // ── UNAUTH STILL 401 — additive header block changed no authz rule ────────

    @Test
    void unauthenticated_arbitraryPath_still401s() {
        client.get().uri("/api/reports/q3").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void unauthenticated_infraPath_still401s() {
        client.get().uri("/actuator/health").exchange().expectStatus().isUnauthorized();
    }

    @RestController
    static class ProbeController {
        @RequestMapping({"/api/reports/q3", "/actuator/health"})
        Mono<String> ok() {
            return Mono.just("ok");
        }
    }
}
