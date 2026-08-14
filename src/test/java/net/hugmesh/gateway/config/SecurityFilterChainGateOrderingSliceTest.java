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

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * WAVE-2 GATE-ORDERING slice — proves the {@link SecurityConfig#filterChain} runs the
 * right filters in the right order: an unauthenticated (or badly-authenticated) request
 * to a PROTECTED route is rejected (401) by the resource-server / authorization layer
 * BEFORE the downstream handler ever runs.
 *
 * <p>The PR-#34 {@link SecurityConfigPathGateSliceTest} asserts the {@code authorizeExchange}
 * VERDICTS (which role gets which status on which path). This slice adds the ORDERING
 * invariant that the verdicts alone don't prove: that the gate SHORT-CIRCUITS — the
 * protected handler is NEVER INVOKED on a rejected request (a 401 returned AFTER the
 * handler ran would be a serious leak / side-effect bug). It does so with a probe
 * controller that increments a counter on every hit; the counter MUST stay 0 for every
 * rejected request.
 *
 * <p>Assertions:
 * <ul>
 *   <li><b>ANONYMOUS DENY before handler</b> — an anonymous request to a gated path 401s
 *       AND the handler counter is still 0 (the authenticated() floor fired first);</li>
 *   <li><b>BAD-TOKEN DENY before handler</b> — a malformed bearer and a tampered-signature
 *       token both 401 before the handler (the resource-server decoder rejected them);</li>
 *   <li><b>UNKNOWN-ISSUER DENY before handler</b> — a well-formed token from an untrusted
 *       issuer 401s before the handler (multi-issuer fail-closed);</li>
 *   <li><b>AUTHORIZED reaches handler</b> — a valid trusted-issuer token DOES reach the
 *       handler (counter increments), proving the gate is an ordered allow, not a blanket
 *       deny — the positive control that makes the negatives meaningful.</li>
 * </ul>
 *
 * <p>Per the comprehensive test standard: the DENY-before-handler cases are CROSS-USER
 * DENY (no unauthenticated/forged caller may reach a protected handler); the
 * authorized-reaches-handler case is USER-SITUATIONAL ALLOW.
 */
class SecurityFilterChainGateOrderingSliceTest extends SecuritySliceSupport {

    private TestIssuer trusted;
    private TestIssuer trusted2;   // a second trusted issuer so isMultiIssuer() holds
    private TestIssuer rogue;      // NOT in app.tenancy.issuers
    private ProbeController probe;
    private WebTestClient client;

    @BeforeEach
    void setUp() {
        trusted = new TestIssuer();
        trusted2 = new TestIssuer();
        rogue = new TestIssuer();
        String issuersCsv = trusted.issuerUri() + "=brandx," + trusted2.issuerUri() + "=brandy";
        DomainRegistry registry = new DomainRegistry(trusted.issuerUri(), issuersCsv, "");
        TenancyResourceServerConfig tenancy = new TenancyResourceServerConfig(registry, "", "");
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                tenancy.tenantAuthManagerResolver();
        probe = new ProbeController();
        client = sliceClient(registry, provider(resolver), probe);
    }

    @AfterEach
    void tearDown() {
        trusted.close();
        trusted2.close();
        rogue.close();
    }

    /** A protected (non-public) path the anyExchange().authenticated() floor governs. */
    private static final String PROTECTED = "/api/reports/q3";

    // ── ANONYMOUS DENY — 401 AND the handler is never reached ──────────────────

    @Test
    void anonymous_protectedRoute_is401_beforeHandler() {
        client.get().uri(PROTECTED).exchange().expectStatus().isUnauthorized();
        assertThat(probe.hits())
                .as("the authenticated() gate must reject anonymous BEFORE the handler runs")
                .isZero();
    }

    @Test
    void anonymous_postMutation_is401_beforeHandler() {
        // A write to a gated path must also be stopped at the floor — never reaching a
        // handler that could mutate state.
        client.post().uri("/api/reports/ingest").exchange().expectStatus().isUnauthorized();
        assertThat(probe.hits()).isZero();
    }

    // ── BAD-TOKEN DENY — 401 before handler (resource-server decode failure) ───

    @Test
    void garbageBearer_protectedRoute_is401_beforeHandler() {
        client.get().uri(PROTECTED)
                .header("Authorization", "Bearer not-a-jwt")
                .exchange()
                .expectStatus().isUnauthorized();
        assertThat(probe.hits())
                .as("a malformed bearer is rejected by the decoder, before the handler")
                .isZero();
    }

    @Test
    void tamperedSignature_protectedRoute_is401_beforeHandler() {
        String token = trusted.mint("user-x", List.of("admin"));
        String tampered = token.substring(0, token.length() - 4) + "AAAA";
        client.get().uri(PROTECTED)
                .header("Authorization", "Bearer " + tampered)
                .exchange()
                .expectStatus().isUnauthorized();
        assertThat(probe.hits())
                .as("a signature-tampered token fails validation before the handler")
                .isZero();
    }

    // ── UNKNOWN-ISSUER DENY — 401 before handler (multi-issuer fail-closed) ────

    @Test
    void unknownIssuer_protectedRoute_is401_beforeHandler() {
        // A perfectly-signed token from an issuer NOT in app.tenancy.issuers: the
        // resolver yields no manager (fail-closed), so it 401s and never reaches the
        // handler — even though it carries admin+superadmin claims.
        String token = rogue.mint("attacker", List.of("admin", "superadmin"));
        client.get().uri(PROTECTED)
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();
        assertThat(probe.hits())
                .as("an untrusted issuer is rejected before the handler — forged roles never matter")
                .isZero();
    }

    // ── AUTHORIZED ALLOW — the valid token DOES reach the handler (positive control)

    @Test
    void trustedToken_protectedRoute_reachesHandler_200() {
        String token = trusted.mint("user-x", List.of("user"));
        client.get().uri(PROTECTED)
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk();
        assertThat(probe.hits())
                .as("a valid trusted-issuer token must reach the handler — proving the gate is "
                        + "an ordered ALLOW, not a blanket deny that makes the negatives vacuous")
                .isEqualTo(1);
    }

    /** Probe controller that COUNTS handler invocations, so a rejected request can be
     *  proven to have short-circuited BEFORE the handler (the ordering invariant). */
    @RestController
    static class ProbeController {
        private final AtomicInteger hits = new AtomicInteger();

        int hits() {
            return hits.get();
        }

        @RequestMapping({"/api/reports/q3", "/api/reports/ingest"})
        Mono<String> handle() {
            hits.incrementAndGet();
            return Mono.just("ok");
        }
    }
}
