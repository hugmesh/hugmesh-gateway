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
 * KEYSTONE coarse PATH-GATE slice (Tier-1) — the {@link SecurityConfig}
 * {@code authorizeExchange} policy, end-to-end through the real filter chain.
 * Today only the {@code roleHierarchy()} bean is unit-tested in isolation
 * ({@code RoleHierarchyTest}); this proves the actual request-path gating.
 *
 * <p>Asserts:
 * <ul>
 *   <li><b>USER-SITUATIONAL DENY</b> — {@code ROLE_USER} and {@code ROLE_MOD} get
 *       403 on the INFRA paths ({@code /actuator/**}, {@code /api/admin/**}) — the
 *       infra-isolation invariant (mods/users never reach infra);</li>
 *   <li><b>USER-SITUATIONAL ALLOW</b> — {@code ROLE_ADMIN} reaches the infra paths;</li>
 *   <li><b>ANONYMOUS ALLOW</b> — public + homeserver-passthrough paths are reachable
 *       unauthenticated (login / registration / matrix discovery);</li>
 *   <li><b>ANONYMOUS DENY</b> — any other path 401s anonymous (the
 *       {@code anyExchange().authenticated()} floor).</li>
 * </ul>
 *
 * <p>The path policy is auth-decoder-agnostic, so this slice drives tokens through
 * the multi-issuer resolver path (the only no-network decoder seam — backed by an
 * in-process {@link TestIssuer}); the {@code authorizeExchange} rules under test are
 * identical on the single-issuer path.
 */
class SecurityConfigPathGateSliceTest extends SecuritySliceSupport {

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

    private WebTestClient.RequestHeadersSpec<?> as(List<String> roles, String path) {
        String token = issuer.mint("p-" + String.join("-", roles), roles);
        return client.get().uri(path).header("Authorization", "Bearer " + token);
    }

    // ── USER-SITUATIONAL DENY — ROLE_USER / ROLE_MOD vs infra paths ───────────

    @Test
    void user_forbiddenOn_actuator() {
        as(List.of("user"), "/actuator/health").exchange().expectStatus().isForbidden();
    }

    @Test
    void user_forbiddenOn_apiAdmin() {
        as(List.of("user"), "/api/admin/cluster/nodes").exchange().expectStatus().isForbidden();
    }

    @Test
    void mod_forbiddenOn_actuator() {
        // The infra-isolation invariant: a MOD is NOT an infra role, even though MOD
        // is a privileged user role. 403, never 200.
        as(List.of("mod"), "/actuator/metrics").exchange().expectStatus().isForbidden();
    }

    @Test
    void mod_forbiddenOn_apiAdmin() {
        as(List.of("mod"), "/api/admin/cassandra/keyspaces").exchange().expectStatus().isForbidden();
    }

    // ── USER-SITUATIONAL ALLOW — ROLE_ADMIN reaches infra ─────────────────────

    @Test
    void admin_allowedOn_actuator() {
        // ROLE_ADMIN is in the INFRA_PATHS allowlist (hasAnyRole GAME-MASTER/ADMIN/
        // SUPERADMIN). It reaches the controller (200), proving the gate is a role
        // allow, not a blanket deny.
        as(List.of("admin"), "/actuator/health").exchange().expectStatus().isOk();
    }

    @Test
    void admin_allowedOn_apiAdmin() {
        as(List.of("admin"), "/api/admin/cluster/nodes").exchange().expectStatus().isOk();
    }

    @Test
    void superadmin_allowedOn_actuator() {
        as(List.of("superadmin"), "/actuator/info").exchange().expectStatus().isOk();
    }

    // ── ANONYMOUS ALLOW — public + homeserver-passthrough paths ───────────────

    @Test
    void anonymous_allowedOn_publicPaths() {
        // PUBLIC_PATHS — login / registration / public announcements / appeal-contact
        // must be reachable with NO credentials.
        for (String path : List.of(
                "/api/auth/token",
                "/api/registration/start",
                "/api/login/options",
                "/bff/public/announcements/login",
                "/bff/public/appeal-contact")) {
            client.get().uri(path).exchange()
                    .expectStatus().value(s -> assertNot401Nor403(path, s));
        }
    }

    @Test
    void anonymous_allowedOn_homeserverPassthrough() {
        // HOMESERVER_PASSTHROUGH_PATHS — opaque Matrix/Mastodon bearers (not JWTs) +
        // first-run discovery must not be 401'd at the resource-server layer.
        for (String path : List.of(
                "/_matrix/client/versions",
                "/api/v1/timelines/public",
                "/.well-known/matrix/client")) {
            client.get().uri(path).exchange()
                    .expectStatus().value(s -> assertNot401Nor403(path, s));
        }
    }

    // ── ANONYMOUS DENY — the authenticated() floor ────────────────────────────

    @Test
    void anonymous_deniedOn_arbitraryGatedPath() {
        // anyExchange().authenticated() — an ungoverned, non-public path 401s an
        // anonymous caller.
        client.get().uri("/api/reports/q3").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void anonymous_deniedOn_infraPath() {
        // Infra paths are NEVER public — anonymous gets 401 (no auth) at the floor.
        client.get().uri("/actuator/health").exchange().expectStatus().isUnauthorized();
    }

    /** A path reached by an ALLOWED (permitAll) request must not be 401/403. The
     *  probe controller maps every path below, so a permitAll path resolves to 200;
     *  the only failures we guard against are the security 401/403. The WebTestClient
     *  status-value consumer hands us the RAW status code (int). */
    private static void assertNot401Nor403(String path, int status) {
        if (status == 401 || status == 403) {
            throw new AssertionError("expected anonymous ALLOW on " + path + " but got " + status);
        }
    }

    /** Maps every path the slice exercises so an ALLOWED request resolves to 200
     *  (instead of a 404 that could mask a missing security decision). */
    @RestController
    static class ProbeController {
        @RequestMapping({
                "/actuator/health", "/actuator/metrics", "/actuator/info",
                "/api/admin/cluster/nodes", "/api/admin/cassandra/keyspaces",
                "/api/reports/q3",
                "/api/auth/token", "/api/registration/start", "/api/login/options",
                "/bff/public/announcements/login", "/bff/public/appeal-contact",
                "/_matrix/client/versions", "/api/v1/timelines/public",
                "/.well-known/matrix/client",
        })
        Mono<String> ok() {
            return Mono.just("ok");
        }
    }
}
