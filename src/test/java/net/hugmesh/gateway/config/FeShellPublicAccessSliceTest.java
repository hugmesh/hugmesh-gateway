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

/**
 * FE-shell PUBLIC-access slice — the tier-scoped {@code FE_SHELL_PUBLIC_GET_PATHS}
 * floor in {@link SecurityConfig}. Proves the front-page parity fix (the
 * route-access seed carried {@code '/' -> PUBLIC} but the coarse
 * {@code anyExchange().authenticated()} floor 401'd anonymous {@code GET /}
 * before that rule was consulted — verified live on the compose front door) and
 * that the new public federation reads open ONLY on the fe tier, ONLY for GET.
 *
 * <p>Asserts:
 * <ul>
 *   <li><b>ANONYMOUS ALLOW (fe tier)</b> — {@code /}, the SPA shell assets, the
 *       vanity resolve and the capabilities projection are NOT 401/403 at the
 *       security layer on an instance named {@code *-fe-gateway};</li>
 *   <li><b>CONTROL DENY (fe tier)</b> — {@code /bff/user/**} (and the
 *       non-public federation manifest) still 401 anonymous on the SAME fe
 *       instance — the permits are scoped, not a floor removal;</li>
 *   <li><b>METHOD DENY (fe tier)</b> — a non-GET to a shell path still 401s
 *       (the permits are GET-only);</li>
 *   <li><b>TIER DENY (pki/be/unknown)</b> — the SAME anonymous {@code GET /}
 *       stays 401 on the pki and be tiers and on a blank instance name
 *       (fail-closed: the pki tier fronts the headscale control plane with a
 *       Host-but-no-Path route, and the route-access filter forwards anonymous
 *       traffic untouched — this coarse floor is the ONLY anonymous gate).</li>
 * </ul>
 */
class FeShellPublicAccessSliceTest extends SecuritySliceSupport {

    private TestIssuer issuer;
    private TestIssuer issuer2;   // second trusted issuer so isMultiIssuer() holds

    @BeforeEach
    void setUp() {
        issuer = new TestIssuer();
        issuer2 = new TestIssuer();
    }

    @AfterEach
    void tearDown() {
        issuer.close();
        issuer2.close();
    }

    private WebTestClient clientFor(String applicationName) {
        String issuersCsv = issuer.issuerUri() + "=brandx," + issuer2.issuerUri() + "=brandy";
        DomainRegistry registry = new DomainRegistry(issuer.issuerUri(), issuersCsv, "");
        TenancyResourceServerConfig tenancy = new TenancyResourceServerConfig(registry, "", "");
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                tenancy.tenantAuthManagerResolver();
        return sliceClient(applicationName, registry, provider(resolver), new ProbeController());
    }

    /** Every path the fe shell floor opens — the SPA document + root-level hashed
     *  bundles + federation public reads. Kept in ONE place so the allow and the
     *  cross-tier deny loops exercise the identical surface. */
    private static final List<String> FE_SHELL_PATHS = List.of(
            "/",
            "/index.html",
            "/favicon.ico",
            "/importmap.json",
            "/remoteEntry.json",
            "/main-PCXO4T2D.js",
            "/styles-76A67VRN.css",
            "/assets/logo.svg",
            "/api/federation/vanity",
            "/api/federation/vanity/somebody",
            "/api/federation/capabilities",
            // NATIVE-LOGIN: the anonymous login-ui SPA shell — the deep-link/hard-nav
            // entry point a logged-out visitor loads to see the username/password
            // form. Both the /login route document and its hashed bundles under
            // /login/** must be anonymous GET on the fe front door.
            "/login",
            "/login/main-ABCD1234.js");

    // ── ANONYMOUS ALLOW — the fe front door serves the shell + public reads ───

    @Test
    void anonymous_allowedOn_feShellPaths_onFeGateway() {
        WebTestClient fe = clientFor("hugmesh-fe-gateway");
        for (String path : FE_SHELL_PATHS) {
            fe.get().uri(path).exchange()
                    .expectStatus().value(s -> assertNot401Nor403(path, s));
        }
    }

    @Test
    void anonymous_allowedOn_feShellPaths_onPerBrandFeGateway() {
        // Per-brand instances derive the tier by SUFFIX (${BRAND}-fe-gateway),
        // exactly like CanonicalSeed.bySuffix — the shell must open there too.
        WebTestClient fe = clientFor("brandx-fe-gateway");
        for (String path : List.of("/", "/api/federation/capabilities")) {
            fe.get().uri(path).exchange()
                    .expectStatus().value(s -> assertNot401Nor403(path, s));
        }
    }

    // ── CONTROL DENY — the permits are scoped, the floor is intact ────────────

    @Test
    void anonymous_stillDeniedOn_bffUser_onFeGateway() {
        // The task's control path: /bff/user/** keeps requiring auth on the very
        // instance that now serves the anonymous shell.
        clientFor("hugmesh-fe-gateway")
                .get().uri("/bff/user/profile").exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void anonymous_stillDeniedOn_nonPublicFederationSurface_onFeGateway() {
        // /api/federation/** is NOT blanket-public: the manifest read stays on the
        // authenticated() floor — only vanity + capabilities opened.
        clientFor("hugmesh-fe-gateway")
                .get().uri("/api/federation/manifest").exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void anonymous_stillDeniedOn_nestedJsOutsideWebroot_onFeGateway() {
        // Ant '*' does not cross '/': only ROOT-level bundles are public; a nested
        // .js path is NOT matched by /*.js and stays on the floor.
        clientFor("hugmesh-fe-gateway")
                .get().uri("/bff/user/evil.js").exchange()
                .expectStatus().isUnauthorized();
    }

    // ── NATIVE-LOGIN — the anonymous auth entry points ────────────────────────

    @Test
    void anonymous_canPostCredentials_toBffLogin_onFeGateway() {
        // The native credential submit: an anonymous browser POSTs
        // {username,password} to /bff/login BEFORE it holds any session/role. It
        // is in PUBLIC_PATHS (all-method, all-tier), so the coarse floor must NOT
        // 401 it — otherwise there is no way to authenticate at all.
        clientFor("hugmesh-fe-gateway")
                .post().uri("/bff/login").exchange()
                .expectStatus().value(s -> assertNot401Nor403("/bff/login (POST)", s));
    }

    @Test
    void anonymous_canPostCredentials_toBffLogin_onPerBrandFeGateway() {
        // /bff/login lives in the all-tier PUBLIC_PATHS, so a per-brand front door
        // opens it too (a brand's users authenticate on that brand's login-ui).
        clientFor("brandx-fe-gateway")
                .post().uri("/bff/login").exchange()
                .expectStatus().value(s -> assertNot401Nor403("/bff/login (POST, brand)", s));
    }

    // ── METHOD DENY — GET-only permits ─────────────────────────────────────────

    @Test
    void anonymous_postDenied_onFeShellPath() {
        clientFor("hugmesh-fe-gateway")
                .post().uri("/").exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void anonymous_postDenied_onLoginShellPath() {
        // The login-ui shell floor is GET-only (FE_SHELL_PUBLIC_GET_PATHS): a
        // non-GET to /login/** is NOT the credential submit (that is the separate
        // /bff/login) and stays on the authenticated() floor — so a POST to the
        // static shell path is 401, exactly like a POST to '/'.
        clientFor("hugmesh-fe-gateway")
                .post().uri("/login").exchange()
                .expectStatus().isUnauthorized();
    }

    // ── TIER DENY — pki/be/unknown instances never open the shell ─────────────

    @Test
    void anonymous_deniedOn_shellPaths_onPkiGateway() {
        // The pki tier fronts headscale with a Host-but-no-Path route and the
        // route-access filter forwards anonymous requests untouched — the coarse
        // floor here is the ONLY anonymous gate, so it MUST stay closed.
        WebTestClient pki = clientFor("hugmesh-pki-gateway");
        for (String path : FE_SHELL_PATHS) {
            pki.get().uri(path).exchange().expectStatus().isUnauthorized();
        }
    }

    @Test
    void anonymous_deniedOn_shellPaths_onBeGateway() {
        WebTestClient be = clientFor("hugmesh-be-gateway");
        for (String path : List.of("/", "/index.html", "/assets/logo.svg")) {
            be.get().uri(path).exchange().expectStatus().isUnauthorized();
        }
    }

    @Test
    void anonymous_deniedOn_root_onBlankInstanceName() {
        // A misconfigured (blank) spring.application.name must NOT open the shell
        // — unknown tier fails closed, mirroring CanonicalSeed's deny-floor.
        clientFor("")
                .get().uri("/").exchange()
                .expectStatus().isUnauthorized();
    }

    /** A permitAll'd anonymous request must not be 401/403; the probe controller
     *  maps every exercised path, so an ALLOW resolves 200 (a 404 can't mask a
     *  missing mapping). */
    private static void assertNot401Nor403(String path, int status) {
        if (status == 401 || status == 403) {
            throw new AssertionError("expected anonymous ALLOW on " + path + " but got " + status);
        }
    }

    /** Maps every path the slice exercises so an ALLOWED request resolves to 200. */
    @RestController
    static class ProbeController {
        @RequestMapping({
                "/", "/index.html", "/favicon.ico", "/importmap.json",
                "/remoteEntry.json", "/main-PCXO4T2D.js", "/styles-76A67VRN.css",
                "/assets/logo.svg",
                "/api/federation/vanity", "/api/federation/vanity/somebody",
                "/api/federation/capabilities", "/api/federation/manifest",
                "/bff/user/profile", "/bff/user/evil.js",
                // NATIVE-LOGIN surfaces exercised by the login slice below.
                "/login", "/login/main-ABCD1234.js", "/bff/login",
        })
        Mono<String> ok() {
            return Mono.just("ok");
        }
    }
}
