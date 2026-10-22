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

    private WebTestClient feClient() {
        String issuersCsv = issuer.issuerUri() + "=brandx," + issuer2.issuerUri() + "=brandy";
        DomainRegistry registry = new DomainRegistry(issuer.issuerUri(), issuersCsv, "");
        TenancyResourceServerConfig tenancy = new TenancyResourceServerConfig(registry, "", "");
        return sliceClient("hugmesh-fe-gateway", registry,
                provider(tenancy.tenantAuthManagerResolver()), new ProbeController());
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
        // / the per-domain theme must be reachable with NO credentials.
        //
        // The theme pair is the newest and was the one that regressed: it served 200
        // direct from the admin-bff and 401 through the gateway, so the PRE-AUTH login
        // page rendered unbranded for every visitor. That is invisible to the Studio and
        // the admin UI, which are authenticated and always saw a correctly-themed mesh.
        for (String path : List.of(
                "/api/auth/token",
                "/api/registration/start",
                "/api/login/options",
                "/bff/public/announcements/login",
                "/bff/public/appeal-contact",
                "/bff/public/theme",
                "/bff/public/theme.css",
                // The anonymous forgot-password legs. They run with NO session by
                // definition, so a 401 here makes a correctly-routed reset
                // unreachable no matter what the route table says.
                "/bff/password-reset/request",
                "/bff/password-reset/confirm")) {
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

    @Test
    void anonymous_allowedOn_loginAndRegistrationRemotes() {
        // The two platform federated UI shells stay anonymous-reachable (they are
        // the pre-auth sign-in / sign-up pages). Pins that making the
        // /_remotes/banned/** permit opt-in did not touch its siblings.
        for (String path : List.of(
                "/_remotes/login/remoteEntry.json",
                "/_remotes/registration/remoteEntry.json")) {
            client.get().uri(path).exchange()
                    .expectStatus().value(s -> assertNot401Nor403(path, s));
        }
    }

    @Test
    void anonymous_deniedOn_bannedRemote_everySpelling() {
        // With app.security.banned-remote-public unset (the default) the prefix is on
        // the authenticated() floor: only hugmesh-games serves a remote there, and the
        // platform banned-user flow is the login-ui /login/appeal page, reached through
        // /bff/public/appeal-contact. RAW URIs, so the encoded,
        // dot-segment, case, trailing-slash and ;param spellings reach the matcher
        // exactly as a client would send them.
        for (String raw : List.of(
                "/_remotes/banned/x",
                "/_remotes/banned/remoteEntry.json",
                "/_remotes/banned/",
                "/_remotes/banned",
                "/_remotes/BANNED/x",
                "/_remotes/%62anned/x",
                "/_remotes/banned%2Fx",
                "/_remotes/%2562anned/x",
                "/_remotes/banned/./x",
                "/_remotes/login/../banned/x",
                "/_remotes/banned;a=b/x",
                "/_remotes/banned/x;a=b")) {
            client.get().uri(URI.create(raw)).exchange()
                    .expectStatus().value(status -> assertDeniedNotServed(raw, status));
        }
    }

    /** Anonymous must be refused: 401 from the authenticated() floor, or 400 where
     *  the server rejects the malformed spelling (an encoded slash) before routing.
     *  Anything else — above all 200 — means the path was served. */
    private static void assertDeniedNotServed(String raw, int status) {
        if (status != 401 && status != 400) {
            throw new AssertionError("expected anonymous DENY (401, or 400 for a malformed "
                    + "spelling) on " + raw + " but got " + status);
        }
    }

    @Test
    void feTier_deniedOn_bannedRemote() {
        // The fe front door adds anonymous SPA-shell permits on top of PUBLIC_PATHS;
        // none of them may cover the banned remote.
        WebTestClient fe = feClient();
        fe.get().uri("/_remotes/banned/remoteEntry.json").exchange()
                .expectStatus().isUnauthorized();
    }

    // ── OPT-IN banned-remote permit (app.security.banned-remote-public) ───────
    //
    // hugmesh-games serves a `banned` remote at /_remotes/banned/ and its host
    // (games.<domain>) is routed through the be-tier instance. The permit is kept
    // behind one switch so a games deployment can turn it back on.

    private static final String BE = "hugmesh-be-gateway";

    private WebTestClient tierClient(String applicationName, boolean bannedRemotePublic) {
        String issuersCsv = issuer.issuerUri() + "=brandx," + issuer2.issuerUri() + "=brandy";
        DomainRegistry registry = new DomainRegistry(issuer.issuerUri(), issuersCsv, "");
        TenancyResourceServerConfig tenancy = new TenancyResourceServerConfig(registry, "", "");
        return sliceClient(new SecurityConfig(registry, provider(tenancy.tenantAuthManagerResolver()),
                applicationName, false, 600_000L, List.of(), bannedRemotePublic),
                new ProbeController());
    }

    /** The production {@code @Autowired} constructor, fed the RAW property string. */
    private WebTestClient productionCtorClient(String applicationName, String rawFlag) {
        String issuersCsv = issuer.issuerUri() + "=brandx," + issuer2.issuerUri() + "=brandy";
        DomainRegistry registry = new DomainRegistry(issuer.issuerUri(), issuersCsv, "");
        TenancyResourceServerConfig tenancy = new TenancyResourceServerConfig(registry, "", "");
        return sliceClient(new SecurityConfig(registry, provider(tenancy.tenantAuthManagerResolver()),
                applicationName, false, 600_000L, absent(), rawFlag),
                new ProbeController());
    }

    @Test
    void beTier_flagOff_deniesBannedRemote() {
        // The default on the tier that fronts games: anonymous is refused.
        WebTestClient be = tierClient(BE, false);
        for (String path : List.of("/_remotes/banned/remoteEntry.json", "/_remotes/banned/x")) {
            be.get().uri(path).exchange().expectStatus().isUnauthorized();
        }
    }

    @Test
    void flagOn_servesBannedRemoteAnonymously_onEveryTier() {
        // The switch restores the anonymous permit games documents. RED if the flag
        // is not wired into the permit list.
        for (String tier : List.of(BE, "hugmesh-fe-gateway", "")) {
            WebTestClient c = tierClient(tier, true);
            for (String path : List.of("/_remotes/banned/remoteEntry.json", "/_remotes/banned/x")) {
                c.get().uri(path).exchange()
                        .expectStatus().value(s -> {
                            if (s != 200) {
                                throw new AssertionError("flag on, tier '" + tier
                                        + "': expected 200 on " + path + " but got " + s);
                            }
                        });
            }
        }
    }

    @Test
    void flagOn_opensOnlyTheBannedPrefix() {
        // With the permit on, no other path may ride it: case, a longer sibling
        // name, dot segments (plain, encoded, with ;params) and an encoded slash
        // that would climb out of the prefix all stay refused (401, or 400 where the
        // firewall rejects the spelling). ProbeController maps /api/reports/q3 and
        // /_remotes/**, so a leak would show as 200.
        WebTestClient c = tierClient(BE, true);
        for (String raw : List.of(
                "/_remotes/BANNED/x",
                "/_remotes/Banned/remoteEntry.json",
                "/_remotes/bannedx/y",
                "/_remotes/banned-appeal/y",
                "/_remotes/banned/../../api/reports/q3",
                "/_remotes/banned/%2e%2e/%2e%2e/api/reports/q3",
                "/_remotes/banned/%252e%252e/%252e%252e/api/reports/q3",
                "/_remotes/banned/..;/..;/api/reports/q3",
                "/_remotes/banned%2F..%2F..%2Fapi/reports/q3",
                "/_remotes/banned/..%2F..%2Fapi/reports/q3",
                "/_remotes/banned//../../api/reports/q3")) {
            c.get().uri(URI.create(raw)).exchange()
                    .expectStatus().value(status -> assertDeniedNotServed(raw, status));
        }
        // Control: a non-banned gated path is still refused with the flag on.
        c.get().uri("/api/reports/q3").exchange().expectStatus().isUnauthorized();
        c.get().uri("/_remotes/admin/remoteEntry.json").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void flagOn_onlyLiteralTrue_productionConstructorFailsClosed() {
        // The @Autowired constructor parses the raw property: anything but the
        // literal "true" (any case, trimmed) leaves the prefix closed.
        for (String raw : java.util.Arrays.asList(null, "", " ", "false", "yes", "1", "on",
                "tru", "true1", "\"true\"")) {
            productionCtorClient(BE, raw).get().uri("/_remotes/banned/remoteEntry.json")
                    .exchange().expectStatus().isUnauthorized();
        }
        for (String raw : List.of("true", "TRUE", " True ")) {
            productionCtorClient(BE, raw).get().uri("/_remotes/banned/remoteEntry.json")
                    .exchange().expectStatus().isOk();
        }
    }

    @Test
    void beTier_anonymousCannotLoadTheGamesShellOrManifest_eitherFlagState() {
        // Why the default can be OFF without breaking a working flow through this
        // gateway: the games shell (games.<domain>, be tier) is itself refused to an
        // anonymous visitor, and so is /api/federation/manifest, which the games
        // shell fetches with credentials 'omit' before it wires ANY remote. So no
        // anonymous games page ever reaches the step that would request
        // /_remotes/banned/remoteEntry.json. The flag does not change this.
        for (boolean flag : List.of(false, true)) {
            WebTestClient be = tierClient(BE, flag);
            for (String path : List.of("/", "/index.html", "/main.js",
                    "/api/federation/manifest")) {
                be.get().uri(path).exchange().expectStatus().isUnauthorized();
            }
        }
    }

    @Test
    void bannedRemote_authenticatedCallerNotBlockedByCoarseFloor() {
        // The floor is authenticated(), not a blanket deny: a signed-in user is let
        // through the coarse layer (route-access, a later layer, still governs).
        as(List.of("user"), "/_remotes/banned/remoteEntry.json").exchange()
                .expectStatus().isOk();
    }

    // ── ANONYMOUS DENY — the authenticated() floor ────────────────────────────

    @Test
    void anonymous_deniedOn_arbitraryGatedPath() {
        // anyExchange().authenticated() — an ungoverned, non-public path 401s an
        // anonymous caller.
        client.get().uri("/api/reports/q3").exchange().expectStatus().isUnauthorized();
    }

    /** The exact path plus the subtree paths that exist or are used as probes:
     *  stage 1 per provider, stage 2, and the /start probe the route-access test
     *  has always used. */
    private static final List<String> REGISTER_PATHS = List.of(
            "/bff/register", "/bff/register/start", "/bff/register/complete",
            "/bff/register/google", "/bff/register/discord");

    @Test
    void anonymous_deniedOn_bffRegister_exactAndSubtree() {
        // /bff/register is a COOKIE-AUTHENTICATED surface (docs/decisions/002).
        // user-bff's register mints a session for an allow-listed email without
        // proof that the caller owns it, so it must not be reachable anonymously:
        // the coarse floor 401s it before routing. Both the exact path (the POST
        // user-bff serves) and the /bff/register/** subtree (/start, /complete)
        // are pinned, on POST (the real verb) and GET. ProbeController maps every
        // path below, so an anonymous ALLOW would surface as a 200, not a 404 that
        // could be mistaken for a security decision. RED if "/bff/register" or
        // "/bff/register/**" is ever added to PUBLIC_PATHS.
        for (String path : REGISTER_PATHS) {
            client.post().uri(path).exchange().expectStatus().isUnauthorized();
            client.get().uri(path).exchange().expectStatus().isUnauthorized();
        }
        // Sibling control: the exact-path /bff/login stays anonymous in the same
        // chain, so a 401 above is the register decision, not a broken harness.
        client.get().uri("/bff/login").exchange()
                .expectStatus().value(st -> assertNot401Nor403("/bff/login", st));
    }

    @Test
    void authenticatedUser_reachesBffRegister() {
        // The other half of "cookie-authenticated": a ROLE_USER principal passes
        // the floor on the exact path and the subtree (route access is a separate
        // layer, pinned in GatewayRouteAccessServiceTest).
        for (String path : REGISTER_PATHS) {
            as(List.of("user"), path).exchange().expectStatus().isOk();
        }
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
                "/_remotes/**",
                "/actuator/health", "/actuator/metrics", "/actuator/info",
                "/api/admin/cluster/nodes", "/api/admin/cassandra/keyspaces",
                "/api/reports/q3",
                "/", "/index.html", "/main.js", "/api/federation/manifest",
                "/api/auth/token", "/api/registration/start", "/api/login/options",
                "/bff/public/announcements/login", "/bff/public/appeal-contact",
                "/bff/password-reset/request", "/bff/password-reset/confirm",
                "/bff/login", "/bff/register", "/bff/register/start", "/bff/register/complete",
                "/bff/register/google", "/bff/register/discord",
                "/_matrix/client/versions", "/api/v1/timelines/public",
                "/.well-known/matrix/client",
        })
        Mono<String> ok() {
            return Mono.just("ok");
        }
    }
}
