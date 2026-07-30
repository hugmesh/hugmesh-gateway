package systems.hugmesh.gateway.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;
import systems.hugmesh.gateway.cache.GatewayRouteAccessService;
import systems.hugmesh.gateway.cache.GatewayRouteAccessService.Rule;
import systems.hugmesh.gateway.cache.RevocationListService;
import systems.hugmesh.gateway.filter.GatewayRouteAccessFilter;
import systems.hugmesh.gateway.filter.RevocationGatewayFilter;
import systems.hugmesh.gateway.security.DomainRegistry;
import systems.hugmesh.gateway.testsupport.TestIssuer;

import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CROSS-REALM role-authorization matrix at the hugmesh-gateway front door —
 * the {@code systems} realm × {@code games} realm × {@code forum} surface ALLOW/DENY
 * cells the existing role-e2e suites do NOT cover.
 *
 * <p><b>What was missing.</b> The existing suites
 * ({@link MultiIssuerSecuritySliceTest}, {@link GatewayDenyChainSliceTest} and the
 * per-BFF {@code RawApiDeny*}/{@code RoleMatrix*} families) are <em>systems-realm
 * only</em>: their "foreign / rogue / unlisted issuer → 401" assertion uses a bare
 * extra {@link TestIssuer} <em>labelled</em> "games realm" in a comment, but there
 * is no fixture that models the TWO actual Casdoor REALMS the platform runs
 * (systems Casdoor at {@code https://id.hugmesh.systems}, org {@code hugmesh};
 * games Casdoor at {@code https://id.hugmesh.games}, org {@code threewizards} —
 * a SEPARATE, independent instance) and asserts the cross-realm boundary across all
 * three surfaces a gateway fronts. This suite adds exactly that, reusing the
 * established {@link TestIssuer} + {@link SecuritySliceSupport} harness and the REAL
 * assembled production chain (multi-issuer resource server + {@link RevocationGatewayFilter}
 * + {@link GatewayRouteAccessFilter}) behind a {@link WebTestClient} — no parallel
 * harness, no live Casdoor, no network beyond {@code 127.0.0.1}.
 *
 * <p><b>The three realms / surfaces modelled.</b>
 * <ul>
 *   <li><b>systems realm</b> — issuer stands for {@code https://id.hugmesh.systems}.
 *       Roles {@code user/mod/admin/superadmin}. SUPERADMIN is the cross-domain infra
 *       control plane (systems-ONLY: it does not exist in the games realm).</li>
 *   <li><b>games realm</b> — issuer stands for {@code https://id.hugmesh.games}.
 *       Roles {@code user/mod/admin/publisher} — there is NO {@code superadmin} and NO
 *       {@code game-master} in the games realm seed. The same role NAME ({@code admin})
 *       collides with systems, but authority MUST stay realm-scoped via the
 *       issuer-derived {@code DOMAIN_<realm>}.</li>
 *   <li><b>forum surface</b> — phpBB-backed, fronted by hugmesh-forum-bff which
 *       trusts the SYSTEMS realm ({@code issuer-uri: https://id.hugmesh.systems}).
 *       At the gateway the forum admin/mod surface is the systems-realm
 *       {@code /bff/forum/admin/**} + {@code /bff/forum/**} route (gated ROLE_ADMIN /
 *       ROLE_FORUM here; the {@code ROLE_FORUM_MOD = MOD ∩ FORUM} AND-composite is the
 *       forum-bff's own downstream @PreAuthorize concern, asserted in forum-bff). The
 *       cross-REALM property — a games-realm token can NEVER reach the forum — is a
 *       gateway concern and is asserted here.</li>
 * </ul>
 *
 * <p><b>The cross-realm threat model (what each cell defends).</b>
 * <ol>
 *   <li><b>Realm isolation / fail-closed.</b> A systems gateway configures ONLY the
 *       systems Casdoor as its resource-server issuer. A games-realm token presented
 *       to it (even minted {@code admin}+{@code superadmin}) carries a {@code iss}
 *       NOT in the trusted set → 401 at the resource server BEFORE any role decision,
 *       on EVERY surface (systems, games, forum). There is no default-accept manager.
 *       Symmetrically a systems-realm token at a games-realm gateway is 401'd.</li>
 *   <li><b>Realm-confused token.</b> Right role NAME, wrong realm/issuer. Because the
 *       domain is derived from the cryptographically-validated {@code iss} (never the
 *       authorities list / a request claim), a games-realm {@code admin} can never
 *       present as the systems domain — even when BOTH realms are trusted by one front
 *       door, the games-realm admin is HARD-DENIED on a systems-domain Host (domain
 *       mismatch) and lacks the {@code ROLE_GAMES_ADMIN} composite the games admin API
 *       requires.</li>
 *   <li><b>SUPERADMIN does not leak across realms.</b> A systems SUPERADMIN crosses
 *       systems DOMAINS (the one cross-domain ALLOW) but is NOT a games admin: the
 *       games realm has no superadmin concept, and a games-realm token can't carry one
 *       anyway.</li>
 * </ol>
 *
 * <p><b>ALLOW / DENY matrix (the cells this suite pins).</b> Each cell pairs the HTTP
 * status with the mutation-resistant {@link #downstreamHits()} oracle — a DENY must
 * leave the downstream {@link DownstreamEchoController} untouched (0 hits); a fail-OPEN
 * (a real cross-realm authz gap) would forward, bump the counter and FAIL loudly.
 *
 * <pre>
 *  TOKEN REALM / ROLE          SURFACE (systems gateway, systems realm trusted ONLY)
 *                              systems /api/admin   forum /bff/forum/admin   games /games/api/admin   games portal /games
 *  ─────────────────────────   ──────────────────   ──────────────────────   ──────────────────────   ───────────────────
 *  systems user                403 (not admin)      403 (not admin)          403 (no games role)      403 (no ROLE_GAMES)
 *  systems mod                 403 (not admin)      403*(forum-mod=MOD∩FORUM 403 (no ROLE_GAMES_ADMIN)200 (mod superset)
 *                                                    is downstream; gw=admin)
 *  systems admin (own domain)  200 (admin bypass)   200 (admin bypass)       200 (admin own-domain    200 (admin superset)
 *                                                                            bypass; ROLE_GAMES_ADMIN
 *                                                                            enforced downstream)
 *  systems superadmin          200 (cross-domain)   200                      200                      200
 *  games user/mod/admin/super  401 (untrusted iss — fail closed on EVERY systems/forum/games surface)
 *  realm-confused (games admin 401 (untrusted iss) on a systems gateway; and when BOTH realms trusted:
 *    name, games iss)          403 on systems-domain Host (domain mismatch) / 403 on games admin API (no composite)
 * </pre>
 * (*the forum {@code MOD ∩ FORUM} AND-composite for moderation is enforced by the
 * forum-bff downstream, not the gateway; at the gateway a systems mod is governed by
 * the {@code /bff/forum/admin/** → ROLE_ADMIN} row and is therefore denied the admin
 * console — pinned below.)
 *
 * <p>TEST-ONLY: no production code changes; all keys/JWTs generated in-process (no
 * secrets); no network beyond {@code 127.0.0.1} (the TestIssuer JWKS servers).
 */
class CrossRealmRoleMatrixSliceTest extends SecuritySliceSupport {

    private static final String GW = "hugmesh-be-gateway";

    // The production issuer URIs each realm uses (labels for readability; the actual
    // iss values in the minted tokens are the in-process TestIssuer loopback URIs).
    private static final String SYSTEMS_ISS_LABEL = "https://id.hugmesh.systems";
    private static final String GAMES_ISS_LABEL   = "https://id.hugmesh.games";

    /** The systems realm (id.hugmesh.systems, org hugmesh). Domain "systems". */
    private TestIssuer systemsRealm;
    /** A second systems-realm brand issuer — needed only to push a single-realm
     *  registry into multi-issuer mode (so the per-issuer resolver swap is exercised)
     *  without ever trusting the OTHER realm. It is always a SYSTEMS-realm brand. */
    private TestIssuer systemsRealmB;
    /** The games realm (id.hugmesh.games, org threewizards — a SEPARATE Casdoor). */
    private TestIssuer gamesRealm;

    private DownstreamEchoController echo;

    @BeforeEach
    void setUp() {
        systemsRealm = new TestIssuer();
        systemsRealmB = new TestIssuer();
        gamesRealm = new TestIssuer();
        echo = new DownstreamEchoController();
    }

    @AfterEach
    void tearDown() {
        systemsRealm.close();
        systemsRealmB.close();
        gamesRealm.close();
    }

    // ───────────────────────────── wiring helpers ─────────────────────────────

    /**
     * The FAITHFUL systems gateway posture: its resource server trusts ONLY the
     * systems realm's Casdoor issuer (one Casdoor per realm — the games Casdoor is a
     * separate instance the systems be-gateway does NOT configure). Two listed issuers
     * are required to take the multi-issuer resolver swap, so we register a second
     * systems-realm BRAND ({@code systems} + {@code systemsb}) — both systems-realm
     * issuers; the games realm is deliberately NOT listed. Host map pins the systems
     * brands so the route-access filter computes a non-default targetDomain from Host.
     */
    private DomainRegistry systemsOnlyRegistry() {
        // Both trusted issuers are SYSTEMS-realm brands; the games realm is untrusted.
        String issuers = systemsRealm.issuerUri() + "=systems,"
                + systemsRealmB.issuerUri() + "=systemsb";
        String hosts = "api.systems.tld=systems,api.systemsb.tld=systemsb";
        DomainRegistry registry = new DomainRegistry(systemsRealm.issuerUri(), issuers, hosts);
        assertThat(registry.isMultiIssuer())
                .as("two trusted issuers => multi-issuer mode (the resolver swap is taken)").isTrue();
        assertThat(registry.isTrusted(gamesRealm.issuerUri()))
                .as("the games realm's Casdoor is NOT trusted by the systems gateway").isFalse();
        return registry;
    }

    /**
     * The HYPOTHETICAL merged front door that trusts BOTH realms (systems + games).
     * Used to prove that even when the games realm IS a trusted issuer, a games-realm
     * token does NOT gain systems authority: it is scoped to {@code DOMAIN_games} and
     * fails the domain HARD-DENY on a systems-domain Host and the composite gate on the
     * games admin API. (Production runs separate per-realm gateways; this models the
     * defence-in-depth property under the worst-case shared-issuer config.)
     */
    private DomainRegistry bothRealmsRegistry() {
        String issuers = systemsRealm.issuerUri() + "=systems," + gamesRealm.issuerUri() + "=games";
        String hosts = "api.systems.tld=systems,api.games.tld=games";
        DomainRegistry registry = new DomainRegistry(systemsRealm.issuerUri(), issuers, hosts);
        assertThat(registry.isMultiIssuer()).isTrue();
        assertThat(registry.isTrusted(gamesRealm.issuerUri()))
                .as("the merged front door trusts the games realm as an issuer").isTrue();
        return registry;
    }

    /** The REAL per-issuer resolver bean, built exactly as TenancyResourceServerConfig
     *  contributes it — each realm decoder discovers from its own in-process issuer. */
    private ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>> resolver(
            DomainRegistry registry) {
        TenancyResourceServerConfig tenancy = new TenancyResourceServerConfig(registry, "", "");
        return SecuritySliceSupport.provider(tenancy.tenantAuthManagerResolver());
    }

    /**
     * A REAL route-access service for the be-gateway, primed with the canonical-seed
     * cross-surface rows the cross-realm matrix probes:
     * <ul>
     *   <li>SYSTEMS — {@code /api/admin/** → ROLE_ADMIN}, {@code /bff/superadmin/** →
     *       ROLE_SUPERADMIN}, the {@code /api/** → ROLE_USER} floor.</li>
     *   <li>FORUM — {@code /bff/forum/admin/** → ROLE_ADMIN} (the admin console seam,
     *       mirrors forum-bff's {@code hasAnyRole(ADMIN,SUPERADMIN)}), {@code /bff/forum/**
     *       → ROLE_FORUM} (the floor enforced at fe-gateway in prod; modelled here so
     *       the cross-realm denial has a governed surface to land on).</li>
     *   <li>GAMES — {@code /games/api/admin/** → ROLE_GAMES_ADMIN} (the DERIVED composite
     *       = ROLE_GAMES ∩ (ROLE_ADMIN ∪ ROLE_MOD); a single role is default-deny),
     *       {@code /games/** → ROLE_GAMES | ROLE_ADMIN | ROLE_MOD} (the portal floor +
     *       admin/mod supersets), exactly the {@code CanonicalSeed.be()} rows.</li>
     * </ul>
     * Every row is domain-UNSCOPED (domain==null) like the canonical seed, so the
     * per-row brand scoping never masks the cross-REALM property under test (the realm
     * boundary is the issuer-trust + domain-of-issuer layers, not the route rows).
     */
    private GatewayRouteAccessService realRouteAccess() {
        GatewayRouteAccessService svc =
                new GatewayRouteAccessService(null, null, GW, true, false, null);
        svc.primeForTest(List.of(
                // ── systems realm surface ──
                new Rule("sys-admin",   GW, "/api/admin/**",       "ROLE_ADMIN",       null, true, null, false),
                new Rule("sys-super",   GW, "/bff/superadmin/**",  "ROLE_SUPERADMIN",  null, true, null, false),
                new Rule("sys-floor",   GW, "/api/**",             "ROLE_USER",        null, true, null, false),
                // ── forum surface (systems realm, phpBB-backed) ──
                new Rule("forum-admin", GW, "/bff/forum/admin/**", "ROLE_ADMIN",       null, true, null, false),
                new Rule("forum-floor", GW, "/bff/forum/**",       "ROLE_FORUM",       null, true, null, false),
                // ── games realm surface ──
                new Rule("games-admin", GW, "/games/api/admin/**", "ROLE_GAMES_ADMIN", null, true, null, false),
                new Rule("games-floor", GW, "/games/**",           "ROLE_GAMES",       null, true, null, false),
                new Rule("games-asup",  GW, "/games/**",           "ROLE_ADMIN",       null, true, null, false),
                new Rule("games-msup",  GW, "/games/**",           "ROLE_MOD",         null, true, null, false)));
        return svc;
    }

    private RevocationListService noRevocations() {
        RevocationListService svc = new RevocationListService(null, true);
        svc.primeRevokedForTest(Set.of());
        return svc;
    }

    /** Assemble the WebTestClient through the FULL production chain: SecurityConfig
     *  (multi-issuer) + RevocationGatewayFilter + GatewayRouteAccessFilter, in
     *  production order, in front of the echo controller. */
    private WebTestClient client(DomainRegistry registry) {
        List<WebFilter> gatewayFilters = List.of(
                new RevocationGatewayFilter(noRevocations(), true),
                new GatewayRouteAccessFilter(realRouteAccess(), registry));
        return sliceClientWithGatewayFilters(registry, resolver(registry), gatewayFilters, echo);
    }

    private int downstreamHits() {
        return echo.hits.get();
    }

    // Convenience: GET a surface with a token + Host, returning the spec for status asserts.
    private WebTestClient.ResponseSpec get(WebTestClient client, String token, String host, String path) {
        return client.get().uri(path)
                .header(org.springframework.http.HttpHeaders.HOST, host)
                .header("Authorization", "Bearer " + token)
                .exchange();
    }

    // ════════════════════════════════════════════════════════════════════════
    //  (1) REALM ISOLATION — a games-realm token is 401'd on a systems gateway at
    //      EVERY surface (systems / forum / games), fail-closed, never default-accept.
    //      This is the load-bearing cross-realm boundary.
    // ════════════════════════════════════════════════════════════════════════
    @Nested
    class GamesRealmTokenAtSystemsGateway {

        // The systems gateway trusts ONLY the systems Casdoor. A games-realm token
        // (separate Casdoor, separate iss) is rejected at the resource server before
        // any role/route decision. We probe with the MOST privileged games-realm token
        // we can mint — admin AND a forged superadmin — to prove privilege can't buy a
        // crossing: the failure is the ISSUER, not the role.

        private WebTestClient systemsGateway() {
            return client(systemsOnlyRegistry());
        }

        @Test
        void gamesRealmAdmin_atSystemsAdminApi_is401_failClosed_neverDownstream() {
            WebTestClient client = systemsGateway();
            String token = gamesRealm.mint("g-admin", List.of("admin", "superadmin"));
            get(client, token, "api.systems.tld", "/api/admin/secrets")
                    .expectStatus().isUnauthorized();
            assertThat(downstreamHits())
                    .as("a games-realm (" + GAMES_ISS_LABEL + ") token is 401'd at a systems "
                            + "(" + SYSTEMS_ISS_LABEL + ") gateway's admin API — untrusted issuer, "
                            + "never reaches the route/role layer or downstream").isZero();
        }

        @Test
        void gamesRealmAdmin_atForumAdminConsole_is401_failClosed_neverDownstream() {
            WebTestClient client = systemsGateway();
            String token = gamesRealm.mint("g-admin", List.of("admin"));
            get(client, token, "api.systems.tld", "/bff/forum/admin/boards")
                    .expectStatus().isUnauthorized();
            assertThat(downstreamHits())
                    .as("the forum is a SYSTEMS-realm surface; a games-realm admin can NEVER "
                            + "reach the forum admin console").isZero();
        }

        @Test
        void gamesRealmUser_atForumFloor_is401_failClosed_neverDownstream() {
            WebTestClient client = systemsGateway();
            String token = gamesRealm.mint("g-user", List.of("user"));
            get(client, token, "api.systems.tld", "/bff/forum/threads/42")
                    .expectStatus().isUnauthorized();
            assertThat(downstreamHits())
                    .as("even the forum READ floor is closed to a games-realm token").isZero();
        }

        @Test
        void gamesRealmAdmin_atGamesAdminApi_onSystemsGateway_is401_failClosed() {
            // Even the GAMES surface, when fronted by the SYSTEMS gateway, is closed to
            // a games-realm token: the games portal here is served by the systems
            // be-gateway whose ONLY trusted issuer is the systems Casdoor. The games
            // realm's own BFF/gateway is where a games-realm token authenticates — NOT
            // the systems front door. (Issuer trust is the boundary, not the URL slug.)
            WebTestClient client = systemsGateway();
            String token = gamesRealm.mint("g-admin", List.of("admin"));
            get(client, token, "api.systems.tld", "/games/api/admin/catalog")
                    .expectStatus().isUnauthorized();
            assertThat(downstreamHits()).isZero();
        }

        @Test
        void gamesRealmPublisher_atSystemsFloor_is401_failClosed() {
            // ROLE_PUBLISHER exists ONLY in the games realm; presented to the systems
            // gateway it is still just an untrusted-issuer token -> 401.
            WebTestClient client = systemsGateway();
            String token = gamesRealm.mint("g-pub", List.of("publisher"));
            get(client, token, "api.systems.tld", "/api/reports/q3")
                    .expectStatus().isUnauthorized();
            assertThat(downstreamHits()).isZero();
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  (2) REVERSE ISOLATION — a SYSTEMS-realm token at a GAMES-realm gateway is
    //      401'd. The games realm enforces its OWN iss (id.hugmesh.games); a
    //      systems token (incl. a systems superadmin) cannot cross IN. SUPERADMIN is
    //      systems-cross-DOMAIN, never cross-REALM.
    // ════════════════════════════════════════════════════════════════════════
    @Nested
    class SystemsRealmTokenAtGamesGateway {

        /** A GAMES gateway: trusts ONLY the games Casdoor (+ a second games brand to
         *  reach multi-issuer mode). The systems realm is NOT listed. */
        private DomainRegistry gamesOnlyRegistry() {
            String issuers = gamesRealm.issuerUri() + "=games," + systemsRealmB.issuerUri() + "=gamesb";
            // NB: systemsRealmB stands in here purely as the "second trusted brand" to
            // enable the resolver swap; the SYSTEMS realm proper (systemsRealm) is the
            // untrusted one under test.
            String hosts = "api.games.tld=games,api.gamesb.tld=gamesb";
            DomainRegistry registry = new DomainRegistry(gamesRealm.issuerUri(), issuers, hosts);
            assertThat(registry.isMultiIssuer()).isTrue();
            assertThat(registry.isTrusted(systemsRealm.issuerUri()))
                    .as("the games gateway does NOT trust the systems realm's Casdoor").isFalse();
            return registry;
        }

        private WebTestClient gamesGateway() {
            DomainRegistry registry = gamesOnlyRegistry();
            List<WebFilter> gatewayFilters = List.of(
                    new RevocationGatewayFilter(noRevocations(), true),
                    new GatewayRouteAccessFilter(realRouteAccess(), registry));
            return sliceClientWithGatewayFilters(registry, resolver(registry), gatewayFilters, echo);
        }

        @Test
        void systemsAdmin_atGamesAdminApi_is401_failClosed_neverDownstream() {
            String token = systemsRealm.mint("s-admin", List.of("admin"));
            get(gamesGateway(), token, "api.games.tld", "/games/api/admin/catalog")
                    .expectStatus().isUnauthorized();
            assertThat(downstreamHits())
                    .as("a systems-realm admin is NOT a games admin — untrusted at the games "
                            + "gateway, 401 before any role/route decision").isZero();
        }

        @Test
        void systemsSuperadmin_atGamesAdminApi_is401_superadminDoesNotLeakAcrossRealms() {
            // SUPERADMIN is the systems cross-DOMAIN infra control plane — it does NOT
            // exist in the games realm and cannot cross the realm boundary. A systems
            // superadmin token at the games gateway is just an untrusted-issuer token.
            String token = systemsRealm.mint("s-root", List.of("admin", "superadmin"));
            get(gamesGateway(), token, "api.games.tld", "/games/api/admin/catalog")
                    .expectStatus().isUnauthorized();
            assertThat(downstreamHits())
                    .as("SUPERADMIN crosses systems DOMAINS, never the systems→games REALM "
                            + "boundary").isZero();
        }

        @Test
        void systemsUser_atGamesPortalFloor_is401_failClosed() {
            String token = systemsRealm.mint("s-user", List.of("user"));
            get(gamesGateway(), token, "api.games.tld", "/games/portal/home")
                    .expectStatus().isUnauthorized();
            assertThat(downstreamHits()).isZero();
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  (3) SAME-REALM POSITIVE CONTROLS — the systems realm's OWN tokens get the
    //      CORRECT allows/denies on the systems + forum + games surfaces. These are
    //      the non-vacuous counterparts: they prove the 401s above are the REALM
    //      boundary, not a blanket block, and pin the in-realm role matrix.
    // ════════════════════════════════════════════════════════════════════════
    @Nested
    class SystemsRealmInRealmMatrix {

        private WebTestClient systemsGateway() {
            return client(systemsOnlyRegistry());
        }

        // ── systems /api/admin/** surface ──

        @Test
        void systemsUser_atSystemsAdminApi_isDenied403_notAdmin() {
            WebTestClient client = systemsGateway();
            String token = systemsRealm.mint("s-user", List.of("user"));
            get(client, token, "api.systems.tld", "/api/admin/secrets")
                    .expectStatus().isForbidden()
                    .expectHeader().exists("X-Route-Denied");
            assertThat(downstreamHits()).as("a systems user is not a systems admin").isZero();
        }

        @Test
        void systemsMod_atSystemsAdminApi_isDenied403_modIsNotAdmin() {
            // ADMIN and MOD are documented SIBLINGS (the RoleHierarchy has only
            // SUPERADMIN>{ADMIN,MOD,USER}, NO ADMIN>MOD edge) — a mod can never climb to
            // admin at the gateway.
            WebTestClient client = systemsGateway();
            String token = systemsRealm.mint("s-mod", List.of("mod"));
            get(client, token, "api.systems.tld", "/api/admin/secrets")
                    .expectStatus().isForbidden();
            assertThat(downstreamHits()).isZero();
        }

        @Test
        void systemsAdmin_atSystemsAdminApi_ownDomain_isAllowed200() {
            WebTestClient client = systemsGateway();
            String token = systemsRealm.mint("s-admin", List.of("admin"));
            get(client, token, "api.systems.tld", "/api/admin/secrets")
                    .expectStatus().isOk();
            assertThat(downstreamHits())
                    .as("a systems admin reaches its OWN realm+domain admin API (own-domain "
                            + "gateway bypass)").isEqualTo(1);
        }

        @Test
        void systemsSuperadmin_atSystemsSuperadminSurface_isAllowed200() {
            WebTestClient client = systemsGateway();
            String token = systemsRealm.mint("s-root", List.of("superadmin"));
            get(client, token, "api.systems.tld", "/bff/superadmin/cluster")
                    .expectStatus().isOk();
            assertThat(downstreamHits()).isEqualTo(1);
        }

        @Test
        void systemsMod_atSystemsSuperadminSurface_isDenied403() {
            WebTestClient client = systemsGateway();
            String token = systemsRealm.mint("s-mod", List.of("mod"));
            get(client, token, "api.systems.tld", "/bff/superadmin/cluster")
                    .expectStatus().isForbidden();
            assertThat(downstreamHits()).isZero();
        }

        // ── forum /bff/forum/** surface (systems realm) ──

        @Test
        void systemsAdmin_atForumAdminConsole_isAllowed200() {
            WebTestClient client = systemsGateway();
            String token = systemsRealm.mint("s-admin", List.of("admin"));
            get(client, token, "api.systems.tld", "/bff/forum/admin/boards")
                    .expectStatus().isOk();
            assertThat(downstreamHits())
                    .as("forum admin console = ROLE_ADMIN at the gateway (own-domain bypass)")
                    .isEqualTo(1);
        }

        @Test
        void systemsMod_atForumAdminConsole_isDenied403_atGateway() {
            // GATEWAY-LAYER PIN: the forum admin console row is /bff/forum/admin/** ->
            // ROLE_ADMIN, so a plain systems MOD is denied here. The forum MODERATION
            // capability (the AND-composite ROLE_FORUM_MOD = MOD ∩ FORUM) is a SEPARATE,
            // non-admin surface gated by the forum-bff's downstream @PreAuthorize — NOT
            // by this gateway row. This cell pins the gateway decision only.
            WebTestClient client = systemsGateway();
            String token = systemsRealm.mint("s-mod", List.of("mod"));
            get(client, token, "api.systems.tld", "/bff/forum/admin/boards")
                    .expectStatus().isForbidden();
            assertThat(downstreamHits())
                    .as("a systems mod is NOT a forum ADMIN at the gateway; forum MOD∩FORUM "
                            + "moderation is a downstream forum-bff concern").isZero();
        }

        @Test
        void systemsForumUser_atForumFloor_isAllowed200() {
            // A systems user carrying the platform ROLE_FORUM access role reaches the
            // forum READ floor. (ROLE_FORUM is the network-wide forum-access grant; a
            // forum ban is its removal -> governed-but-ungranted -> deny.)
            WebTestClient client = systemsGateway();
            String token = systemsRealm.mint("s-forumuser", List.of("forum"));
            get(client, token, "api.systems.tld", "/bff/forum/threads/42")
                    .expectStatus().isOk();
            assertThat(downstreamHits())
                    .as("a systems ROLE_FORUM holder reaches the forum read floor").isEqualTo(1);
        }

        @Test
        void systemsPlainUser_withoutForumRole_atForumFloor_isDenied403() {
            // A systems user WITHOUT ROLE_FORUM is governed-but-ungranted on the forum
            // floor -> 403 (the forum is opt-in access, not every user's by default).
            WebTestClient client = systemsGateway();
            String token = systemsRealm.mint("s-user", List.of("user"));
            get(client, token, "api.systems.tld", "/bff/forum/threads/42")
                    .expectStatus().isForbidden();
            assertThat(downstreamHits()).isZero();
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  (4) SYSTEMS REALM ON THE GAMES SURFACE — role-name collision is realm-scoped.
    //      A systems admin/mod reaching the GAMES portal/admin API (served on the
    //      systems gateway under /games/**) is governed by the games composite rows,
    //      NOT by being a "systems admin". A systems admin is NOT a games admin unless
    //      it ALSO holds the games-access composite (ROLE_GAMES_ADMIN).
    // ════════════════════════════════════════════════════════════════════════
    @Nested
    class SystemsRealmOnGamesSurface {

        private WebTestClient systemsGateway() {
            return client(systemsOnlyRegistry());
        }

        @Test
        void systemsAdmin_atGamesAdminApi_takesOwnDomainAdminBypass_PIN() {
            // BEHAVIOUR PIN (documented gateway contract, NOT a fail-open): a systems
            // ADMIN in its OWN domain takes the GatewayRouteAccessFilter ADMIN
            // own-domain bypass, which returns chain.filter() BEFORE the route-access
            // decide() — so the /games/api/admin/** -> ROLE_GAMES_ADMIN composite is NOT
            // enforced against an in-domain admin AT THE GATEWAY. The "a systems admin is
            // NOT automatically a games admin" distinction on this surface is enforced
            // DOWNSTREAM by the games BFF's @PreAuthorize / per-game scope (Postgres
            // mod_game_scopes / publisher_game_scopes), exactly as the superadmin-vs-admin
            // distinction is deferred downstream on /bff/superadmin/**. We pin the current
            // assembled-chain decision (forward) so a regression in either direction is
            // caught loudly. The COMPOSITE gate proper is exercised against a
            // NON-bypassing principal below.
            WebTestClient client = systemsGateway();
            String token = systemsRealm.mint("s-admin", List.of("admin"));
            get(client, token, "api.systems.tld", "/games/api/admin/catalog")
                    .expectStatus().isOk();
            assertThat(downstreamHits())
                    .as("in-own-domain systems admin takes the documented gateway admin "
                            + "bypass; the games-admin-composite distinction is downstream")
                    .isEqualTo(1);
        }

        @Test
        void systemsMod_withoutGamesRole_atGamesAdminApi_isDenied403_compositeNotSatisfied() {
            // A systems MOD is a NON-bypassing principal (mod is not admin/superadmin),
            // so it reaches the route-access decide(). The deciding longest-pattern rule
            // is /games/api/admin/** -> ROLE_GAMES_ADMIN. A plain ROLE_MOD does NOT hold
            // the DERIVED composite ROLE_GAMES_ADMIN (= ROLE_GAMES ∩ (ROLE_ADMIN ∪
            // ROLE_MOD), materialized by games-admin-sync in Casdoor) -> governed-but-
            // ungranted -> 403. This is the cell that proves "a systems mod is NOT a games
            // admin": the role NAME mod/admin does not auto-confer games authority.
            WebTestClient client = systemsGateway();
            String token = systemsRealm.mint("s-mod", List.of("mod"));
            get(client, token, "api.systems.tld", "/games/api/admin/catalog")
                    .expectStatus().isForbidden()
                    .expectHeader().exists("X-Route-Denied");
            assertThat(downstreamHits())
                    .as("a systems mod lacking the games-access composite is denied the games "
                            + "admin API").isZero();
        }

        @Test
        void systemsModWithGamesComposite_atGamesAdminApi_isAllowed200() {
            // The non-vacuous counterpart: a systems mod that ALSO holds the derived
            // games-access composite ROLE_GAMES_ADMIN (granted via games-admin-sync) DOES
            // reach the games admin API. Proves the 403 above is the missing composite,
            // not a blanket block. (A non-bypassing principal: it carries ROLE_GAMES_ADMIN
            // but NOT ROLE_ADMIN, so it goes through decide().)
            WebTestClient client = systemsGateway();
            String token = systemsRealm.mint("s-gadmin", List.of("mod", "games", "games_admin"));
            get(client, token, "api.systems.tld", "/games/api/admin/catalog")
                    .expectStatus().isOk();
            assertThat(downstreamHits())
                    .as("a systems principal holding the games-access composite reaches the "
                            + "games admin API").isEqualTo(1);
        }

        @Test
        void systemsUser_withoutGamesRole_atGamesPortalFloor_isDenied403() {
            // The games PORTAL floor is /games/** -> ROLE_GAMES | ROLE_ADMIN | ROLE_MOD.
            // A plain systems user holds none of those -> 403. A games ban is removal of
            // ROLE_GAMES -> governed-but-ungranted -> deny.
            WebTestClient client = systemsGateway();
            String token = systemsRealm.mint("s-user", List.of("user"));
            get(client, token, "api.systems.tld", "/games/portal/home")
                    .expectStatus().isForbidden();
            assertThat(downstreamHits()).isZero();
        }

        @Test
        void systemsGamesAccessUser_atGamesPortalFloor_isAllowed200() {
            WebTestClient client = systemsGateway();
            String token = systemsRealm.mint("s-gamer", List.of("games"));
            get(client, token, "api.systems.tld", "/games/portal/home")
                    .expectStatus().isOk();
            assertThat(downstreamHits())
                    .as("a systems ROLE_GAMES holder reaches the games portal floor")
                    .isEqualTo(1);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  (5) REALM-CONFUSED TOKEN under a MERGED (both-realms-trusted) front door.
    //      Right role NAME (admin), wrong realm/issuer (games). Even when the games
    //      realm IS a trusted issuer, the games-realm admin is scoped to DOMAIN_games
    //      (from the validated iss) and cannot present as the systems domain, nor does
    //      its bare `admin` satisfy the games-admin COMPOSITE.
    // ════════════════════════════════════════════════════════════════════════
    @Nested
    class RealmConfusedTokenUnderMergedFrontDoor {

        private WebTestClient mergedGateway() {
            return client(bothRealmsRegistry());
        }

        @Test
        void gamesRealmAdmin_onSystemsDomainHost_isHardDenied403_domainMismatch() {
            // The games-realm admin authenticates (games iss IS trusted here) and is
            // stamped DOMAIN_games from its validated issuer. Presented to the
            // SYSTEMS-domain Host (targetDomain=systems), the non-superadmin domain
            // HARD-DENY fires: DOMAIN_games != systems -> 403, before the route-access
            // GRANT layer can even be consulted. The role NAME `admin` is irrelevant —
            // the realm/domain mismatch is decisive. This is the core "realm-confused"
            // cell: a games admin can never act as a systems admin even on a shared
            // front door.
            WebTestClient client = mergedGateway();
            String token = gamesRealm.mint("g-admin", List.of("admin"));
            get(client, token, "api.systems.tld", "/api/admin/secrets")
                    .expectStatus().isForbidden()
                    .expectHeader().exists("X-Route-Denied");
            assertThat(downstreamHits())
                    .as("a games-realm admin is HARD-DENIED on a systems-domain surface "
                            + "(DOMAIN_games != systems), regardless of the colliding role name")
                    .isZero();
        }

        @Test
        void gamesRealmAdmin_onForumAdminConsole_systemsDomainHost_isHardDenied403() {
            // The forum is a systems-domain surface; the same domain HARD-DENY closes it
            // to a games-realm admin under the merged front door.
            WebTestClient client = mergedGateway();
            String token = gamesRealm.mint("g-admin", List.of("admin"));
            get(client, token, "api.systems.tld", "/bff/forum/admin/boards")
                    .expectStatus().isForbidden();
            assertThat(downstreamHits()).isZero();
        }

        @Test
        void gamesRealmBareAdmin_onGamesAdminApi_gamesDomainHost_takesAdminBypass_200_FINDING() {
            // FINDING (cross-realm, surfaced by this suite — see PR body "FINDING G1").
            // On its OWN games-domain Host the games-realm `admin` carries ROLE_ADMIN and
            // DOMAIN_games (== targetDomain), so it takes the GatewayRouteAccessFilter
            // ADMIN own-domain bypass — chain.filter() returns BEFORE decide(), so the
            // /games/api/admin/** -> ROLE_GAMES_ADMIN COMPOSITE is NOT enforced at the
            // gateway against an in-domain admin. The composite distinction
            // (ROLE_GAMES_ADMIN = ROLE_GAMES ∩ (ROLE_ADMIN ∪ ROLE_MOD), materialized by
            // games-admin-sync) is therefore enforced ONLY by the games BFF's downstream
            // @PreAuthorize, NOT by this gateway row — identical to how the SUPERADMIN-vs-
            // ADMIN distinction on /bff/superadmin/** is deferred downstream (pinned in
            // GatewayDenyChainSliceTest). A plain ROLE_ADMIN bypassing the composite at
            // the gateway is the documented admin-own-domain contract, NOT a fail-open;
            // we PIN the actual 200 so a regression in either direction is caught loudly,
            // and prove the composite gate proper against a NON-bypassing principal below.
            WebTestClient client = mergedGateway();
            String token = gamesRealm.mint("g-admin", List.of("admin"));
            get(client, token, "api.games.tld", "/games/api/admin/catalog")
                    .expectStatus().isOk();
            assertThat(downstreamHits())
                    .as("an in-own-domain games-realm ADMIN takes the gateway admin bypass; "
                            + "the ROLE_GAMES_ADMIN composite is a DOWNSTREAM games-BFF concern")
                    .isEqualTo(1);
        }

        @Test
        void gamesRealmMod_onGamesAdminApi_gamesDomainHost_isDenied403_compositeNotSatisfied() {
            // The composite gate PROPER, against a NON-bypassing principal. A games-realm
            // MOD is not admin/superadmin, so it does NOT take the own-domain bypass — it
            // reaches the route-access decide(). The deciding longest-pattern rule is
            // /games/api/admin/** -> ROLE_GAMES_ADMIN, which a plain ROLE_MOD does NOT
            // hold -> governed-but-ungranted -> 403. This is the cell that proves the
            // games admin API is composite-gated at the gateway for every NON-admin
            // principal: a games-realm mod is NOT a games admin.
            WebTestClient client = mergedGateway();
            String token = gamesRealm.mint("g-mod", List.of("mod"));
            get(client, token, "api.games.tld", "/games/api/admin/catalog")
                    .expectStatus().isForbidden()
                    .expectHeader().exists("X-Route-Denied");
            assertThat(downstreamHits())
                    .as("a games-realm mod lacking the ROLE_GAMES_ADMIN composite is denied "
                            + "the games admin API at the gateway").isZero();
        }

        @Test
        void gamesRealmAdmin_onOwnGamesPortalFloor_isAllowed200() {
            // Non-vacuous control: the games-realm admin DOES reach the games PORTAL
            // floor on its own games-domain Host (the floor allows ROLE_ADMIN). Proves
            // the denials above are the domain boundary / missing composite, not a
            // blanket block of every games-realm token.
            WebTestClient client = mergedGateway();
            String token = gamesRealm.mint("g-admin", List.of("admin"));
            get(client, token, "api.games.tld", "/games/portal/home")
                    .expectStatus().isOk();
            assertThat(downstreamHits())
                    .as("a games-realm admin reaches its OWN games portal floor (ROLE_ADMIN "
                            + "superset row)").isEqualTo(1);
        }

        @Test
        void systemsAdmin_onGamesDomainHost_isHardDenied403_mirrorDirection() {
            // The mirror: a SYSTEMS-realm admin presented to the GAMES-domain Host under
            // the merged front door is HARD-DENIED (DOMAIN_systems != games). The
            // cross-realm domain boundary is symmetric for non-superadmins.
            WebTestClient client = mergedGateway();
            String token = systemsRealm.mint("s-admin", List.of("admin"));
            get(client, token, "api.games.tld", "/games/api/admin/catalog")
                    .expectStatus().isForbidden();
            assertThat(downstreamHits()).isZero();
        }

        @Test
        void systemsSuperadmin_onGamesDomainHost_takesCrossDomainBypass_PIN() {
            // BEHAVIOUR PIN of an ASYMMETRY worth surfacing: under a single MERGED front
            // door that trusts BOTH realms, a SYSTEMS superadmin's cross-DOMAIN bypass
            // (Roles.isSuperadmin -> chain.filter() before any domain/route check) ALSO
            // forwards onto a GAMES-domain Host — because the merged registry maps the
            // games host to a domain in the SAME trust fabric, the gateway treats it as a
            // cross-DOMAIN reach (which superadmin is licensed for), NOT a cross-REALM one.
            // In production the realms run as SEPARATE gateways/issuers (see scenario 2:
            // a systems superadmin is simply 401'd at the real games gateway), so this
            // asymmetry only manifests under the worst-case shared-issuer config. We pin
            // it explicitly so the boundary is documented and a future change is caught.
            // See the PR body FINDING note.
            WebTestClient client = mergedGateway();
            String token = systemsRealm.mint("s-root", List.of("admin", "superadmin"));
            get(client, token, "api.games.tld", "/games/api/admin/catalog")
                    .expectStatus().isOk();
            assertThat(downstreamHits())
                    .as("under a MERGED both-realms front door, systems SUPERADMIN's "
                            + "cross-domain bypass reaches the games-domain host (separate "
                            + "per-realm gateways 401 it instead — see scenario 2)")
                    .isEqualTo(1);
        }
    }

    // ────────────────────────────── downstream oracle ──────────────────────────────

    /**
     * The protected downstream surface across all three realms' route patterns.
     * Reached ONLY if the FULL chain forwards; every cross-realm DENY test asserts
     * {@link #hits} stays 0 (the request never took effect) — the mutation-resistant
     * oracle: a fail-OPEN cross-realm authz gap would forward here and FAIL the assert.
     */
    @RestController
    @RequestMapping
    static class DownstreamEchoController {
        final AtomicInteger hits = new AtomicInteger(0);

        @GetMapping({
                // systems realm
                "/api/reports/q3", "/api/admin/secrets", "/bff/superadmin/cluster",
                // forum surface
                "/bff/forum/threads/42", "/bff/forum/admin/boards",
                // games realm
                "/games/portal/home", "/games/api/admin/catalog"})
        Mono<String> getEcho() {
            hits.incrementAndGet();
            return ReactiveSecurityContextHolder.getContext()
                    .map(ctx -> "REACHED:" + ctx.getAuthentication().getName()
                            + ":" + authoritiesOf(ctx))
                    .defaultIfEmpty("REACHED:anonymous");
        }

        @PostMapping({"/api/admin/secrets", "/bff/forum/admin/boards", "/games/api/admin/catalog"})
        Mono<String> postEcho() {
            hits.incrementAndGet();
            return Mono.just("WROTE");
        }

        private static String authoritiesOf(org.springframework.security.core.context.SecurityContext ctx) {
            return ctx.getAuthentication().getAuthorities().stream()
                    .map(Object::toString)
                    .reduce((a, b) -> a + "," + b).orElse("");
        }
    }
}
