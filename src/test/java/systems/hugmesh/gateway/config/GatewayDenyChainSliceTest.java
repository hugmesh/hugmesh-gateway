package systems.hugmesh.gateway.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
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
 * THE KEYSTONE — raw-API-deny negative security suite at the hugmesh-gateway
 * front door, driving the REAL assembled gateway chain end to end with REAL RS256
 * tokens. Unlike the existing {@code RevocationGatewayFilterTest} /
 * {@code GatewayRouteAccessFilterTest} (which exercise ONE filter in isolation
 * against a {@code MockServerWebExchange} + a mock/seeded service and a
 * hand-built {@code JwtAuthenticationToken}), this test wires the PRODUCTION
 * {@link SecurityConfig#filterChain} (multi-issuer resource-server +
 * {@code authorizeExchange} floor) TOGETHER WITH the REAL
 * {@link RevocationGatewayFilter} and {@link GatewayRouteAccessFilter} — in their
 * production order — behind a {@link WebTestClient}, and replays REAL per-brand
 * RSA-signed JWTs minted by in-process {@link TestIssuer} JWKS servers (the gold
 * exemplar pattern from hugmesh-federation-api's
 * {@code MultiIssuerSecuritySliceTest} / {@code CrossDomainWriteIsolationTest}).
 *
 * <p><b>Mutation-resistant oracle (the "did the action take effect" half).</b>
 * The downstream {@link DownstreamEchoController} is reached ONLY if the whole
 * chain forwards. Every DENY assertion therefore pairs the rejected HTTP status
 * (401/403) with {@link #downstreamHits()} == 0 — proving the request never
 * touched the protected surface. A fail-OPEN (a real authz gap) would forward to
 * the echo controller, bumping the counter and FAILING the assertion loudly; the
 * test would NOT be silently green. This is the negative-test analogue of
 * re-reading the DB after a denied write.
 *
 * <p>The authority for every expected status is the production code path:
 * {@link SecurityConfig}'s {@code authorizeExchange} table + the multi-issuer
 * resolver (unknown {@code iss} -> 401), the {@link GatewayRouteAccessFilter}
 * decision chain (SUPERADMIN cross-domain bypass; non-superadmin domain mismatch
 * HARD-DENY; route-access {@link GatewayRouteAccessService#decide} = longest-
 * pattern-wins, OR-of-allow rows), and the {@link CanonicalSeed}-equivalent
 * route-access rows primed here as the oracle (a brand-Y {@code /api/admin/**} ->
 * ROLE_ADMIN grant + a brand-X {@code /api/admin/**} -> ROLE_ADMIN grant +
 * the {@code /api/**} -> ROLE_USER floor for the be-gateway).
 *
 * <p>Negative classes covered, delineated per the comprehensive test standard:
 * <ul>
 *   <li><b>REVOCATION</b> — a structurally-valid, correctly-signed, NON-expired
 *       RS256 token whose subject is on the revocation list is DENIED 403 at the
 *       revocation filter and never reaches downstream (CROSS-USER isolation: the
 *       same path forwards for a non-revoked subject).</li>
 *   <li><b>CROSS-TENANT</b> — a DOMAIN_brandA token presented to a brandB-scoped
 *       Host is 403'd by the GatewayRouteAccessFilter domain HARD-DENY, even
 *       though a domain-blind brandB {@code /api/admin/** -> ROLE_ADMIN} grant
 *       row exists (it must NOT re-grant the foreign-brand admin).</li>
 *   <li><b>CROSS-TIER / WRONG-ISSUER</b> — a token from an issuer NOT in
 *       {@code app.tenancy.issuers} (a foreign / games-realm Casdoor) is 401'd by
 *       the resource server BEFORE any gateway filter — issuer isolation, fail
 *       closed, never a default-accept.</li>
 *   <li><b>PRIVILEGE-ESCALATION</b> — ROLE_USER at an admin route -> 403;
 *       ROLE_MOD at a superadmin route -> 403; and SUPERADMIN is the ONLY
 *       cross-domain ALLOW (a brand-X superadmin reaches brand-Y's admin
 *       surface).</li>
 *   <li><b>FORGED-TOKEN</b> — a tampered-signature token is 401'd (the validation
 *       boundary), and a permissions-injected bare-role ({@code permissions:[
 *       "superadmin"]}) does NOT satisfy a ROLE_SUPERADMIN route rule.</li>
 * </ul>
 *
 * <p>TEST-ONLY: no production code changes; all keys/JWTs are generated in-process
 * (no secrets); no network beyond {@code 127.0.0.1} (the TestIssuer JWKS servers).
 */
class GatewayDenyChainSliceTest extends SecuritySliceSupport {

    private static final String GW = "hugmesh-be-gateway";

    private TestIssuer brandX;
    private TestIssuer brandY;
    private TestIssuer foreign;   // a trusted-by-NOBODY issuer (games realm / rogue)

    private DownstreamEchoController echo;

    @BeforeEach
    void setUp() {
        brandX = new TestIssuer();
        brandY = new TestIssuer();
        foreign = new TestIssuer();
        echo = new DownstreamEchoController();
    }

    @AfterEach
    void tearDown() {
        brandX.close();
        brandY.close();
        foreign.close();
    }

    // ─────────────────────────── wiring helpers ───────────────────────────

    /** Multi-brand registry: brandX + brandY trusted (so the resource server is in
     *  multi-issuer mode); the {@code foreign} issuer is deliberately NOT listed.
     *  Host map pins api.brandx.tld -> brandx, api.brandy.tld -> brandy so the
     *  GatewayRouteAccessFilter computes a non-default targetDomain from Host. */
    private DomainRegistry multiBrandRegistry() {
        String issuers = brandX.issuerUri() + "=brandx," + brandY.issuerUri() + "=brandy";
        String hosts = "api.brandx.tld=brandx,api.brandy.tld=brandy";
        DomainRegistry registry = new DomainRegistry(brandX.issuerUri(), issuers, hosts);
        assertThat(registry.isMultiIssuer())
                .as("two trusted issuers => multi-issuer mode (the resolver swap is taken)").isTrue();
        return registry;
    }

    /** The REAL per-issuer resolver bean, built exactly as TenancyResourceServerConfig
     *  contributes it — each brand decoder discovers from its own in-process issuer. */
    private ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>> resolver(
            DomainRegistry registry) {
        TenancyResourceServerConfig tenancy = new TenancyResourceServerConfig(registry, "", "");
        return SecuritySliceSupport.provider(tenancy.tenantAuthManagerResolver());
    }

    /** A REAL (de-stubbed) route-access service for the be-gateway, primed with the
     *  oracle rows: per-brand admin grants (brandx + brandy) + the ROLE_USER /api/**
     *  floor + a superadmin-only surface. domain==null on the floor (unscoped). */
    private GatewayRouteAccessService realRouteAccess() {
        GatewayRouteAccessService svc =
                new GatewayRouteAccessService(null, null, GW, true, false, null);
        svc.primeForTest(List.of(
                // /api/admin/** is the more-specific (longer) pattern -> it decides on
                // admin paths; the brand-scoped rows prove a brand-Y grant can't
                // re-grant a brand-X admin (and vice-versa). The /api/** ROLE_USER
                // floor decides on non-admin api paths.
                new Rule("brandx-admin", GW, "/api/admin/**", "ROLE_ADMIN", null, true, "brandx", false),
                new Rule("brandy-admin", GW, "/api/admin/**", "ROLE_ADMIN", null, true, "brandy", false),
                new Rule("api-floor",    GW, "/api/**",       "ROLE_USER",  null, true, null,     false),
                // A superadmin-only surface (mirrors the be() seed /bff/superadmin/**).
                new Rule("superadmin",   GW, "/bff/superadmin/**", "ROLE_SUPERADMIN", null, true, null, false)));
        return svc;
    }

    /** Revocation service with NO datastore wired (cql==null => isPrimed()==true
     *  unconditionally, so the cold-start 503 gate is inert) primed with the given
     *  revoked keys — the single-tenant/dev posture the allow/deny path reads as
     *  the steady state. */
    private RevocationListService revocationsWith(Set<String> revoked) {
        RevocationListService svc = new RevocationListService(null, true);
        svc.primeRevokedForTest(revoked);
        return svc;
    }

    /** Assemble the WebTestClient through the FULL production chain: SecurityConfig
     *  (multi-issuer) + RevocationGatewayFilter (order 10) + GatewayRouteAccessFilter
     *  (order 25), in that production order, in front of the echo controller. */
    private WebTestClient client(DomainRegistry registry, GatewayRouteAccessService routeAccess,
                                 RevocationListService revocations) {
        List<WebFilter> gatewayFilters = List.of(
                new RevocationGatewayFilter(revocations, true),
                new GatewayRouteAccessFilter(routeAccess, registry));
        return sliceClientWithGatewayFilters(registry, resolver(registry), gatewayFilters, echo);
    }

    private int downstreamHits() {
        return echo.hits.get();
    }

    private WebTestClient defaultClient() {
        DomainRegistry registry = multiBrandRegistry();
        return client(registry, realRouteAccess(), revocationsWith(Set.of()));
    }

    // ════════════════════════ (1) REVOCATION ════════════════════════
    // A structurally-valid, correctly-signed, NON-expired RS256 token whose subject
    // is on the revocation list MUST be DENIED at the gateway (the RevocationGatewayFilter
    // was historically noted as UNTESTED at the assembled-chain level).

    @Test
    void revocation_revokedSubject_validRs256Token_isDenied403_andNeverReachesDownstream() {
        DomainRegistry registry = multiBrandRegistry();
        // brandX subject "banned-1" is revoked (key subject:<sub>).
        WebTestClient client = client(registry, realRouteAccess(),
                revocationsWith(Set.of("subject:banned-1")));

        // The token is otherwise perfectly valid: real RS256, trusted issuer, fresh,
        // ROLE_USER on its own /api/** floor (a request that WOULD forward but for
        // the revocation).
        String token = brandX.mint("banned-1", List.of("user"));
        client.get().uri("/api/reports/q3")
                .header(org.springframework.http.HttpHeaders.HOST, "api.brandx.tld")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().exists("X-Revoked");

        assertThat(downstreamHits())
                .as("a revoked subject must be cut off at the gateway — the downstream "
                        + "surface is NEVER reached (mutation-resistant: a fail-open would forward)")
                .isZero();
    }

    @Test
    void revocation_crossUser_nonRevokedSubject_sameSurface_isAllowedThrough() {
        // CROSS-USER ISOLATION: revocation is scoped to the KEY, not the path. A
        // DIFFERENT, non-revoked brandX user on the SAME /api/** floor forwards —
        // proving the 403 above is the revocation, not a blanket block (non-vacuous).
        DomainRegistry registry = multiBrandRegistry();
        WebTestClient client = client(registry, realRouteAccess(),
                revocationsWith(Set.of("subject:banned-1")));

        String token = brandX.mint("good-user", List.of("user"));
        client.get().uri("/api/reports/q3")
                .header(org.springframework.http.HttpHeaders.HOST, "api.brandx.tld")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk();

        assertThat(downstreamHits())
                .as("a non-revoked subject on its own /api/** floor reaches downstream")
                .isEqualTo(1);
    }

    // ════════════════════════ (2) CROSS-TENANT ════════════════════════
    // A DOMAIN_brandX token hitting a brandY-scoped route -> 403 via the
    // GatewayRouteAccessFilter domain HARD-DENY, even though a domain-blind brandY
    // /api/admin/** -> ROLE_ADMIN grant row exists.

    @Test
    void crossTenant_brandXAdmin_onBrandYAdminSurface_isDenied403_andNeverReachesDownstream() {
        WebTestClient client = defaultClient();

        // A REAL brandX-issued admin token (validated iss => DOMAIN_brandx) presented
        // to brandY's Host. The brandY admin grant row must NOT re-grant it.
        String token = brandX.mint("admin-x", List.of("admin"));
        client.get().uri("/api/admin/secrets")
                .header(org.springframework.http.HttpHeaders.HOST, "api.brandy.tld")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().exists("X-Route-Denied");

        assertThat(downstreamHits())
                .as("a brand-X admin must NOT reach brand-Y's admin surface (cross-tenant)")
                .isZero();
    }

    @Test
    void crossTenant_brandXAdmin_onOwnBrandAdminSurface_isAllowed() {
        // USER-SITUATIONAL ALLOW: the SAME brandX admin reaching brandX's OWN admin
        // surface bypasses (its own domain matches) — proving the cross-tenant DENY
        // is the domain boundary, not over-blocking.
        WebTestClient client = defaultClient();

        String token = brandX.mint("admin-x", List.of("admin"));
        client.get().uri("/api/admin/secrets")
                .header(org.springframework.http.HttpHeaders.HOST, "api.brandx.tld")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk();

        assertThat(downstreamHits())
                .as("a brand-X admin reaches its OWN brand-X admin surface").isEqualTo(1);
    }

    // ════════════════════════ (3) CROSS-TIER / WRONG-ISSUER ════════════════════════
    // A foreign-issuer token (games realm / unlisted Casdoor) at a systems route ->
    // 401 at the resource server BEFORE any gateway filter. Issuer isolation.

    @Test
    void crossTier_foreignIssuerToken_isDenied401_byResourceServer_neverReachesGatewayFilters() {
        WebTestClient client = defaultClient();

        // A perfectly well-formed, correctly-signed RS256 token — its ONLY sin is an
        // issuer NOT in app.tenancy.issuers (a games-realm / foreign Casdoor). The
        // per-issuer resolver returns empty for it -> 401 fail-closed; there is no
        // default-accept manager. Even minted with admin+superadmin it cannot cross in.
        String token = foreign.mint("attacker", List.of("admin", "superadmin"));
        client.get().uri("/api/admin/secrets")
                .header(org.springframework.http.HttpHeaders.HOST, "api.brandx.tld")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();

        assertThat(downstreamHits())
                .as("an untrusted-issuer token is 401'd at the resource server, never "
                        + "reaching the gateway filters or downstream").isZero();
    }

    @Test
    void crossTier_garbageBearer_isDenied401() {
        // A non-JWT bearer also fails closed (no issuer to resolve).
        WebTestClient client = defaultClient();
        client.get().uri("/api/admin/secrets")
                .header(org.springframework.http.HttpHeaders.HOST, "api.brandx.tld")
                .header("Authorization", "Bearer not-a-jwt")
                .exchange()
                .expectStatus().isUnauthorized();
        assertThat(downstreamHits()).isZero();
    }

    @Test
    void crossTier_noBearer_onAuthenticatedRoute_isDenied401() {
        // The coarse authorizeExchange floor: an anonymous request to a non-public
        // route is 401'd by SecurityConfig before any gateway filter forwards it.
        WebTestClient client = defaultClient();
        client.get().uri("/api/admin/secrets")
                .header(org.springframework.http.HttpHeaders.HOST, "api.brandx.tld")
                .exchange()
                .expectStatus().isUnauthorized();
        assertThat(downstreamHits()).isZero();
    }

    // ════════════════════════ (4) PRIVILEGE-ESCALATION ════════════════════════

    @Test
    void escalation_roleUser_atAdminRoute_isDenied403_andNeverReachesDownstream() {
        // A plain ROLE_USER (in its OWN brand, so the domain matches and the request
        // reaches the route-access decide) at the /api/admin/** surface: the deciding
        // longest-pattern rule is /api/admin/** -> ROLE_ADMIN, which a ROLE_USER does
        // NOT hold -> governed-but-ungranted -> DENY 403.
        WebTestClient client = defaultClient();

        String token = brandX.mint("plain-user", List.of("user"));
        client.get().uri("/api/admin/secrets")
                .header(org.springframework.http.HttpHeaders.HOST, "api.brandx.tld")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().exists("X-Route-Denied");

        assertThat(downstreamHits())
                .as("a ROLE_USER must NOT reach an admin route").isZero();
    }

    @Test
    void escalation_roleMod_atSuperadminRoute_isDenied403_andNeverReachesDownstream() {
        // ROLE_MOD at the /bff/superadmin/** surface: the deciding rule requires
        // ROLE_SUPERADMIN; a mod is NOT a superadmin (and mod is NOT an admin/game-master
        // bypass either). Governed-but-ungranted -> DENY 403. Proves the cross-TIER
        // floor: a mod can never climb to the infra control plane.
        WebTestClient client = defaultClient();

        String token = brandX.mint("mod-x", List.of("mod"));
        client.get().uri("/bff/superadmin/cluster")
                .header(org.springframework.http.HttpHeaders.HOST, "api.brandx.tld")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().exists("X-Route-Denied");

        assertThat(downstreamHits())
                .as("a ROLE_MOD must NOT reach a superadmin route").isZero();
    }

    @Test
    void escalation_inDomainAdmin_atSuperadminRoute_takesDocumentedAdminBypass_PIN() {
        // BEHAVIOUR PIN (NOT a deny). A per-domain ADMIN reaching the SUPERADMIN-only
        // /bff/superadmin/** surface IN ITS OWN domain takes the GatewayRouteAccessFilter
        // ADMIN own-domain bypass, which returns chain.filter() BEFORE the route-access
        // decide() — so the SUPERADMIN-only route rule is NOT enforced against an
        // in-domain admin AT THE GATEWAY layer. This is the documented "admin works on
        // the internal token alone within its own domain" contract (see the filter's
        // Javadoc): the SUPERADMIN-only protection of this surface against a per-domain
        // admin is enforced DOWNSTREAM by the target BFF's @PreAuthorize, NOT by this
        // gateway. (The route-access SUPERADMIN rule still bites NON-bypassing
        // principals — proven by escalation_roleMod_/_roleUser_ above.)
        //
        // We pin the CURRENT assembled-chain decision (forward) explicitly so a future
        // regression in either direction is caught loudly. This is INTENTIONAL design,
        // not a fail-open: cross-DOMAIN reach by a non-superadmin is hard-denied
        // (crossTenant_* / escalation_nonSuperadminUser_crossDomain_*); only the
        // in-OWN-domain admin bypass forwards, deferring the admin-vs-superadmin
        // distinction on this surface to the downstream service.
        WebTestClient client = defaultClient();

        String token = brandX.mint("admin-x", List.of("admin"));
        client.get().uri("/bff/superadmin/cluster")
                .header(org.springframework.http.HttpHeaders.HOST, "api.brandx.tld")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk();

        assertThat(downstreamHits())
                .as("an in-OWN-domain admin takes the documented gateway admin bypass; "
                        + "the SUPERADMIN-vs-ADMIN distinction on this surface is a DOWNSTREAM "
                        + "@PreAuthorize concern, not a gateway route-access one")
                .isEqualTo(1);
    }

    @Test
    void escalation_superadmin_isTheOnlyCrossDomainAllow() {
        // SUPERADMIN cross-domain ALLOW (the ONE positive of the negative suite): a
        // brandX-issued SUPERADMIN reaches brandY's admin surface — the only principal
        // that crosses the domain boundary (infra control plane).
        WebTestClient client = defaultClient();

        String token = brandX.mint("root", List.of("superadmin"));
        client.get().uri("/api/admin/secrets")
                .header(org.springframework.http.HttpHeaders.HOST, "api.brandy.tld")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk();

        assertThat(downstreamHits())
                .as("SUPERADMIN is the only cross-domain ALLOW — it reaches brand-Y")
                .isEqualTo(1);
    }

    @Test
    void escalation_nonSuperadminUser_crossDomain_isDenied403() {
        // The mirror of the superadmin allow: a plain brandX user presented to
        // brandY's Host is HARD-DENIED on the domain mismatch (it is neither
        // superadmin nor an in-domain principal) -> 403, never downstream.
        WebTestClient client = defaultClient();

        String token = brandX.mint("user-x", List.of("user"));
        client.get().uri("/api/reports/q3")
                .header(org.springframework.http.HttpHeaders.HOST, "api.brandy.tld")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isForbidden();

        assertThat(downstreamHits())
                .as("a non-superadmin must NOT cross the domain boundary").isZero();
    }

    // ════════════════════════ (5) FORGED-TOKEN ════════════════════════

    @Test
    void forgedToken_tamperedSignature_isDenied401() {
        // A brandX token whose signature is corrupted fails brandX's manager
        // validation -> 401, never authenticated, never downstream.
        WebTestClient client = defaultClient();

        String token = brandX.mint("admin-x", List.of("admin"));
        String tampered = token.substring(0, token.length() - 4) + "AAAA";
        client.get().uri("/api/admin/secrets")
                .header(org.springframework.http.HttpHeaders.HOST, "api.brandx.tld")
                .header("Authorization", "Bearer " + tampered)
                .exchange()
                .expectStatus().isUnauthorized();

        assertThat(downstreamHits()).as("a tampered token never authenticates").isZero();
    }

    @Test
    void forgedToken_permissionInjectedBareRole_doesNotSatisfyRouteRole() {
        // AUTHORITY-INJECTION (CWE-863): a brandX token carrying NO superadmin ROLE,
        // but a forged permissions:["superadmin"] (which the converter passes through
        // VERBATIM, non-prefixed). The route-access appliesTo() requires a genuine
        // ROLE_-prefixed authority, so the bare "SUPERADMIN" permission must NOT
        // satisfy the /bff/superadmin/** ROLE_SUPERADMIN rule -> DENY 403.
        WebTestClient client = defaultClient();

        String token = brandX.mintWithClaims("sneaky", java.util.Map.of(
                "roles", List.of(java.util.Map.of("name", "user")),
                "permissions", List.of("superadmin", "admin"),
                "name", "sneaky"));
        client.get().uri("/bff/superadmin/cluster")
                .header(org.springframework.http.HttpHeaders.HOST, "api.brandx.tld")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().exists("X-Route-Denied");

        assertThat(downstreamHits())
                .as("a permissions-injected bare role must NOT satisfy a ROLE_ route rule")
                .isZero();
    }

    @Test
    void forgedToken_expiredRs256Token_isDenied401() {
        // An expired (but correctly-signed, trusted-issuer) token: the resource
        // server's exp validation rejects it -> 401, never downstream.
        WebTestClient client = defaultClient();

        String expired = brandX.mintExpired("admin-x", List.of("admin"));
        client.get().uri("/api/admin/secrets")
                .header(org.springframework.http.HttpHeaders.HOST, "api.brandx.tld")
                .header("Authorization", "Bearer " + expired)
                .exchange()
                .expectStatus().isUnauthorized();

        assertThat(downstreamHits()).as("an expired token never authenticates").isZero();
    }

    // ─────────────────────────── downstream oracle ───────────────────────────

    /**
     * The protected downstream surface. Reached ONLY if the FULL chain forwards;
     * every DENY test asserts {@link #hits} stays 0 (the request never took effect).
     * Mirrors the federation exemplar's DB re-read: here the "DB" is the hit counter.
     */
    @RestController
    @RequestMapping
    static class DownstreamEchoController {
        final AtomicInteger hits = new AtomicInteger(0);

        @GetMapping({"/api/reports/q3", "/api/admin/secrets", "/bff/superadmin/cluster"})
        Mono<String> getEcho() {
            hits.incrementAndGet();
            return ReactiveSecurityContextHolder.getContext()
                    .map(ctx -> "REACHED:" + ctx.getAuthentication().getName())
                    .defaultIfEmpty("REACHED:anonymous");
        }

        @PostMapping({"/api/admin/secrets", "/bff/superadmin/cluster"})
        Mono<String> postEcho() {
            hits.incrementAndGet();
            return Mono.just("WROTE");
        }
    }
}
