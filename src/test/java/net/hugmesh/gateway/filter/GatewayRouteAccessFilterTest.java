package net.hugmesh.gateway.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import net.hugmesh.gateway.cache.GatewayRouteAccessService;
import net.hugmesh.gateway.cache.GatewayRouteAccessService.Decision;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Per-gateway route-access filter contract:
 *
 * <ul>
 *   <li>Admin token alone → forwards, service never consulted (the admin who
 *       manages the rules is never locked out by them).</li>
 *   <li>Game-master alone → forwards.</li>
 *   <li>{@link Decision#DENY} → 403 + {@code X-Route-Denied}.</li>
 *   <li>{@link Decision#ALLOW} → forwards.</li>
 *   <li>{@link Decision#NO_RULE} (ungoverned path) → forwards.</li>
 *   <li>Anonymous request → forwards (SecurityConfig already decided).</li>
 * </ul>
 */
class GatewayRouteAccessFilterTest {

    private GatewayRouteAccessService routeAccess;
    private GatewayRouteAccessFilter filter;
    private WebFilterChain forwarded;
    private AtomicBoolean downstreamCalled;

    @BeforeEach
    void setup() {
        routeAccess = Mockito.mock(GatewayRouteAccessService.class);
        when(routeAccess.gatewayName()).thenReturn("hugmesh-be-gateway");
        // Single-issuer registry (no tenancy config) — domainForHost("...") => "default",
        // so the domain-scoped admin bypass behaves exactly like the old unconditional
        // one (default==default) in these single-tenant cases.
        filter = new GatewayRouteAccessFilter(routeAccess,
                new net.hugmesh.gateway.security.DomainRegistry(
                        "http://casdoor:8000", "", ""));
        downstreamCalled = new AtomicBoolean(false);
        forwarded = ex -> { downstreamCalled.set(true); return Mono.empty(); };
    }

    // The single-issuer registry under test is seeded with this issuer; a
    // production single-issuer token always carries it as `iss`, so the filter
    // (which now derives the principal domain from the VALIDATED issuer) resolves
    // it to DEFAULT_DOMAIN.
    private static final String SINGLE_ISSUER = "http://casdoor:8000";

    private static Jwt jwt(String sub, List<?> roles) {
        return jwt(sub, roles, SINGLE_ISSUER);
    }

    private static Jwt jwt(String sub, List<?> roles, String issuer) {
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

    private static AbstractAuthenticationToken authFor(Jwt jwt, String... roles) {
        var authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        for (String r : roles) authorities.add(new SimpleGrantedAuthority("ROLE_" + r));
        return new JwtAuthenticationToken(jwt, authorities);
    }

    /** Auth carrying a DOMAIN_&lt;x&gt; authority (the form the converter emits) so
     *  the filter's domain-scoped bypass can be exercised. */
    private static AbstractAuthenticationToken authForDomain(Jwt jwt, String domain, String... roles) {
        var authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        for (String r : roles) authorities.add(new SimpleGrantedAuthority("ROLE_" + r));
        authorities.add(new SimpleGrantedAuthority("DOMAIN_" + domain));
        return new JwtAuthenticationToken(jwt, authorities);
    }

    private MockServerWebExchange run(String path, AbstractAuthenticationToken auth) {
        return run(path, null, auth);
    }

    private MockServerWebExchange run(String path, String host, AbstractAuthenticationToken auth) {
        var builder = MockServerHttpRequest.get(path);
        if (host != null) builder.header(org.springframework.http.HttpHeaders.HOST, host);
        MockServerWebExchange mwex = MockServerWebExchange.from(builder.build());
        if (auth == null) {
            filter.filter(mwex, forwarded).block();
        } else {
            filter.filter(new ExchangeWithPrincipal(mwex, auth), forwarded).block();
        }
        return mwex;
    }

    @Test
    void adminBypasses_serviceNeverConsulted() {
        Jwt adminJwt = jwt("admin-1", List.of(Map.of("name", "admin")));
        run("/api/anything", authFor(adminJwt, "ADMIN"));
        assertThat(downstreamCalled).isTrue();
        Mockito.verify(routeAccess, Mockito.never()).decide(any(), any(), any(), any());
    }

    @Test
    void gameMasterBypasses() {
        Jwt gmJwt = jwt("gm-1", List.of(Map.of("name", "game-master")));
        run("/api/anything", authFor(gmJwt, "GAME-MASTER"));
        assertThat(downstreamCalled).isTrue();
        Mockito.verify(routeAccess, Mockito.never()).decide(any(), any(), any(), any());
    }

    @Test
    void deny_returns403WithHeader() {
        when(routeAccess.decide(any(), any(), any(), any())).thenReturn(Decision.DENY);
        Jwt userJwt = jwt("user-1", List.of(Map.of("name", "user")));
        MockServerWebExchange mwex = run("/api/reports/q3", authFor(userJwt));
        assertThat(downstreamCalled).isFalse();
        assertThat(mwex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(mwex.getResponse().getHeaders().getFirst("X-Route-Denied"))
            .isEqualTo("hugmesh-be-gateway:/api/reports/q3");
    }

    @Test
    void allow_forwards() {
        when(routeAccess.decide(any(), any(), any(), any())).thenReturn(Decision.ALLOW);
        Jwt userJwt = jwt("user-1", List.of(Map.of("name", "user")));
        run("/api/reports/q3", authFor(userJwt));
        assertThat(downstreamCalled).isTrue();
    }

    @Test
    void noRule_forwards() {
        when(routeAccess.decide(any(), any(), any(), any())).thenReturn(Decision.NO_RULE);
        Jwt userJwt = jwt("user-1", List.of(Map.of("name", "user")));
        run("/api/public/health", authFor(userJwt));
        assertThat(downstreamCalled).isTrue();
    }

    @Test
    void anonymous_forwards() {
        run("/api/login", null);
        assertThat(downstreamCalled).isTrue();
        Mockito.verify(routeAccess, Mockito.never()).decide(any(), any(), any(), any());
    }

    // ── Domain-scoped bypass — multi-brand gateway ────────────────────────────

    /** A be-gateway configured for two brands (brandx + brandy) with a host map,
     *  so the filter computes a non-default targetDomain from Host. */
    private GatewayRouteAccessFilter multiBrandFilter() {
        return new GatewayRouteAccessFilter(routeAccess, multiBrandRegistry());
    }

    // Per-brand Casdoor issuers the multi-brand registry trusts. A brand-X token
    // carries BRANDX_ISSUER as `iss`; the filter derives its tenant from this
    // validated issuer (never from a spoofable authority).
    private static final String BRANDX_ISSUER = "https://id.brandx.tld";
    private static final String BRANDY_ISSUER = "https://id.brandy.tld";

    private static net.hugmesh.gateway.security.DomainRegistry multiBrandRegistry() {
        return new net.hugmesh.gateway.security.DomainRegistry(
                "https://id.brandx.tld",
                "https://id.brandx.tld=brandx,https://id.brandy.tld=brandy",
                "api.brandx.tld=brandx,api.brandy.tld=brandy");
    }

    /** A REAL (not mocked) {@link GatewayRouteAccessService} for the be-gateway,
     *  primed with a brand-Y {@code /api/admin/** -> ROLE_ADMIN allow=true} row.
     *  Under the OLD domain-BLIND grant this row (matched on the role string alone)
     *  would RE-GRANT a brand-X admin denied the bypass; the cross-tenant tests use
     *  it to prove the brand-X admin is STILL denied 403 against the REAL service. */
    private static GatewayRouteAccessService realServiceWithBrandYAdminRow() {
        var svc = new GatewayRouteAccessService(null, null, "hugmesh-be-gateway", true, false, null);
        svc.primeForTest(List.of(new GatewayRouteAccessService.Rule(
                "brandy-admin", "hugmesh-be-gateway", "/api/admin/**",
                "ROLE_ADMIN", null, true, "brandy", false)));
        return svc;
    }

    /** A REAL service primed with an UNSCOPED (domain=null) admin allow row — the
     *  CanonicalSeed shape ({@code r(BE, "/api/admin/**", "ROLE_ADMIN")}). An
     *  unscoped row applies to ANY targetDomain (domainApplies() admits null), so
     *  under the OLD code a bff_ session principal that skipped the JWT-only
     *  cross-domain hard-deny would be RE-GRANTED by this row on any brand's Host.
     *  The non-JWT cross-domain tests use it to prove the bff_ session is now
     *  HARD-DENIED at the filter BEFORE decide() ever consults this row. */
    private static GatewayRouteAccessService realServiceWithUnscopedAdminRow() {
        var svc = new GatewayRouteAccessService(null, null, "hugmesh-be-gateway", true, false, null);
        svc.primeForTest(List.of(new GatewayRouteAccessService.Rule(
                "seed-admin", "hugmesh-be-gateway", "/api/admin/**",
                "ROLE_ADMIN", null, true, /*domain*/ null, false)));
        return svc;
    }

    /** A bff_ session principal as BffSessionAuthFilter builds it: a
     *  UsernamePasswordAuthenticationToken whose principal is a String id and
     *  whose authorities carry ROLE_USER + the named roles but NO DOMAIN_ marker
     *  (BffSessionAuthFilter.buildAuthorities never stamps one). This is the
     *  non-JWT principal type that previously skipped the cross-domain hard-deny. */
    private static AbstractAuthenticationToken bffSession(String id, String... roles) {
        var authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        for (String r : roles) authorities.add(new SimpleGrantedAuthority("ROLE_" + r));
        return new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                id, null, authorities);
    }

    /** A bff_ session that DOES carry a DOMAIN_<x> authority (the form a future
     *  BffSessionAuthFilter could stamp from an issuer/domain introspect field) —
     *  used to prove a properly-scoped non-JWT principal is NOT broken: it matches
     *  its own brand and is adjudicated by route-access like any other principal. */
    private static AbstractAuthenticationToken bffSessionWithDomain(String id, String domain, String... roles) {
        var authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        for (String r : roles) authorities.add(new SimpleGrantedAuthority("ROLE_" + r));
        authorities.add(new SimpleGrantedAuthority("DOMAIN_" + domain));
        return new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                id, null, authorities);
    }

    @Test
    void bffSession_populatesUserIds_soPerUserCasdoorPinApplies() {
        // Regression for the per-user-pin bypass: a native-login (bff_) String principal
        // must feed userIds into decide() so a casdoor_user route pin applies — previously
        // userIds was empty for a bff_ session (populated only for a Jwt principal), so a
        // pinned deny (targeted ban) was a silent no-op and the user reached the surface
        // simply by choosing native login over a JWT.
        @SuppressWarnings("unchecked")
        org.mockito.ArgumentCaptor<java.util.List<String>> cap =
                org.mockito.ArgumentCaptor.forClass(java.util.List.class);
        when(routeAccess.decide(any(), any(), cap.capture(), any())).thenReturn(Decision.NO_RULE);

        run("/api/social/feed", bffSession("casdoor:e2e-alice"));

        assertThat(cap.getValue())
                .as("bff_ userIds carry the account id AND the bare handle so a pin in either form matches")
                .contains("casdoor:e2e-alice", "e2e-alice");
    }

    @Test
    void bffSession_pinnedDeny_isEnforced() {
        // With userIds populated, a pinned allow=false row that matches the account id
        // now DENIES the bff_ session (deny-wins), closing the carrier-shopping bypass.
        when(routeAccess.decide(any(), any(),
                org.mockito.ArgumentMatchers.argThat(ids -> ids != null && ids.contains("casdoor:e2e-alice")),
                any())).thenReturn(Decision.DENY);
        MockServerWebExchange ex = run("/api/social/feed", bffSession("casdoor:e2e-alice"));
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    // ── A5 part-B: UUID-form pins vs the bff_ carrier (introspect casdoorSub) ─

    /** A bff_ session whose introspect response carried the changeset-292
     *  {@code casdoorSub} — exactly the token {@code BffSessionAuthFilter} builds:
     *  String-id principal + a {@link BffSessionAuthFilter.SessionDetails} on the
     *  details slot. */
    private static AbstractAuthenticationToken bffSessionWithSub(String id, String sub, String... roles) {
        var auth = (org.springframework.security.authentication.UsernamePasswordAuthenticationToken)
                bffSession(id, roles);
        auth.setDetails(new BffSessionAuthFilter.SessionDetails(sub));
        return auth;
    }

    @Test
    void bffSessionWithSub_userIds_carryTheUuidForms() {
        // A5 part-B regression: with the introspect-supplied sub on the token details,
        // the bff_ branch must present the SAME sub-derived identity forms the JWT
        // branch does (raw UUID + lowercased "casdoor:<sub>" + bare), so a UUID-form
        // casdoor_user pin matches this user on BOTH carriers.
        @SuppressWarnings("unchecked")
        org.mockito.ArgumentCaptor<java.util.List<String>> cap =
                org.mockito.ArgumentCaptor.forClass(java.util.List.class);
        when(routeAccess.decide(any(), any(), cap.capture(), any())).thenReturn(Decision.NO_RULE);

        run("/api/social/feed", bffSessionWithSub("casdoor:alice@example.test", "UUID-1234"));

        assertThat(cap.getValue())
                .as("bff_ userIds must carry the raw sub AND the lowercased account-id forms")
                .contains("casdoor:alice@example.test", "alice@example.test",
                        "UUID-1234", "casdoor:uuid-1234", "uuid-1234");
    }

    @Test
    void bffSessionWithoutSub_userIds_unchangedFromToday() {
        // Legacy-null path: an introspect response with NO casdoorSub (an admin-bff
        // predating the field, or an account row not yet re-stamped) leaves the token's
        // details null — userIds must be EXACTLY the pre-field pair, nothing added.
        @SuppressWarnings("unchecked")
        org.mockito.ArgumentCaptor<java.util.List<String>> cap =
                org.mockito.ArgumentCaptor.forClass(java.util.List.class);
        when(routeAccess.decide(any(), any(), cap.capture(), any())).thenReturn(Decision.NO_RULE);

        run("/api/social/feed", bffSession("casdoor:e2e-alice"));

        assertThat(cap.getValue())
                .as("no sub on the session ⇒ byte-identical legacy identity set")
                .containsExactly("casdoor:e2e-alice", "e2e-alice");
    }

    @Test
    void uuidFormPinnedDeny_nowDeniesBothCarriers_legacySessionUnchanged() {
        // THE A5 part-B asymmetry, against the REAL service: a targeted deny pinned in
        // UUID form ("uuid-1234", the raw Casdoor sub — e.g. copied from Casdoor's user
        // admin) previously denied ONLY the JWT carrier; the same human's bff_ session
        // sailed through (a DENY pin failing OPEN). With introspect carrying the sub,
        // the bff_ carrier is now denied too.
        filter = new GatewayRouteAccessFilter(
                realServiceWithPinnedDeny("uuid-1234"),
                new net.hugmesh.gateway.security.DomainRegistry(
                        "http://casdoor:8000", "", ""));

        // bff_ carrier whose introspect carried the stamped sub → DENIED.
        MockServerWebExchange viaBff = run("/api/social/feed",
                bffSessionWithSub("casdoor:alice@example.test", "uuid-1234"));
        assertThat(viaBff.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(downstreamCalled).as("sub-carrying bff_ session must not reach the surface").isFalse();

        // JWT carrier for the same human (raw sub in userIds) → DENIED, as before.
        MockServerWebExchange viaJwt = run("/api/social/feed",
                authFor(jwtWithEmail("uuid-1234", "e2e-alice", "alice@example.test")));
        assertThat(viaJwt.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(downstreamCalled).isFalse();

        // Legacy control — a bff_ session WITHOUT the sub (null details) still rides the
        // ROLE_USER allow row: exactly today's behavior, unchanged by this fix (and the
        // documented reason legacy rows must re-login natively before a UUID pin can
        // reach them).
        MockServerWebExchange legacy = run("/api/social/feed",
                bffSession("casdoor:alice@example.test"));
        assertThat(legacy.getResponse().getStatusCode()).isNull();
        assertThat(downstreamCalled).as("legacy (sub-less) session behaves exactly as today").isTrue();
    }

    @Test
    void uuidFormAllowPin_nowAdmitsTheBffCarrier() {
        // The ALLOW half of the asymmetry: a casdoor_user allow row pinned in UUID form
        // wrongly DENIED the same human's bff_ session (governed path, no matching id).
        // With the sub in userIds the native-login carrier is admitted like the JWT one.
        var svc = new GatewayRouteAccessService(null, null, "hugmesh-be-gateway", true, false, null);
        svc.primeForTest(List.of(new GatewayRouteAccessService.Rule(
                "uuid-allow", "hugmesh-be-gateway", "/api/social/**",
                "ROLE_USER", "uuid-1234", true, null, false)));
        filter = new GatewayRouteAccessFilter(svc,
                new net.hugmesh.gateway.security.DomainRegistry(
                        "http://casdoor:8000", "", ""));

        MockServerWebExchange withSub = run("/api/social/feed",
                bffSessionWithSub("casdoor:alice@example.test", "uuid-1234"));
        assertThat(downstreamCalled).as("UUID-pinned allow must admit the sub-carrying bff_ session").isTrue();
        assertThat(withSub.getResponse().getStatusCode()).isNull();

        // Legacy control — WITHOUT the sub the pin cannot match, so the governed path
        // stays denied (governed-but-ungranted): exactly today's behavior for a row not
        // yet re-stamped, and the wrongly-denied half of the pre-fix asymmetry.
        downstreamCalled.set(false);
        MockServerWebExchange legacy = run("/api/social/feed",
                bffSession("casdoor:alice@example.test"));
        assertThat(legacy.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(downstreamCalled).isFalse();
    }

    // ── JWT carrier ↔ account-id pin parity (mirror of the bff_ gap above) ────

    /** A Casdoor JWT with independent {@code sub} / {@code name} / {@code email}
     *  claims (the {@link #jwt} fixture reuses {@code sub} as {@code name}, which
     *  would mask which claim an identity form was derived from). */
    private static Jwt jwtWithEmail(String sub, String name, String email) {
        return Jwt.withTokenValue("test")
            .header("alg", "none")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(60))
            .subject(sub)
            .issuer(SINGLE_ISSUER)
            .claim("name", name)
            .claim("email", email)
            .build();
    }

    @Test
    void jwtSession_userIds_carryNativeAccountIdForms() {
        // Mirror regression of bffSession_populatesUserIds: a Casdoor-JWT principal
        // must ALSO present the durable-account identity forms admin-bff mints for
        // the same user ("casdoor:<handle>" + bare lowercase handle, handle drawn
        // from email/preferred_username/sub/username) — previously a pin written in
        // the account-id form matched ONLY the bff_ carrier, so a targeted deny
        // copied verbatim from the account row was dodgeable by switching to a JWT.
        @SuppressWarnings("unchecked")
        org.mockito.ArgumentCaptor<java.util.List<String>> cap =
                org.mockito.ArgumentCaptor.forClass(java.util.List.class);
        when(routeAccess.decide(any(), any(), cap.capture(), any())).thenReturn(Decision.NO_RULE);

        run("/api/social/feed",
                authFor(jwtWithEmail("uuid-1234", "E2E-Alice", "Alice@Example.test")));

        assertThat(cap.getValue())
                .as("JWT userIds carry the raw sub/name AND the lowercased account-id"
                        + " forms so a pin in any minted form matches")
                .contains("uuid-1234", "E2E-Alice",
                        "casdoor:alice@example.test", "alice@example.test",
                        "casdoor:e2e-alice", "e2e-alice",
                        "casdoor:uuid-1234");
    }

    /** A REAL service primed with an unpinned {@code ROLE_USER allow} row PLUS a
     *  pinned {@code allow=false} row at the SAME pattern, so a 403 can only come
     *  from the pin matching (deny-wins) — never from the governed-but-not-granted
     *  floor. */
    private static GatewayRouteAccessService realServiceWithPinnedDeny(String pin) {
        var svc = new GatewayRouteAccessService(null, null, "hugmesh-be-gateway", true, false, null);
        svc.primeForTest(List.of(
                new GatewayRouteAccessService.Rule(
                        "social-users", "hugmesh-be-gateway", "/api/social/**",
                        "ROLE_USER", null, true, null, false),
                new GatewayRouteAccessService.Rule(
                        "targeted-ban", "hugmesh-be-gateway", "/api/social/**",
                        "ROLE_USER", pin, false, null, false)));
        return svc;
    }

    @Test
    void jwtSession_accountIdFormPinnedDeny_isEnforced_viaEmailHandle() {
        // CARRIER-SHOPPING (JWT direction), against the REAL service: a targeted deny
        // pinned to the durable account id — "casdoor:" + lowercase(email), exactly
        // what admin-bff mints for an email-bearing Casdoor user — must DENY the same
        // user's JWT session too. Mixed-case email proves the mint-matching lowercase.
        filter = new GatewayRouteAccessFilter(
                realServiceWithPinnedDeny("casdoor:alice@example.test"),
                new net.hugmesh.gateway.security.DomainRegistry(
                        "http://casdoor:8000", "", ""));
        MockServerWebExchange ex = run("/api/social/feed",
                authFor(jwtWithEmail("uuid-1234", "E2E-Alice", "Alice@Example.test")));
        assertThat(downstreamCalled).as("pinned deny must not forward").isFalse();
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        // Positive control — an unpinned user still passes the allow row.
        MockServerWebExchange ok = run("/api/social/feed",
                authFor(jwtWithEmail("uuid-5678", "e2e-bob", "bob@example.test")));
        assertThat(downstreamCalled).as("unpinned user rides the ROLE_USER allow").isTrue();
        assertThat(ok.getResponse().getStatusCode()).isNull();
    }

    @Test
    void accountIdFormPinnedDeny_deniesBothCarriers() {
        // The SAME pin row ("casdoor:<username>", the bare-handle mint form) denies
        // the user on BOTH carriers — the full carrier-shopping regression pair.
        filter = new GatewayRouteAccessFilter(
                realServiceWithPinnedDeny("casdoor:e2e-alice"),
                new net.hugmesh.gateway.security.DomainRegistry(
                        "http://casdoor:8000", "", ""));
        MockServerWebExchange viaBff = run("/api/social/feed", bffSession("casdoor:e2e-alice"));
        assertThat(viaBff.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        MockServerWebExchange viaJwt = run("/api/social/feed",
                authFor(jwtWithEmail("uuid-1234", "e2e-alice", "alice@example.test")));
        assertThat(viaJwt.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(downstreamCalled).as("neither carrier may reach the surface").isFalse();
    }

    @Test
    void multiUserSituational_adminBypasses_onlyWithinItsOwnDomain() {
        // MULTIUSER-SITUATIONAL: brand-X admin reaching brand-X's host bypasses
        // (service never consulted), exactly as the legacy in-domain admin did.
        filter = multiBrandFilter();
        Jwt adminJwt = jwt("admin-x", List.of(Map.of("name", "admin")), BRANDX_ISSUER);
        run("/api/anything", "api.brandx.tld", authForDomain(adminJwt, "brandx", "ADMIN"));
        assertThat(downstreamCalled).isTrue();
        Mockito.verify(routeAccess, Mockito.never()).decide(any(), any(), any(), any());
    }

    @Test
    void crossUser_brandXAdmin_DENIED_onBrandYSurface() {
        // CROSS-USER (negative isolation), driven against the REAL service — NOT a
        // Mockito stub — so the actual grant logic is exercised. The real service is
        // primed with a brand-Y `/api/admin/** -> ROLE_ADMIN allow=true` row: under
        // the OLD domain-BLIND grant (role-string equality, no domain) this row
        // would RE-GRANT the brand-X admin denied the bypass and 200 it on brand-Y's
        // surface. With the fix (filter hard-deny on domain mismatch + per-row
        // domain scoping) the brand-X admin presenting brand-Y's Host is STILL
        // DENIED 403. This is the keystone cross-tenant DENY at the gateway layer.
        GatewayRouteAccessService real = realServiceWithBrandYAdminRow();
        filter = new GatewayRouteAccessFilter(real, multiBrandRegistry());
        Jwt adminJwt = jwt("admin-x", List.of(Map.of("name", "admin")), BRANDX_ISSUER);
        MockServerWebExchange mwex =
                run("/api/admin/secrets", "api.brandy.tld", authForDomain(adminJwt, "brandx", "ADMIN"));
        assertThat(downstreamCalled).as("cross-domain admin must NOT bypass").isFalse();
        assertThat(mwex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        // Belt-and-braces: the brand-Y admin row, queried directly on the REAL
        // service for the brand-X TARGET, also denies — so even if the filter's
        // hard-deny were ever bypassed, the per-row domain scope holds the line.
        assertThat(real.decide("/api/admin/secrets", "brandx", List.of("admin-x"),
                List.of("ROLE_USER", "ROLE_ADMIN", "DOMAIN_brandx")))
            .as("brand-Y-scoped admin row must NOT grant on the brand-X target")
            .isEqualTo(Decision.DENY);
    }

    @Test
    void authorityInjection_forgedDomainAuthority_stillDeniedCrossDomain() {
        // AUTHORITY-INJECTION ESCALATION REGRESSION at the FILTER (fix #2, proven
        // independently of the converter's reserved-prefix guard). Even if a forged
        // DOMAIN_brandy authority somehow reached the authorities list (here injected
        // directly), the filter derives the principal domain from the VALIDATED JWT
        // ISSUER (brandx) — NOT from the spoofable authorities — so a brand-X admin
        // presenting brand-Y's Host is HARD-DENIED on the domain mismatch BEFORE the
        // admin short-circuit. This is the exact escalation that previously forwarded
        // (forwarded=true, no 403); it now 403s.
        GatewayRouteAccessService real = realServiceWithBrandYAdminRow();
        filter = new GatewayRouteAccessFilter(real, multiBrandRegistry());
        // Token's VALIDATED issuer is brand-X; authorities carry a FORGED DOMAIN_brandy
        // (and a forged ROLE_SUPERADMIN) as if injection had slipped past the converter.
        Jwt adminJwt = jwt("admin-x", List.of(Map.of("name", "admin")), BRANDX_ISSUER);
        var forged = new ArrayList<GrantedAuthority>();
        forged.add(new SimpleGrantedAuthority("ROLE_USER"));
        forged.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        forged.add(new SimpleGrantedAuthority("ROLE_SUPERADMIN"));   // forged super-role authority
        forged.add(new SimpleGrantedAuthority("DOMAIN_brandy"));     // forged tenant scope
        forged.add(new SimpleGrantedAuthority("DOMAIN_brandx"));     // genuine issuer-derived
        var auth = new JwtAuthenticationToken(adminJwt, forged);

        MockServerWebExchange mwex = run("/api/admin/secrets", "api.brandy.tld", auth);
        assertThat(downstreamCalled)
                .as("forged DOMAIN_/ROLE_ authority must NOT escalate cross-domain").isFalse();
        assertThat(mwex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        // The forged ROLE_SUPERADMIN authority does NOT grant the superadmin bypass:
        // Roles.isSuperadmin reads the JWT roles claim (here only "admin"), not the
        // authorities list — so the request never short-circuits as superadmin.
    }

    @Test
    void issuerWins_forgedSecondDomainAuthority_doesNotBreakInDomainAdminBypass() {
        // SCENARIO 3 (issuer-wins, POSITIVE direction): the principal domain is
        // derived from the VALIDATED issuer, NOT the authorities list. A brand-X
        // admin reaching brand-X's OWN host bypasses normally; here the same admin
        // ALSO carries a FORGED extra DOMAIN_brandy authority (as if injection had
        // slipped past the converter) alongside the genuine DOMAIN_brandx. Because
        // the filter keys off the issuer (brandx) and ignores the authorities for
        // the domain decision, the forged authority neither escalates cross-domain
        // (see authorityInjection_* for the negative case) NOR breaks the admin's
        // legitimate in-domain bypass — they STILL forward on brand-X's surface.
        // This proves the spoofed DOMAIN_ authority does not change the matched
        // domain in EITHER direction: the validated issuer is the sole authority.
        filter = multiBrandFilter();
        Jwt adminJwt = jwt("admin-x", List.of(Map.of("name", "admin")), BRANDX_ISSUER);
        var authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        authorities.add(new SimpleGrantedAuthority("DOMAIN_brandx"));   // genuine issuer-derived
        authorities.add(new SimpleGrantedAuthority("DOMAIN_brandy"));   // forged extra tenant scope
        var auth = new JwtAuthenticationToken(adminJwt, authorities);
        run("/api/anything", "api.brandx.tld", auth);
        assertThat(downstreamCalled)
                .as("issuer (brandx) decides the domain; the forged DOMAIN_brandy does not break in-domain bypass")
                .isTrue();
        Mockito.verify(routeAccess, Mockito.never()).decide(any(), any(), any(), any());
    }

    @Test
    void unresolvedIssuer_failClosed_adminTokenIsHardDeniedNotForwarded() {
        // SCENARIO 5 (fail-CLOSED on an ambiguous/unresolved domain) at the FILTER.
        // In multi-brand mode an UNTRUSTED issuer resolves to a null principal
        // domain (Roles.domainOf -> DomainRegistry.domainOf -> null). The filter's
        // domainMatches(null, …) must treat that as a NON-match and HARD-DENY (403),
        // NEVER fall open to "matches everything" and forward. We exercise it with
        // an ADMIN token (the strongest case): even an admin whose tenant cannot be
        // proven is denied BEFORE the admin short-circuit — the domain check is
        // applied SIMULTANEOUSLY with the role check, so an unresolved domain closes
        // the gate regardless of role. (The resource server's iss-validation would
        // normally 401 this upstream; the filter fails closed defensively in case it
        // ever reaches here.)
        filter = multiBrandFilter();
        Jwt adminJwt = jwt("admin-?", List.of(Map.of("name", "admin")), "https://evil.attacker.tld");
        MockServerWebExchange mwex =
                run("/api/admin/secrets", "api.brandx.tld", authForDomain(adminJwt, "brandx", "ADMIN"));
        assertThat(downstreamCalled)
                .as("an admin whose issuer is unresolved must NOT forward (fail-closed)").isFalse();
        assertThat(mwex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        // The route-access GRANT layer is never even consulted — the hard-deny on
        // the unresolved domain short-circuits before decide().
        Mockito.verify(routeAccess, Mockito.never()).decide(any(), any(), any(), any());
    }

    @Test
    void crossUser_superadmin_ALLOWED_acrossAnyDomain() {
        // CROSS-USER (positive): SUPERADMIN is the ONLY cross-domain bypass — it
        // reaches brand-Y's surface even though its own token is brand-X, WITHOUT
        // consulting route-access (infra control plane).
        filter = multiBrandFilter();
        Jwt saJwt = jwt("sa-1", List.of(Map.of("name", "superadmin")), BRANDX_ISSUER);
        run("/api/admin/secrets", "api.brandy.tld", authForDomain(saJwt, "brandx", "SUPERADMIN"));
        assertThat(downstreamCalled).as("superadmin bypasses cross-domain").isTrue();
        Mockito.verify(routeAccess, Mockito.never()).decide(any(), any(), any(), any());
    }

    @Test
    void crossUser_plainUser_neverBypasses_evenInOwnDomain() {
        // A plain ROLE_USER never bypasses; it is always adjudicated by
        // route-access (here DENY).
        filter = multiBrandFilter();
        when(routeAccess.decide(any(), any(), any(), any())).thenReturn(Decision.DENY);
        Jwt userJwt = jwt("u-x", List.of(Map.of("name", "user")), BRANDX_ISSUER);
        MockServerWebExchange mwex =
                run("/api/admin/x", "api.brandx.tld", authForDomain(userJwt, "brandx"));
        assertThat(downstreamCalled).isFalse();
        assertThat(mwex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void backCompat_singleIssuerAdmin_noDomainAuthority_stillBypasses() {
        // A legacy token with NO DOMAIN_ authority on the default single-issuer
        // filter: principalDomain="default", targetDomain="default" -> bypass,
        // exactly as before the change.
        Jwt adminJwt = jwt("admin-1", List.of(Map.of("name", "admin")));
        run("/api/anything", "anything.tld", authFor(adminJwt, "ADMIN")); // no DOMAIN_ authority
        assertThat(downstreamCalled).isTrue();
        Mockito.verify(routeAccess, Mockito.never()).decide(any(), any(), any(), any());
    }

    @Test
    void concurrent_crossDomainAdminAlwaysDenied_inDomainAlwaysBypasses() throws Exception {
        // CONCURRENT: hammer the filter — backed by the REAL service primed with a
        // brand-Y `/api/admin/** -> ROLE_ADMIN allow=true` row — with interleaved
        // in-domain (bypass) and cross-domain (deny) admin requests. The brand-Y row
        // would, under the OLD domain-blind grant, re-grant the cross-domain brand-X
        // admin; here the domain scoping must hold under contention (no in-domain
        // leak, no cross-domain bypass) against the real grant logic.
        GatewayRouteAccessService real = realServiceWithBrandYAdminRow();
        GatewayRouteAccessFilter f = new GatewayRouteAccessFilter(real, multiBrandRegistry());

        var pool = java.util.concurrent.Executors.newFixedThreadPool(8);
        var wrongOutcome = new java.util.concurrent.atomic.AtomicBoolean(false);
        try {
            var futures = new java.util.concurrent.Future<?>[160];
            for (int i = 0; i < futures.length; i++) {
                final boolean inDomain = (i % 2 == 0);
                futures[i] = pool.submit(() -> {
                    var called = new java.util.concurrent.atomic.AtomicBoolean(false);
                    WebFilterChain chain = ex -> { called.set(true); return Mono.empty(); };
                    Jwt adminJwt = jwt("admin-x", List.of(Map.of("name", "admin")), BRANDX_ISSUER);
                    var auth = authForDomain(adminJwt, "brandx", "ADMIN");
                    String host = inDomain ? "api.brandx.tld" : "api.brandy.tld";
                    var req = MockServerHttpRequest.get("/api/admin/x")
                            .header(org.springframework.http.HttpHeaders.HOST, host).build();
                    MockServerWebExchange mwex = MockServerWebExchange.from(req);
                    f.filter(new ExchangeWithPrincipal(mwex, auth), chain).block();
                    if (inDomain) {
                        // in-domain admin must bypass (downstream called, no 403)
                        if (!called.get()) wrongOutcome.set(true);
                    } else {
                        // cross-domain admin must be denied (no bypass, 403)
                        if (called.get()) wrongOutcome.set(true);
                        if (mwex.getResponse().getStatusCode() != HttpStatus.FORBIDDEN) wrongOutcome.set(true);
                    }
                });
            }
            for (var ft : futures) ft.get(30, java.util.concurrent.TimeUnit.SECONDS);
        } finally {
            pool.shutdownNow();
        }
        assertThat(wrongOutcome.get())
                .as("domain scoping held under concurrency (no leak, no cross-domain bypass)")
                .isFalse();
    }

    // ── Non-JWT (bff_ session) cross-domain isolation (finding #3) ────────────
    // The cross-domain HARD-DENY was hoisted OUT of the `instanceof Jwt` block so a
    // bff_ session principal (UsernamePasswordAuthenticationToken, NO DOMAIN_ marker)
    // can no longer skip it and ride an unscoped admin seed row onto another brand.

    @Test
    void crossUser_bffSessionAdmin_DENIED_onForeignBrandSurface() {
        // KEYSTONE (finding #3, exploit closed): a legitimate brand-X bff_ session
        // holding ROLE_ADMIN presents its cookie/bearer to brand-Y's gateway Host.
        // Driven against the REAL service primed with the UNSCOPED (domain=null)
        // admin seed row — under the OLD JWT-only hard-deny this non-JWT principal
        // skipped the cross-domain check and decide() RE-GRANTED it via the unscoped
        // row (domainApplies(null,…)=true), forwarding a brand-X admin onto brand-Y's
        // admin surface. With the fix the multi-issuer non-JWT cross-domain check
        // fires: the bff_ session carries NO provable domain (Roles.domainOf(
        // authorities)=null), domainMatches(null,"brandy")=false -> HARD-DENY 403
        // BEFORE decide() is ever consulted.
        GatewayRouteAccessService real = realServiceWithUnscopedAdminRow();
        filter = new GatewayRouteAccessFilter(real, multiBrandRegistry());
        MockServerWebExchange mwex =
                run("/api/admin/secrets", "api.brandy.tld", bffSession("brandx-admin-1", "ADMIN"));
        assertThat(downstreamCalled)
                .as("a bff_ session with no provable domain must NOT reach a foreign brand").isFalse();
        assertThat(mwex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        // Belt-and-braces: the unscoped admin row, queried directly, WOULD have
        // granted this principal (proving the filter hard-deny is what closes it).
        assertThat(real.decide("/api/admin/secrets", "brandy", List.of("brandx-admin-1"),
                List.of("ROLE_USER", "ROLE_ADMIN")))
                .as("the unscoped seed row alone re-grants — only the filter hard-deny closes the gap")
                .isEqualTo(Decision.ALLOW);
    }

    @Test
    void crossUser_bffSessionAdmin_withMismatchedDomainAuthority_DENIED() {
        // A bff_ session that DID carry a DOMAIN_brandx authority (future stamped
        // form) presented to brand-Y's Host is HARD-DENIED on the mismatch, exactly
        // like the JWT path — the hoisted check uses domainMatches() identically.
        GatewayRouteAccessService real = realServiceWithUnscopedAdminRow();
        filter = new GatewayRouteAccessFilter(real, multiBrandRegistry());
        MockServerWebExchange mwex =
                run("/api/admin/secrets", "api.brandy.tld",
                        bffSessionWithDomain("brandx-admin-1", "brandx", "ADMIN"));
        assertThat(downstreamCalled).isFalse();
        assertThat(mwex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void bffSessionAdmin_withMatchingDomainAuthority_ownDomainBypass() {
        // A properly-scoped non-JWT ADMIN (DOMAIN_brandx) reaching its OWN brand's Host
        // now takes the ADMIN own-domain BYPASS — mirroring the JWT path (domainMatches
        // passes, so the cross-domain hard-deny does not fire, then the admin bypass
        // forwards). decide() is NOT consulted for a bypassing admin.
        filter = multiBrandFilter();
        run("/api/admin/x", "api.brandx.tld", bffSessionWithDomain("brandx-admin-1", "brandx", "ADMIN"));
        assertThat(downstreamCalled).as("in-domain bff_ admin bypasses like a JWT admin").isTrue();
        Mockito.verify(routeAccess, Mockito.never()).decide(any(), any(), any(), any());
    }

    @Test
    void backCompat_singleIssuer_bffSession_admin_ownDomainBypass() {
        // On a single-issuer cluster a bff_ ADMIN carries NO DOMAIN_ authority;
        // isMultiIssuer()=false so the cross-domain check is skipped, then the ADMIN
        // bypass forwards (mirroring the JWT path). decide() not consulted.
        run("/api/admin/x", "anything.tld", bffSession("admin-1", "ADMIN"));
        assertThat(downstreamCalled).as("single-issuer bff_ admin bypasses").isTrue();
        Mockito.verify(routeAccess, Mockito.never()).decide(any(), any(), any(), any());
    }

    @Test
    void backCompat_singleIssuer_bffSession_deny_stillDenied() {
        // Single-issuer bff_ session with a DENY decision still 403s through the
        // normal route-access path (the new check did not perturb the deny branch).
        when(routeAccess.decide(any(), any(), any(), any())).thenReturn(Decision.DENY);
        MockServerWebExchange mwex = run("/api/reports/q3", bffSession("user-1"));
        assertThat(downstreamCalled).isFalse();
        assertThat(mwex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    // ── bff_ session PRIVILEGED BYPASS parity with the JWT path (the fix) ──────

    @Test
    void bffSessionSuperadmin_bypasses_serviceNeverConsulted() {
        // THE FIX: a native-login SUPERADMIN (bff_ session, ROLE_SUPERADMIN authority,
        // no ROLE_ADMIN) now takes the SUPERADMIN bypass like a JWT superadmin — reaching
        // an admin-pathed surface WITHOUT a ROLE_SUPERADMIN route_access row. Before, it
        // fell through to decide() and was DENIED every /bff/admin/** route (e.g. its own
        // go-live console, gated hasRole('SUPERADMIN') but pathed under /bff/admin/).
        run("/bff/admin/go-live/providers", bffSession("sa-1", "SUPERADMIN"));
        assertThat(downstreamCalled).isTrue();
        Mockito.verify(routeAccess, Mockito.never()).decide(any(), any(), any(), any());
    }

    @Test
    void bffSessionSuperadmin_crossDomainBypass_reachesAnyBrand() {
        // SUPERADMIN is THE cross-domain bypass (the infra control plane) — it fires
        // BEFORE the cross-domain hard-deny, so a bff_ superadmin reaches another brand's
        // Host, exactly like a JWT superadmin. (The authority is trustworthy: set by the
        // gateway from admin-bff's introspect, never user-forgeable.)
        filter = multiBrandFilter();
        run("/api/admin/secrets", "api.brandy.tld", bffSession("sa-1", "SUPERADMIN"));
        assertThat(downstreamCalled).as("bff_ superadmin reaches every brand").isTrue();
        Mockito.verify(routeAccess, Mockito.never()).decide(any(), any(), any(), any());
    }

    @Test
    void bffSessionNonPrivileged_stillAdjudicatedByDecide() {
        // A non-privileged bff_ session (plain user) gets NO bypass and is still
        // adjudicated by decide() — the bypass is scoped strictly to the privileged roles.
        when(routeAccess.decide(any(), any(), any(), any())).thenReturn(Decision.DENY);
        MockServerWebExchange mwex = run("/bff/admin/usage", bffSession("u-1"));
        assertThat(downstreamCalled).isFalse();
        assertThat(mwex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void bffSessionMod_notAdmin_stillAdjudicatedByDecide() {
        // MOD is NOT ADMIN (siblings, no down-cascade): a bff_ MOD gets no admin bypass
        // and is adjudicated by decide() on an admin surface (here DENY).
        when(routeAccess.decide(any(), any(), any(), any())).thenReturn(Decision.DENY);
        MockServerWebExchange mwex = run("/bff/admin/usage", bffSession("m-1", "MOD"));
        assertThat(downstreamCalled).isFalse();
        assertThat(mwex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    // ── bff_ session PRIVILEGED MFA FLOOR parity (app.mfa.enforce-privileged-floor) ──

    @Test
    void bffSessionSuperadmin_onMfaRequiredSurface_withoutMfa_deniedByFloor() {
        // With the privileged floor ON, a bff_ SUPERADMIN reaching an mfa_required surface
        // WITHOUT the MFA_SATISFIED authority is DENIED before the bypass — mirroring the JWT
        // floor (SUPERADMIN is NOT exempt).
        GatewayRouteAccessService svc = realServiceWithMfaRequiredAdminRow();
        filter = floorFilter(svc);
        MockServerWebExchange mwex = run("/api/admin/secrets", bffSession("sa-1", "SUPERADMIN"));
        assertThat(downstreamCalled).isFalse();
        assertThat(mwex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void bffSessionSuperadmin_onMfaRequiredSurface_withMfaSatisfied_bypasses() {
        // Same surface, but the bff_ session carries the MFA_SATISFIED authority (admin-bff
        // stamped it) — the floor passes and the superadmin bypass forwards.
        GatewayRouteAccessService svc = realServiceWithMfaRequiredAdminRow();
        filter = floorFilter(svc);
        var authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        authorities.add(new SimpleGrantedAuthority("ROLE_SUPERADMIN"));
        authorities.add(new SimpleGrantedAuthority("MFA_SATISFIED"));
        var auth = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                "sa-1", null, authorities);
        run("/api/admin/secrets", auth);
        assertThat(downstreamCalled).as("MFA-fresh bff_ superadmin bypasses").isTrue();
    }

    // ── D8 PRIVILEGED MFA FLOOR (app.mfa.enforce-privileged-floor) ────────────
    // A HARD MFA check ABOVE the SUPERADMIN / ADMIN / GAME-MASTER bypasses. On an
    // mfa_required surface a privileged principal lacking a FRESH second factor is
    // DENIED (SUPERADMIN included). Cold-start (route-access unprimed) -> 503.
    // All flags default-off -> byte-identical legacy chain.

    /** Filter with the privileged floor ENABLED (10m window), wired to a REAL
     *  service primed with an mfa_required /api/admin/** row for the be-gateway. */
    private static GatewayRouteAccessFilter floorFilter(GatewayRouteAccessService svc) {
        return new GatewayRouteAccessFilter(svc,
                new net.hugmesh.gateway.security.DomainRegistry("http://casdoor:8000", "", ""),
                true,            // app.mfa.enforce-privileged-floor = ON
                600_000L);       // 10m window
    }

    private static GatewayRouteAccessService realServiceWithMfaRequiredAdminRow() {
        var svc = new GatewayRouteAccessService(null, null, "hugmesh-be-gateway", true, true, null);
        svc.primeForTest(List.of(new GatewayRouteAccessService.Rule(
                "mfa-admin", "hugmesh-be-gateway", "/api/admin/**",
                "ROLE_ADMIN", null, true, null, /*mfaRequired*/ true)));
        return svc;
    }

    /** JWT carrying the named roles AND a fresh/absent mfa_satisfied_at stamp. */
    private static Jwt jwtWithMfa(String sub, List<?> roles, Long satisfiedAtMillis) {
        var b = Jwt.withTokenValue("test").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60))
                .subject(sub).issuer(SINGLE_ISSUER).claim("roles", roles).claim("name", sub);
        if (satisfiedAtMillis != null) b.claim("mfa_satisfied_at", Long.toString(satisfiedAtMillis));
        return b.build();
    }

    @Test
    void privilegedFloor_adminLackingMfa_DENIED_aboveBypass() {
        // An ADMIN that would normally BYPASS is HARD-DENIED on an mfa_required
        // surface when it lacks a fresh second factor — proving the floor sits
        // ABOVE the admin own-domain bypass.
        var svc = realServiceWithMfaRequiredAdminRow();
        GatewayRouteAccessFilter f = floorFilter(svc);
        Jwt adminJwt = jwtWithMfa("admin-1", List.of(Map.of("name", "admin")), null);  // no MFA stamp
        var auth = new JwtAuthenticationToken(adminJwt, List.of(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
        var req = MockServerHttpRequest.get("/api/admin/secrets").build();
        MockServerWebExchange mwex = MockServerWebExchange.from(req);
        f.filter(new ExchangeWithPrincipal(mwex, auth), forwarded).block();
        assertThat(downstreamCalled).as("admin without MFA must NOT bypass an mfa_required surface").isFalse();
        assertThat(mwex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void privilegedFloor_superadminLackingMfa_DENIED_notExempt() {
        // SUPERADMIN is NOT exempt: even the cross-domain super-role is HARD-DENIED
        // on an mfa_required surface without a fresh second factor.
        var svc = realServiceWithMfaRequiredAdminRow();
        GatewayRouteAccessFilter f = floorFilter(svc);
        Jwt saJwt = jwtWithMfa("sa-1", List.of(Map.of("name", "superadmin")), null);
        var auth = new JwtAuthenticationToken(saJwt, List.of(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
        var req = MockServerHttpRequest.get("/api/admin/secrets").build();
        MockServerWebExchange mwex = MockServerWebExchange.from(req);
        f.filter(new ExchangeWithPrincipal(mwex, auth), forwarded).block();
        assertThat(downstreamCalled).as("SUPERADMIN is not exempt from the MFA floor").isFalse();
        assertThat(mwex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void privilegedFloor_adminWithFreshMfa_bypassesAsBefore() {
        // With a FRESH mfa_satisfied_at stamp the admin clears the floor and the
        // normal admin bypass resumes (downstream forwarded).
        var svc = realServiceWithMfaRequiredAdminRow();
        GatewayRouteAccessFilter f = floorFilter(svc);
        Jwt adminJwt = jwtWithMfa("admin-1", List.of(Map.of("name", "admin")),
                System.currentTimeMillis() - 1_000L);   // 1s ago — fresh
        var auth = new JwtAuthenticationToken(adminJwt, List.of(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
        var req = MockServerHttpRequest.get("/api/admin/secrets").build();
        MockServerWebExchange mwex = MockServerWebExchange.from(req);
        f.filter(new ExchangeWithPrincipal(mwex, auth), forwarded).block();
        assertThat(downstreamCalled).as("admin WITH a fresh MFA stamp bypasses normally").isTrue();
    }

    @Test
    void privilegedFloor_nonMfaSurface_adminBypassesUnaffected() {
        // The floor only bites on mfa_required surfaces. On a NON-mfa surface the
        // admin (even with the floor enabled, no stamp) bypasses as before.
        var svc = realServiceWithMfaRequiredAdminRow();
        GatewayRouteAccessFilter f = floorFilter(svc);
        Jwt adminJwt = jwtWithMfa("admin-1", List.of(Map.of("name", "admin")), null);
        var auth = new JwtAuthenticationToken(adminJwt, List.of(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
        var req = MockServerHttpRequest.get("/api/not-admin/thing").build();   // no mfa_required row
        MockServerWebExchange mwex = MockServerWebExchange.from(req);
        f.filter(new ExchangeWithPrincipal(mwex, auth), forwarded).block();
        assertThat(downstreamCalled).as("non-mfa surface: admin bypass unaffected").isTrue();
    }

    @Test
    void privilegedFloor_coldStart_unprimed_holds503() {
        // Before route-access is primed the gateway can't know whether the path is
        // an mfa_required surface -> fail-CLOSED 503 (mirrors RevocationGatewayFilter).
        var svc = realServiceWithMfaRequiredAdminRow();
        svc.simulateDatastoreWiredButUnprimedForTest(true);   // wired, never refreshed
        GatewayRouteAccessFilter f = floorFilter(svc);
        Jwt adminJwt = jwtWithMfa("admin-1", List.of(Map.of("name", "admin")),
                System.currentTimeMillis());   // even WITH a stamp, the surface is unknown -> 503
        var auth = new JwtAuthenticationToken(adminJwt, List.of(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
        var req = MockServerHttpRequest.get("/api/admin/secrets").build();
        MockServerWebExchange mwex = MockServerWebExchange.from(req);
        f.filter(new ExchangeWithPrincipal(mwex, auth), forwarded).block();
        assertThat(downstreamCalled).as("unprimed cold-start must not forward").isFalse();
        assertThat(mwex.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(mwex.getResponse().getHeaders().getFirst(org.springframework.http.HttpHeaders.RETRY_AFTER))
                .isEqualTo("5");
    }

    @Test
    void privilegedFloor_flagOff_byteIdenticalLegacy_adminBypassesWithoutMfa() {
        // app.mfa.enforce-privileged-floor=false (dark default, via the legacy 2-arg
        // ctor): an admin on the SAME mfa_required surface bypasses WITHOUT any MFA —
        // proving the floor is inert until an operator flips the sub-flag.
        var svc = realServiceWithMfaRequiredAdminRow();
        GatewayRouteAccessFilter legacy = new GatewayRouteAccessFilter(svc,
                new net.hugmesh.gateway.security.DomainRegistry("http://casdoor:8000", "", ""));
        Jwt adminJwt = jwtWithMfa("admin-1", List.of(Map.of("name", "admin")), null);
        var auth = new JwtAuthenticationToken(adminJwt, List.of(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
        var req = MockServerHttpRequest.get("/api/admin/secrets").build();
        MockServerWebExchange mwex = MockServerWebExchange.from(req);
        legacy.filter(new ExchangeWithPrincipal(mwex, auth), forwarded).block();
        assertThat(downstreamCalled).as("floor flag off -> legacy admin bypass, no MFA gate").isTrue();
    }

    // ── Inbound X-Domain strip (issue #4, TODO 2 — the half that can land) ───
    //
    // X-Domain is the canonical gateway-stamped brand header. INBOUND it is
    // client-supplied and therefore untrusted; the filter drops it
    // UNCONDITIONALLY at the top of filter(), before every short-circuit, so no
    // downstream can ever receive a caller-forged value. The gateway does not yet
    // stamp a replacement (no consumer exists), which these tests also pin: the
    // forwarded request must carry NO X-Domain at all.

    /** Runs the filter with a capturing chain and returns the exchange the
     *  downstream actually received (NOT the one handed in — the filter forwards a
     *  mutated exchange when it strips a header). */
    private org.springframework.web.server.ServerWebExchange runCapturingForwarded(
            String path, String domainHeaderName, String domainHeaderValue,
            AbstractAuthenticationToken auth) {
        var builder = MockServerHttpRequest.get(path);
        if (domainHeaderName != null) builder.header(domainHeaderName, domainHeaderValue);
        MockServerWebExchange mwex = MockServerWebExchange.from(builder.build());
        var seen = new java.util.concurrent.atomic.AtomicReference<
                org.springframework.web.server.ServerWebExchange>();
        WebFilterChain capturing = ex -> { seen.set(ex); return Mono.empty(); };
        if (auth == null) {
            filter.filter(mwex, capturing).block();
        } else {
            filter.filter(new ExchangeWithPrincipal(mwex, auth), capturing).block();
        }
        return seen.get();
    }

    @Test
    void inboundXDomain_strippedOnAnonymousRequest() {
        // The anonymous branch returns chain.filter() FIRST, before any decision —
        // so a strip placed anywhere further down would miss it entirely.
        var forwardedExchange = runCapturingForwarded("/api/login", "X-Domain", "brandy", null);
        assertThat(forwardedExchange).as("anonymous request must still forward").isNotNull();
        assertThat(forwardedExchange.getRequest().getHeaders().get("X-Domain"))
            .as("a client-supplied X-Domain must never reach a downstream")
            .isNull();
    }

    @Test
    void inboundXDomain_strippedOnAdminBypass() {
        // The ADMIN/GAME-MASTER own-domain bypass also short-circuits before
        // decide(); a forged X-Domain must not ride it downstream either.
        Jwt adminJwt = jwt("admin-1", List.of(Map.of("name", "admin")));
        var forwardedExchange = runCapturingForwarded(
                "/api/anything", "X-Domain", "brandy", authFor(adminJwt, "ADMIN"));
        assertThat(forwardedExchange.getRequest().getHeaders().get("X-Domain")).isNull();
        Mockito.verify(routeAccess, Mockito.never()).decide(any(), any(), any(), any());
    }

    @Test
    void inboundXDomain_strippedOnSuperadminCrossDomainBypass() {
        // SUPERADMIN is the ONLY cross-domain bypass and short-circuits earliest of
        // all — the highest-value forgery target, since it is the one principal that
        // legitimately crosses brands.
        Jwt saJwt = jwt("sa-1", List.of(Map.of("name", "superadmin")));
        var forwardedExchange = runCapturingForwarded(
                "/api/admin/secrets", "X-Domain", "brandy", authFor(saJwt, "SUPERADMIN"));
        assertThat(forwardedExchange.getRequest().getHeaders().get("X-Domain")).isNull();
    }

    @Test
    void inboundXDomain_strippedOnAllowDecision() {
        // The ordinary ALLOW fall-through (the only path that reaches decide()).
        when(routeAccess.decide(any(), any(), any(), any())).thenReturn(Decision.ALLOW);
        Jwt userJwt = jwt("user-1", List.of(Map.of("name", "user")));
        var forwardedExchange = runCapturingForwarded(
                "/api/reports/q3", "X-Domain", "brandy", authFor(userJwt));
        assertThat(forwardedExchange.getRequest().getHeaders().get("X-Domain")).isNull();
    }

    @Test
    void inboundXDomain_strippedOnNoRuleForward() {
        // NO_RULE FORWARDS — an ungoverned path is precisely where a forged header
        // would otherwise sail straight through.
        when(routeAccess.decide(any(), any(), any(), any())).thenReturn(Decision.NO_RULE);
        Jwt userJwt = jwt("user-1", List.of(Map.of("name", "user")));
        var forwardedExchange = runCapturingForwarded(
                "/api/public/health", "X-Domain", "brandy", authFor(userJwt));
        assertThat(forwardedExchange.getRequest().getHeaders().get("X-Domain")).isNull();
    }

    @Test
    void inboundXDomain_strippedRegardlessOfHeaderCase() {
        // HTTP header names are case-insensitive; a strip that matched only the
        // canonical spelling would be trivially bypassed with `x-domain:`.
        when(routeAccess.decide(any(), any(), any(), any())).thenReturn(Decision.ALLOW);
        Jwt userJwt = jwt("user-1", List.of(Map.of("name", "user")));
        var forwardedExchange = runCapturingForwarded(
                "/api/reports/q3", "x-domain", "brandy", authFor(userJwt));
        assertThat(forwardedExchange.getRequest().getHeaders().get("X-Domain")).isNull();
        assertThat(forwardedExchange.getRequest().getHeaders().get("x-domain")).isNull();
    }

    @Test
    void inboundXDomain_emptyValuedHeaderAlsoStripped() {
        // A present-but-blank header is still a client-supplied header; leaving it
        // would let a caller assert "no brand" to a downstream that distinguishes
        // absent from empty.
        when(routeAccess.decide(any(), any(), any(), any())).thenReturn(Decision.ALLOW);
        Jwt userJwt = jwt("user-1", List.of(Map.of("name", "user")));
        var forwardedExchange = runCapturingForwarded(
                "/api/reports/q3", "X-Domain", "", authFor(userJwt));
        assertThat(forwardedExchange.getRequest().getHeaders().get("X-Domain")).isNull();
    }

    @Test
    void noInboundXDomain_exchangeForwardedUnmutated_andGatewayStampsNothingYet() {
        // Two contracts in one: (a) the common case allocates no mutated exchange —
        // the SAME exchange instance is forwarded, so the filter is byte-identical to
        // its previous behaviour for a request without the header; and (b) the
        // gateway does NOT stamp an X-Domain of its own. The forwarding half of the
        // TODO is deliberately unimplemented (no downstream consumer exists), so an
        // accidental early stamp — shipping the header dark — fails here.
        when(routeAccess.decide(any(), any(), any(), any())).thenReturn(Decision.ALLOW);
        Jwt userJwt = jwt("user-1", List.of(Map.of("name", "user")));
        var builder = MockServerHttpRequest.get("/api/reports/q3");
        MockServerWebExchange mwex = MockServerWebExchange.from(builder.build());
        var handedIn = new ExchangeWithPrincipal(mwex, authFor(userJwt));
        var seen = new java.util.concurrent.atomic.AtomicReference<
                org.springframework.web.server.ServerWebExchange>();
        WebFilterChain capturing = ex -> { seen.set(ex); return Mono.empty(); };
        filter.filter(handedIn, capturing).block();
        assertThat(seen.get())
            .as("no header present -> forward the very same exchange, no mutation")
            .isSameAs(handedIn);
        assertThat(seen.get().getRequest().getHeaders().get("X-Domain"))
            .as("the gateway must not stamp X-Domain until a consumer exists")
            .isNull();
    }

    @Test
    void inboundXDomain_deniedRequestStillNeverForwards() {
        // Belt-and-braces: on DENY nothing is forwarded at all, and the 403 contract
        // (status + X-Route-Denied) is unchanged by the strip.
        when(routeAccess.decide(any(), any(), any(), any())).thenReturn(Decision.DENY);
        Jwt userJwt = jwt("user-1", List.of(Map.of("name", "user")));
        var builder = MockServerHttpRequest.get("/api/reports/q3").header("X-Domain", "brandy");
        MockServerWebExchange mwex = MockServerWebExchange.from(builder.build());
        var seen = new java.util.concurrent.atomic.AtomicReference<
                org.springframework.web.server.ServerWebExchange>();
        WebFilterChain capturing = ex -> { seen.set(ex); return Mono.empty(); };
        filter.filter(new ExchangeWithPrincipal(mwex, authFor(userJwt)), capturing).block();
        assertThat(seen.get()).as("DENY must not forward").isNull();
        assertThat(mwex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(mwex.getResponse().getHeaders().getFirst("X-Route-Denied"))
            .isEqualTo("hugmesh-be-gateway:/api/reports/q3");
    }


    // ── Outbound X-Domain stamp (issue #4, TODO 2 — the producer, SHIPPING INERT) ─
    //
    // app.domain-header.forward defaults FALSE, so every test above already proves
    // the dark default (nothing stamped). These pin the OTHER state: with the flag
    // on, the gateway stamps the Host-derived, registry-validated brand — the same
    // value decide() is given — on EVERY path that forwards, and a client-supplied
    // header is REPLACED, never merged. The consumer is still absent (games decision
    // 026), so this stays opt-in; what it buys now is that the safe shape is the one
    // in the tree, instead of a TODO inviting the stamp at the decision fall-through
    // where every anonymous request would miss it.

    /** Filter with the stamp ENABLED (5-arg ctor), single-issuer registry — so the
     *  validated brand is the single-tenant {@code "default"}. */
    private GatewayRouteAccessFilter stampingFilter() {
        return new GatewayRouteAccessFilter(routeAccess,
                new net.hugmesh.gateway.security.DomainRegistry("http://casdoor:8000", "", ""),
                false, 600_000L, true);
    }

    /** As {@link #runCapturingForwarded} but against an explicitly supplied filter
     *  and Host, returning the exchange the DOWNSTREAM saw. */
    private static org.springframework.web.server.ServerWebExchange runCapturingForwarded(
            GatewayRouteAccessFilter f, String path, String host,
            String domainHeaderValue, AbstractAuthenticationToken auth) {
        var builder = MockServerHttpRequest.get(path);
        if (host != null) builder.header(org.springframework.http.HttpHeaders.HOST, host);
        if (domainHeaderValue != null) builder.header("X-Domain", domainHeaderValue);
        MockServerWebExchange mwex = MockServerWebExchange.from(builder.build());
        var seen = new java.util.concurrent.atomic.AtomicReference<
                org.springframework.web.server.ServerWebExchange>();
        WebFilterChain capturing = ex -> { seen.set(ex); return Mono.empty(); };
        if (auth == null) {
            f.filter(mwex, capturing).block();
        } else {
            f.filter(new ExchangeWithPrincipal(mwex, auth), capturing).block();
        }
        return seen.get();
    }

    @Test
    void stampOn_anonymousRequestCarriesTheValidatedBrand() {
        // THE WHOLE POINT of the header: the consumer scopes ANONYMOUS public reads.
        // The anonymous branch returns chain.filter() before the route-access
        // decision, so a stamp written at the decision fall-through would be absent
        // here — this test is what fails if someone moves it back down.
        var fwd = runCapturingForwarded(stampingFilter(), "/api/games/catalog", null, null, null);
        assertThat(fwd).as("anonymous request must still forward").isNotNull();
        assertThat(fwd.getRequest().getHeaders().get("X-Domain"))
            .as("anonymous traffic must carry the gateway's brand stamp")
            .containsExactly("default");
    }

    @Test
    void stampOn_forgedInboundIsReplaced_notMerged() {
        // The security contract of the pair: strip THEN stamp, on the same headers,
        // so a caller who forges X-Domain: brandy leaves with exactly ONE value —
        // the gateway's. Two values would let a downstream reading getFirst() pick
        // the attacker's.
        when(routeAccess.decide(any(), any(), any(), any())).thenReturn(Decision.ALLOW);
        Jwt userJwt = jwt("user-1", List.of(Map.of("name", "user")));
        var fwd = runCapturingForwarded(
                stampingFilter(), "/api/reports/q3", null, "brandy", authFor(userJwt));
        assertThat(fwd.getRequest().getHeaders().get("X-Domain"))
            .as("the forged value must be gone and exactly one gateway value present")
            .containsExactly("default");
    }

    @Test
    void stampOn_forgedInboundIsReplaced_evenInLowercaseSpelling() {
        // HTTP header names are case-insensitive: `x-domain: brandy` must be removed
        // by the same lookup, not left beside the stamped canonical spelling.
        when(routeAccess.decide(any(), any(), any(), any())).thenReturn(Decision.ALLOW);
        Jwt userJwt = jwt("user-1", List.of(Map.of("name", "user")));
        var builder = MockServerHttpRequest.get("/api/reports/q3").header("x-domain", "brandy");
        MockServerWebExchange mwex = MockServerWebExchange.from(builder.build());
        var seen = new java.util.concurrent.atomic.AtomicReference<
                org.springframework.web.server.ServerWebExchange>();
        WebFilterChain capturing = ex -> { seen.set(ex); return Mono.empty(); };
        stampingFilter().filter(new ExchangeWithPrincipal(mwex, authFor(userJwt)), capturing).block();
        assertThat(seen.get().getRequest().getHeaders().get("X-Domain"))
            .containsExactly("default");
        assertThat(seen.get().getRequest().getHeaders().get("x-domain"))
            .as("same header, case-insensitive lookup — one value, the gateway's")
            .containsExactly("default");
    }

    @Test
    void stampOn_privilegedBypassesAlsoCarryTheStamp() {
        // Both bypasses reach chain.filter() on their own. A downstream that trusts
        // the header's PRESENCE must not see it vanish for admins and superadmins.
        Jwt adminJwt = jwt("admin-1", List.of(Map.of("name", "admin")));
        var viaAdmin = runCapturingForwarded(
                stampingFilter(), "/api/anything", null, "brandy", authFor(adminJwt, "ADMIN"));
        assertThat(viaAdmin.getRequest().getHeaders().get("X-Domain")).containsExactly("default");
        Mockito.verify(routeAccess, Mockito.never()).decide(any(), any(), any(), any());

        Jwt saJwt = jwt("sa-1", List.of(Map.of("name", "superadmin")));
        var viaSa = runCapturingForwarded(
                stampingFilter(), "/api/admin/secrets", null, "brandy", authFor(saJwt, "SUPERADMIN"));
        assertThat(viaSa.getRequest().getHeaders().get("X-Domain")).containsExactly("default");
    }

    @Test
    void stampOn_valueIsTheRegistryResolvedBrand_fromHost_notTheInboundHeader() {
        // Multi-brand: the stamp is the brand the registry maps this Host to, which
        // is the SAME targetDomain decide() is given — so a downstream scoping on the
        // header and the gateway gating on the table can never disagree. A forged
        // inbound naming the OTHER brand does not influence it.
        when(routeAccess.decide(any(), any(), any(), any())).thenReturn(Decision.ALLOW);
        var multiBrandStamping = new GatewayRouteAccessFilter(
                routeAccess, multiBrandRegistry(), false, 600_000L, true);
        Jwt brandXJwt = jwt("user-x", List.of(Map.of("name", "user")), BRANDX_ISSUER);
        var fwd = runCapturingForwarded(multiBrandStamping, "/api/games/catalog",
                "api.brandx.tld", "brandy", authForDomain(brandXJwt, "brandx"));
        assertThat(fwd.getRequest().getHeaders().get("X-Domain"))
            .as("Host api.brandx.tld resolves to brandx; the forged 'brandy' is discarded")
            .containsExactly("brandx");
        var domainSeenByDecide = org.mockito.ArgumentCaptor.forClass(String.class);
        Mockito.verify(routeAccess).decide(any(), domainSeenByDecide.capture(), any(), any());
        assertThat(domainSeenByDecide.getValue())
            .as("the stamped brand must be the very value the decision was made on")
            .isEqualTo("brandx");
    }

    @Test
    void stampOn_deniedRequestStillForwardsNothing() {
        // The stamp must not become a way for a denied request to reach a downstream.
        when(routeAccess.decide(any(), any(), any(), any())).thenReturn(Decision.DENY);
        Jwt userJwt = jwt("user-1", List.of(Map.of("name", "user")));
        var fwd = runCapturingForwarded(
                stampingFilter(), "/api/reports/q3", null, "brandy", authFor(userJwt));
        assertThat(fwd).as("DENY must not forward, stamped or not").isNull();
    }

    @Test
    void stampOff_isTheDefault_andForwardsNoHeaderAtAll() {
        // The dark default, asserted against the PRODUCTION property default rather
        // than a hand-passed false: a filter built by the 2-arg ctor (which mirrors
        // ${app.domain-header.forward:false}) stamps nothing on any branch.
        when(routeAccess.decide(any(), any(), any(), any())).thenReturn(Decision.ALLOW);
        Jwt userJwt = jwt("user-1", List.of(Map.of("name", "user")));
        var authed = runCapturingForwarded(filter, "/api/reports/q3", null, null, authFor(userJwt));
        assertThat(authed.getRequest().getHeaders().get("X-Domain"))
            .as("stamp is OFF by default — no consumer exists yet")
            .isNull();
        var anon = runCapturingForwarded(filter, "/api/login", null, null, null);
        assertThat(anon.getRequest().getHeaders().get("X-Domain")).isNull();
    }

    /**
     * F1 GUARD (skeptic finding, round 3): pins the {@code @Value} PLACEHOLDER KEY
     * itself, not just the filter's behaviour once a boolean has been handed to it.
     *
     * <p><b>The hole this closes.</b> Every ON-state test above builds the filter by
     * hand through the 5-arg constructor, and the container-wired guard in
     * {@code HugMeshGatewayApplicationTests} asserts only the OFF state — which
     * passes whether or not {@code ${app.domain-header.forward:false}} resolves to
     * anything at all. Measured on this branch: misspelling the key to
     * {@code app.domain-headerz.forward} (fallback still {@code false}) left the
     * FULL suite at 507 tests, 0 failures, BUILD SUCCESS — while
     * {@code APP_DOMAIN_HEADER_FORWARD=true}, the operator lever README.md sells,
     * would have done nothing, forever, with a green build.
     *
     * <p>These two drive the SAME chain the container uses — property ->
     * placeholder -> field -> behaviour — with Spring doing the binding, so any
     * break anywhere in it fails here in BOTH directions (a typo kills the ON test;
     * a fallback flipped to {@code :true} kills the OFF test).
     *
     * <p>{@link ApplicationContextRunner} rather than a second {@code @SpringBootTest}:
     * it is this repo's established pattern for exactly this
     * ({@code BffJwtExchangeConfigTest}, {@code DownstreamMtlsConfigTest}), it is the
     * shape commit {@code 6033cb9} used to close the identical unguarded-{@code @Value}
     * finding on the sibling {@code BffJwtExchangeWebFilter}, and it keeps the
     * per-PR gate from paying for another full application context.
     */
    @org.junit.jupiter.api.Nested
    class XDomainStampPropertyBinding {

        /** Minimal context: the real filter registered as a COMPONENT (so Spring
         *  instantiates it through its {@code @Autowired} constructor and resolves the
         *  placeholder), plus its two collaborators. The route-access service is
         *  wired {@code enabled=false} so its {@code @PostConstruct} no-ops — these
         *  requests are anonymous and never reach {@code decide()} anyway. */
        private final org.springframework.boot.test.context.runner.ApplicationContextRunner runner =
                new org.springframework.boot.test.context.runner.ApplicationContextRunner()
                        .withBean(GatewayRouteAccessService.class, () -> new GatewayRouteAccessService(
                                null, null, "hugmesh-be-gateway", false, false, null))
                        .withBean(net.hugmesh.gateway.security.DomainRegistry.class,
                                () -> new net.hugmesh.gateway.security.DomainRegistry(
                                        "http://casdoor:8000", "", ""))
                        .withUserConfiguration(GatewayRouteAccessFilter.class);

        /** Runs one anonymous request carrying a forged {@code X-Domain} through the
         *  CONTAINER-BUILT filter and returns what the downstream saw. */
        private List<String> forwardedXDomain(
                org.springframework.context.ApplicationContext ctx) {
            var f = ctx.getBean(GatewayRouteAccessFilter.class);
            var req = MockServerHttpRequest.get("/api/anything")
                    .header("X-Domain", "brandy").build();
            var exchange = MockServerWebExchange.from(req);
            var seen = new java.util.concurrent.atomic.AtomicReference<
                    org.springframework.web.server.ServerWebExchange>();
            f.filter(exchange, ex -> { seen.set(ex); return Mono.empty(); }).block();
            assertThat(seen.get()).as("an anonymous request must still forward").isNotNull();
            return seen.get().getRequest().getHeaders().get("X-Domain");
        }

        @Test
        void propertyUnset_theBoundFilterStampsNothing_andStillStripsTheForgedValue() {
            runner.run(ctx -> {
                assertThat(ctx).hasNotFailed();
                assertThat(forwardedXDomain(ctx))
                    .as("the @Value FALLBACK is the effective default wherever "
                            + "application.yml is replaced rather than layered over "
                            + "(SPRING_CONFIG_LOCATION at a mounted ConfigMap): it must "
                            + "be false, and the strip must run regardless")
                    .isNull();
            });
        }

        @Test
        void propertySetTrue_theBoundFilterStampsTheValidatedBrand() {
            runner.withPropertyValues("app.domain-header.forward=true").run(ctx -> {
                assertThat(ctx).hasNotFailed();
                assertThat(forwardedXDomain(ctx))
                    .as("app.domain-header.forward=true must actually BIND through the "
                            + "placeholder: exactly one value, the gateway's "
                            + "single-tenant brand, and the forged 'brandy' gone")
                    .containsExactly("default");
            });
        }
    }

    /** Populates getPrincipal() on a MockServerWebExchange (the mock leaves it
     *  an empty Mono otherwise). Mirrors the helper in ResourceAccessFilterTest. */
    static class ExchangeWithPrincipal extends org.springframework.web.server.ServerWebExchangeDecorator {
        private final java.security.Principal principal;
        ExchangeWithPrincipal(org.springframework.web.server.ServerWebExchange delegate,
                              java.security.Principal principal) {
            super(delegate);
            this.principal = principal;
        }
        @Override
        @SuppressWarnings("unchecked")
        public <T extends java.security.Principal> Mono<T> getPrincipal() {
            return Mono.just((T) principal);
        }
    }
}
