package net.hugmesh.gateway.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import net.hugmesh.gateway.cache.GatewayRouteAccessService;
import net.hugmesh.gateway.cache.GatewayRouteAccessService.Rule;
import net.hugmesh.gateway.security.DomainRegistry;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Raw-path bypass of the route-access gate, MFA step-up surface and privileged MFA
 * floor, against a REAL {@link GatewayRouteAccessService} (not a mock, so the actual
 * {@code AntPathMatcher} walk over decoded patterns is what is under test). Every
 * encoded spelling must get exactly the verdict its plain form gets.
 *
 * <p>The rule table is keyed on the DECODED spelling, as production rows are. Before
 * the fix the filter matched the raw percent-encoded string, so each encoded form
 * below matched no row (NO_RULE, which forwards an authenticated caller).
 */
class GatewayRouteAccessFilterEncodedPathTest {

    private static final String GW = "hugmesh-be-gateway";
    private static final String ISSUER = "http://casdoor:8000";

    private WebFilterChain forwarded;
    private AtomicBoolean downstreamCalled;
    private GatewayRouteAccessFilter filter;
    private GatewayRouteAccessFilter floorFilter;

    private static Rule row(String pattern, String role, boolean allow, boolean mfa) {
        return new Rule("t-" + pattern + role, GW, pattern, role, null, allow, null, mfa);
    }

    @BeforeEach
    void setup() {
        var svc = new GatewayRouteAccessService(null, null, GW, true, true, null);
        svc.primeForTest(List.of(
                row("/bff/mesh/internal/**", "ROLE_USER", false, false),   // explicit deny
                row("/bff/superadmin/**", "ROLE_SUPERADMIN", true, false),  // role-gated
                row("/api/reports/**", "ROLE_USER", true, true),            // mfa_required grant
                row("/api/admin/**", "ROLE_ADMIN", true, true),             // mfa_required surface
                row("/api/v1/apps", "ROLE_MOD", true, false)));             // exact-match row
        var registry = new DomainRegistry(ISSUER, "", "");
        filter = new GatewayRouteAccessFilter(svc, registry);
        floorFilter = new GatewayRouteAccessFilter(svc, registry, true, 600_000L);
        downstreamCalled = new AtomicBoolean(false);
        forwarded = ex -> { downstreamCalled.set(true); return Mono.empty(); };
    }

    private static Jwt jwt(Long mfaAtMillis) {
        return jwt(mfaAtMillis, "user");
    }

    private static Jwt jwt(Long mfaAtMillis, String role) {
        var b = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60))
                .subject("u1").issuer(ISSUER).claim("roles", List.of(Map.of("name", role)));
        if (mfaAtMillis != null) b.claim("mfa_satisfied_at", Long.toString(mfaAtMillis));
        return b.build();
    }

    private static AbstractAuthenticationToken auth(Jwt jwt, String... authorities) {
        var list = new java.util.ArrayList<SimpleGrantedAuthority>();
        list.add(new SimpleGrantedAuthority("ROLE_USER"));
        for (String a : authorities) list.add(new SimpleGrantedAuthority(a));
        return new JwtAuthenticationToken(jwt, list);
    }

    /** Pre-encoded URI: the String overloads of MockServerHttpRequest re-encode '%'. */
    private MockServerWebExchange run(GatewayRouteAccessFilter f, String rawPath,
                                      AbstractAuthenticationToken auth) {
        var mwex = MockServerWebExchange.from(
                MockServerHttpRequest.method(HttpMethod.GET, URI.create(rawPath)).build());
        var ex = auth == null ? mwex
                : new GatewayRouteAccessFilterTest.ExchangeWithPrincipal(mwex, auth);
        f.filter(ex, forwarded).block();
        return mwex;
    }

    private void assertDenied(String rawPath, AbstractAuthenticationToken auth) {
        downstreamCalled.set(false);
        var mwex = run(filter, rawPath, auth);
        assertThat(downstreamCalled).as("%s must not be forwarded", rawPath).isFalse();
        assertThat(mwex.getResponse().getStatusCode()).as(rawPath).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(mwex.getResponse().getHeaders().getFirst("X-Route-Denied"))
                .as(rawPath).isEqualTo(GW + ":" + rawPath);
    }

    private void assertForwarded(GatewayRouteAccessFilter f, String rawPath,
                                 AbstractAuthenticationToken auth) {
        downstreamCalled.set(false);
        run(f, rawPath, auth);
        assertThat(downstreamCalled).as("%s must be forwarded", rawPath).isTrue();
    }

    private void assertRefusedAsAmbiguous(GatewayRouteAccessFilter f, String rawPath,
                                          AbstractAuthenticationToken auth) {
        downstreamCalled.set(false);
        var mwex = run(f, rawPath, auth);
        assertThat(downstreamCalled).as("%s must not be forwarded", rawPath).isFalse();
        assertThat(mwex.getResponse().getStatusCode()).as(rawPath).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    // ── explicit deny row ────────────────────────────────────────────────────────

    @Test
    void denyRow_plainAndEncodedSpellings_getTheSameDeny() {
        var user = auth(jwt(null));
        assertDenied("/bff/mesh/internal/x", user);                   // baseline
        assertDenied("/bff/mesh/%69nternal/x", user);                 // the exploit
        assertDenied("/bff/%6Desh/internal/x", user);
        assertDenied("/bff/%6desh/%69%6e%74ernal/x", user);
        assertDenied("/%62ff/mesh/internal/x", user);
        assertDenied("/bff/mesh/x/../internal/x", user);
        assertDenied("/bff/mesh/./internal/x", user);
        assertDenied("/bff/mesh/x/%2e%2e/internal/x", user);
        assertDenied("/bff//mesh///internal/x", user);
        assertDenied("/bff/mesh/internal/", user);
        assertDenied("/bff/mesh/internal;a=b/x", user);
        assertDenied("/bff/mesh;x=1/internal/x", user);
        assertDenied("/bff/mesh/..;/mesh/internal/x", user);
    }

    // ── role-gated row ───────────────────────────────────────────────────────────

    @Test
    void roleGatedRow_encodedSpelling_isDeniedToAnUnprivilegedUser() {
        var user = auth(jwt(null));
        assertDenied("/bff/superadmin/x", user);
        assertDenied("/bff/%73uperadmin/x", user);
    }

    @Test
    void exactMatchRow_trailingSlashAndEncoding_areGovernedToo() {
        var user = auth(jwt(null));
        assertDenied("/api/v1/apps", user);
        assertDenied("/api/v1/apps/", user);
        assertDenied("/api/v1/%61pps", user);
    }

    // ── MFA step-up denial (X-Step-Up-Required) ──────────────────────────────────

    @Test
    void mfaStepUpDenial_encodedSpelling_carriesTheSameSignal() {
        // a ROLE_USER grant that is mfa_required, principal without a fresh factor
        var svc = new GatewayRouteAccessService(null, null, GW, true, true, null);
        svc.primeForTest(List.of(row("/api/reports/**", "ROLE_USER", true, true)));
        var f = new GatewayRouteAccessFilter(svc, new DomainRegistry(ISSUER, "", ""));
        for (String raw : List.of("/api/reports/q3", "/api/%72eports/q3", "/api/reports/x/../q3")) {
            downstreamCalled.set(false);
            var mwex = run(f, raw, auth(jwt(null)));
            assertThat(downstreamCalled).as(raw).isFalse();
            assertThat(mwex.getResponse().getStatusCode()).as(raw).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(mwex.getResponse().getHeaders().getFirst("X-Step-Up-Required"))
                    .as(raw).isEqualTo("X-Mfa-StepUp");
        }
    }

    // ── privileged MFA floor ─────────────────────────────────────────────────────

    @Test
    void privilegedFloor_encodedSpelling_isStillGated_aboveTheAdminBypass() {
        var admin = auth(jwt(null, "admin"), "ROLE_ADMIN");   // no MFA stamp
        for (String raw : List.of("/api/admin/secrets", "/api/%61dmin/secrets",
                "/api/admin/secrets/", "/api/x/../admin/secrets", "/api/admin;a=b/secrets")) {
            downstreamCalled.set(false);
            var mwex = run(floorFilter, raw, admin);
            assertThat(downstreamCalled).as("%s must hit the MFA floor", raw).isFalse();
            assertThat(mwex.getResponse().getStatusCode()).as(raw).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(mwex.getResponse().getHeaders().getFirst("X-Step-Up-Required")).as(raw).isNotNull();
        }
    }

    @Test
    void privilegedFloor_freshMfa_stillClearsTheEncodedSurface() {
        var admin = auth(jwt(System.currentTimeMillis() - 1_000L, "admin"), "ROLE_ADMIN");
        assertForwarded(floorFilter, "/api/%61dmin/secrets", admin);
    }

    // ── controls ─────────────────────────────────────────────────────────────────

    @Test
    void ungovernedEncodedPath_isStillForwarded() {
        assertForwarded(filter, "/bff/mesh/rooms/%21abc%3Aserver", auth(jwt(null)));
        assertForwarded(filter, "/bff/%6Desh/rooms", auth(jwt(null)));
    }

    @Test
    void legitimatePercentInAContentSegment_isNotRefused() {
        assertForwarded(filter, "/other/100%25", auth(jwt(null)));
    }

    // ── ambiguous: refused for EVERY caller, rule table never consulted ──────────

    @Test
    void ambiguousPaths_areRefusedWith400_forAuthenticatedAndAnonymousCallers() {
        var user = auth(jwt(null));
        var superadmin = auth(jwt(null, "superadmin"), "ROLE_SUPERADMIN");
        for (String raw : List.of(
                "/bff/mesh/%2569nternal/x",          // double encoding
                "/bff/mesh%2Finternal/x",            // encoded slash
                "/bff/mesh%5Cinternal/x",            // encoded backslash
                "/bff/mesh/internal%00/x",           // NUL
                "/bff/mesh/internal%0d%0a/x",        // CR LF
                "/../bff/mesh/internal/x")) {        // above the root
            assertRefusedAsAmbiguous(filter, raw, user);
            assertRefusedAsAmbiguous(filter, raw, superadmin);
            assertRefusedAsAmbiguous(filter, raw, null);
            assertRefusedAsAmbiguous(floorFilter, raw, auth(jwt(null, "admin"), "ROLE_ADMIN"));
        }
    }

    @Test
    void ambiguousPath_hasNoRouteDeniedHeader_andNeverEchoesDecodedBytes() {
        var mwex = run(filter, "/bff/mesh/internal%0d%0aX-Evil:1/x", auth(jwt(null)));
        assertThat(mwex.getResponse().getHeaders().containsHeader("X-Route-Denied")).isFalse();
        assertThat(mwex.getResponse().getHeaders().containsHeader("X-Evil")).isFalse();
    }
}
