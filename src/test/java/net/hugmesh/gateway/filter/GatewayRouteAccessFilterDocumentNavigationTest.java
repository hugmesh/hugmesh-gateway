package net.hugmesh.gateway.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import net.hugmesh.gateway.cache.GatewayRouteAccessService;
import net.hugmesh.gateway.cache.GatewayRouteAccessService.Decision;
import net.hugmesh.gateway.security.DomainRegistry;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * GUI-08, the route-access half: which refusals of a fe-tier document navigation turn
 * into {@code 302 /home?denied=<path>} and which keep the bare 403. Only the plain
 * route-access DENY redirects. A step-up denial, a cross-brand hard-deny and an
 * unregistered onion keep their 403 (the last two refuse /home as well, so a redirect
 * would loop). The full assembled chain is covered by
 * {@code FeDocumentNavigationSliceTest}; these are the branches it cannot reach with a
 * real token.
 */
class GatewayRouteAccessFilterDocumentNavigationTest {

    private static final String FE = "hugmesh-fe-gateway";
    private static final String ISSUER = "http://casdoor:8000";

    private GatewayRouteAccessService routeAccess;
    private AtomicBoolean downstreamCalled;
    private WebFilterChain forwarded;

    @BeforeEach
    void setUp() {
        routeAccess = Mockito.mock(GatewayRouteAccessService.class);
        when(routeAccess.gatewayName()).thenReturn(FE);
        when(routeAccess.isPrimed()).thenReturn(true);
        downstreamCalled = new AtomicBoolean(false);
        forwarded = ex -> { downstreamCalled.set(true); return Mono.empty(); };
    }

    private static MockServerHttpRequest.BaseBuilder<?> navigation(String path) {
        return MockServerHttpRequest.get(path)
                .header(HttpHeaders.ACCEPT, "text/html,application/xhtml+xml,*/*;q=0.8")
                .header("Sec-Fetch-Mode", "navigate")
                .header("Sec-Fetch-Dest", "document");
    }

    private static Jwt jwt(String issuer) {
        return Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60))
                .subject("member-1").issuer(issuer)
                .claim("roles", List.of(Map.of("name", "user"))).build();
    }

    private static AbstractAuthenticationToken jwtUser(String issuer) {
        return new JwtAuthenticationToken(jwt(issuer), List.of(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private static AbstractAuthenticationToken bffSessionUser() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        return new UsernamePasswordAuthenticationToken("casdoor:member-1", null, authorities);
    }

    private MockServerWebExchange run(GatewayRouteAccessFilter filter, MockServerHttpRequest request,
                                      AbstractAuthenticationToken auth) {
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        filter.filter(new GatewayRouteAccessFilterTest.ExchangeWithPrincipal(exchange, auth), forwarded).block();
        return exchange;
    }

    private GatewayRouteAccessFilter singleTenant() {
        return new GatewayRouteAccessFilter(routeAccess, new DomainRegistry(ISSUER, "", ""));
    }

    @Test
    void plainDeny_ofADocumentNavigation_redirectsToTheDeniedPage_forBothCarriers() {
        when(routeAccess.decide(any(), any(), any(), any())).thenReturn(Decision.DENY);
        for (AbstractAuthenticationToken auth : List.of(jwtUser(ISSUER), bffSessionUser())) {
            downstreamCalled.set(false);
            MockServerWebExchange ex = run(singleTenant(), navigation("/admin/users").build(), auth);
            assertThat(ex.getResponse().getStatusCode()).as(auth.getClass().getSimpleName())
                    .isEqualTo(HttpStatus.FOUND);
            assertThat(ex.getResponse().getHeaders().getFirst(HttpHeaders.LOCATION))
                    .isEqualTo("/home?denied=%2Fadmin%2Fusers");
            assertThat(ex.getResponse().getHeaders().getFirst("X-Route-Denied"))
                    .isEqualTo(FE + ":/admin/users");
            assertThat(ex.getResponse().getHeaders().getFirst(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
            assertThat(downstreamCalled).isFalse();
        }
    }

    @Test
    void plainDeny_ofAnApiRequest_isTheBare403() {
        when(routeAccess.decide(any(), any(), any(), any())).thenReturn(Decision.DENY);
        MockServerWebExchange ex = run(singleTenant(),
                MockServerHttpRequest.get("/admin/users").header(HttpHeaders.ACCEPT, "*/*").build(),
                jwtUser(ISSUER));
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(ex.getResponse().getHeaders().getFirst(HttpHeaders.LOCATION)).isNull();
        assertThat(ex.getResponse().getHeaders().getFirst(HttpHeaders.CACHE_CONTROL)).isNull();
        assertThat(ex.getResponse().getHeaders().getFirst("X-Route-Denied")).isEqualTo(FE + ":/admin/users");
        assertThat(downstreamCalled).isFalse();
    }

    @Test
    void plainDeny_onTheBeAndPkiTiers_isTheBare403_evenForANavigation() {
        when(routeAccess.decide(any(), any(), any(), any())).thenReturn(Decision.DENY);
        for (String gw : new String[] {"hugmesh-be-gateway", "hugmesh-pki-gateway", "brandx-be-gateway", ""}) {
            when(routeAccess.gatewayName()).thenReturn(gw);
            MockServerWebExchange ex = run(singleTenant(), navigation("/admin").build(), jwtUser(ISSUER));
            assertThat(ex.getResponse().getStatusCode()).as("tier '%s'", gw).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(ex.getResponse().getHeaders().getFirst(HttpHeaders.LOCATION)).as("tier '%s'", gw).isNull();
        }
    }

    @Test
    void stepUpDenial_isNotAMissingRole_andKeepsIts403() {
        when(routeAccess.decide(any(), any(), any(), any())).thenReturn(Decision.DENY);
        when(routeAccess.isMfaStepUpDenial(any(), any(), any(), any())).thenReturn(true);
        MockServerWebExchange ex = run(singleTenant(), navigation("/admin").build(), jwtUser(ISSUER));
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(ex.getResponse().getHeaders().getFirst("X-Step-Up-Required")).isEqualTo("X-Mfa-StepUp");
        assertThat(ex.getResponse().getHeaders().getFirst(HttpHeaders.LOCATION)).isNull();
        assertThat(downstreamCalled).isFalse();
    }

    @Test
    void crossBrandHardDeny_keepsIts403_becauseItRefusesTheDeniedPageToo() {
        // A brand-X token on brand-Y's Host is refused before any row is read — on
        // /home as much as on /admin — so sending it to /home would loop.
        DomainRegistry registry = new DomainRegistry("https://id.brandx.tld",
                "https://id.brandx.tld=brandx,https://id.brandy.tld=brandy",
                "www.brandx.tld=brandx,www.brandy.tld=brandy");
        GatewayRouteAccessFilter filter = new GatewayRouteAccessFilter(routeAccess, registry);
        for (String path : List.of("/admin", "/home")) {
            MockServerWebExchange ex = run(filter,
                    navigation(path).header(HttpHeaders.HOST, "www.brandy.tld").build(),
                    jwtUser("https://id.brandx.tld"));
            assertThat(ex.getResponse().getStatusCode()).as(path).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(ex.getResponse().getHeaders().getFirst(HttpHeaders.LOCATION)).as(path).isNull();
        }
        Mockito.verify(routeAccess, Mockito.never()).decide(any(), any(), any(), any());
        assertThat(downstreamCalled).isFalse();
    }

    @Test
    void aDenyOfTheDeniedPageItself_staysA403() {
        when(routeAccess.decide(any(), any(), any(), any())).thenReturn(Decision.DENY);
        for (String path : List.of("/home", "/home/", "/home/anything")) {
            MockServerWebExchange ex = run(singleTenant(), navigation(path).build(), jwtUser(ISSUER));
            assertThat(ex.getResponse().getStatusCode()).as(path).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(ex.getResponse().getHeaders().getFirst(HttpHeaders.LOCATION)).as(path).isNull();
        }
    }

    @Test
    void allowAndNoRule_forwardTheNavigationUntouched() {
        for (Decision d : List.of(Decision.ALLOW, Decision.NO_RULE)) {
            when(routeAccess.decide(any(), any(), any(), any())).thenReturn(d);
            downstreamCalled.set(false);
            MockServerWebExchange ex = run(singleTenant(), navigation("/user").build(), jwtUser(ISSUER));
            assertThat(downstreamCalled).as(d.name()).isTrue();
            assertThat(ex.getResponse().getHeaders().getFirst(HttpHeaders.LOCATION)).isNull();
        }
    }
}
