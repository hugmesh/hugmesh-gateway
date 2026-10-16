package net.hugmesh.gateway.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
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
import net.hugmesh.gateway.cache.ResourceAuthorizationService;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * The per-resource grant check matched the RAW path, so {@code /api/%67ames/x/launch}
 * matched no resource pattern and skipped the grant check while the router decoded it
 * onto the games handler. The encoded spelling must get the plain form's verdict, and
 * the resource id must be the DECODED id the downstream will see.
 */
class ResourceAccessFilterEncodedPathTest {

    private ResourceAuthorizationService authz;
    private ResourceAccessFilter filter;
    private WebFilterChain forwarded;
    private AtomicBoolean downstreamCalled;

    @BeforeEach
    void setup() {
        authz = Mockito.mock(ResourceAuthorizationService.class);
        when(authz.isGranted(anyString(), anyString(), any())).thenReturn(false);
        when(authz.hasAnyRoleGrant(anyString(), anyString(), any())).thenReturn(false);
        filter = new ResourceAccessFilter(authz);
        downstreamCalled = new AtomicBoolean(false);
        forwarded = ex -> { downstreamCalled.set(true); return Mono.empty(); };
    }

    private static AbstractAuthenticationToken player() {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60))
                .subject("player-1").claim("roles", List.of(Map.of("name", "user")))
                .claim("name", "player-1").build();
        return new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private MockServerWebExchange run(String rawPath, AbstractAuthenticationToken auth) {
        var mwex = MockServerWebExchange.from(
                MockServerHttpRequest.method(HttpMethod.GET, URI.create(rawPath)).build());
        var ex = auth == null ? mwex : new ResourceAccessFilterTest.ExchangeWithPrincipal(mwex, auth);
        filter.filter(ex, forwarded).block();
        return mwex;
    }

    @Test
    void ungrantedPlayer_isDenied_plainAndEncodedAlike() {
        for (String raw : List.of(
                "/api/games/abbott-village/launch",            // baseline
                "/api/%67ames/abbott-village/launch",          // the exploit
                "/%61pi/games/abbott-village/launch",
                "/api/games/%61bbott-village/launch",          // encoded id
                "/api/x/../games/abbott-village/launch",
                "/api//games///abbott-village/launch",
                "/api/games;a=b/abbott-village/launch",
                "/api/sessions/%73-1/state")) {
            downstreamCalled.set(false);
            var mwex = run(raw, player());
            assertThat(downstreamCalled).as("%s must not be forwarded", raw).isFalse();
            assertThat(mwex.getResponse().getStatusCode()).as(raw).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(mwex.getResponse().getHeaders().getFirst("X-Resource-Denied")).as(raw).isNotNull();
        }
    }

    @Test
    void grantIsLookedUpByTheDecodedResourceId() {
        when(authz.isGranted("game", "abbott-village", "player-1")).thenReturn(true);
        run("/api/games/%61bbott-village/launch", player());
        assertThat(downstreamCalled).as("grant keyed on the decoded id").isTrue();
    }

    @Test
    void ambiguousPaths_areRefusedWith400() {
        for (String raw : List.of(
                "/api/games/abbott%2Fvillage/launch",
                "/api/%2567ames/abbott-village/launch",
                "/api/games/abbott-village%00/launch")) {
            downstreamCalled.set(false);
            var mwex = run(raw, player());
            assertThat(downstreamCalled).as(raw).isFalse();
            assertThat(mwex.getResponse().getStatusCode()).as(raw).isEqualTo(HttpStatus.BAD_REQUEST);
            var anon = run(raw, null);
            assertThat(anon.getResponse().getStatusCode()).as("anonymous " + raw).isEqualTo(HttpStatus.BAD_REQUEST);
        }
    }

    @Test
    void nonResourcePath_isStillForwarded() {
        run("/api/catalog/%6Cist", player());
        assertThat(downstreamCalled).isTrue();
    }
}
