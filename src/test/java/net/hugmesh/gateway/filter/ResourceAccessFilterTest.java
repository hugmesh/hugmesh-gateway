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
import net.hugmesh.gateway.cache.ResourceAuthorizationService;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * Resource-access filter contract:
 *
 * <ul>
 *   <li>Admin token alone → forwards regardless of external auth state.</li>
 *   <li>Game-master alone → forwards.</li>
 *   <li>Plain player with a user-specific grant → forwards.</li>
 *   <li>Plain player with an all-users grant → forwards.</li>
 *   <li>Plain player with a role grant for one of their roles → forwards.</li>
 *   <li>Plain player without any grant → 403 + X-Resource-Denied header.</li>
 *   <li>Anonymous request → forwards (SecurityConfig already decided
 *       whether the path is reachable without auth).</li>
 * </ul>
 */
class ResourceAccessFilterTest {

    private ResourceAuthorizationService authz;
    private ResourceAccessFilter filter;
    private WebFilterChain forwarded;
    private AtomicBoolean downstreamCalled;

    @BeforeEach
    void setup() {
        authz = Mockito.mock(ResourceAuthorizationService.class);
        filter = new ResourceAccessFilter(authz);
        downstreamCalled = new AtomicBoolean(false);
        forwarded = ex -> {
            downstreamCalled.set(true);
            return Mono.empty();
        };
    }

    /** Roles claim accepts any list shape — list-of-strings or list-of-
     *  Casdoor role objects (Map with `name` field). The filter's only
     *  consumer of the claim is Roles.fromJwt + Roles.isAdmin / -Master
     *  which both handle either shape; the tests below exercise the
     *  Casdoor default (object) shape. */
    private static Jwt jwt(String sub, List<?> roles) {
        return Jwt.withTokenValue("test")
            .header("alg", "none")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(60))
            .subject(sub)
            .claim("roles", roles)
            .claim("name", sub)
            .build();
    }

    private static AbstractAuthenticationToken authFor(Jwt jwt, String... roles) {
        var authorities = new java.util.ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        for (String r : roles) authorities.add(new SimpleGrantedAuthority("ROLE_" + r));
        return new JwtAuthenticationToken(jwt, authorities);
    }

    @Test
    void adminBypassesEvenWithoutAnyGrant_andWithoutExternalAuth() {
        when(authz.isGranted(anyString(), anyString(), anyString())).thenReturn(false);
        when(authz.hasAnyRoleGrant(anyString(), anyString(), any())).thenReturn(false);

        Jwt adminJwt = jwt("tw-admin-001", List.of(Map.of("name", "admin")));
        AbstractAuthenticationToken auth = authFor(adminJwt, "ADMIN");
        var ex = MockServerHttpRequest.get("/api/games/abbott-village/launch").build();
        MockServerWebExchange mwex = MockServerWebExchange.from(ex);
        // Hard-wire the principal mono since MockServerWebExchange's
        // getPrincipal() is a no-op until populated by the security
        // filter chain.
        Mono<Void> result = filter.filter(new ExchangeWithPrincipal(mwex, auth), forwarded);
        result.block();

        assertThat(downstreamCalled).isTrue();
        assertThat(mwex.getResponse().getStatusCode()).isNotEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void gameMasterBypassesEvenWithoutAnyGrant() {
        when(authz.isGranted(anyString(), anyString(), anyString())).thenReturn(false);
        when(authz.hasAnyRoleGrant(anyString(), anyString(), any())).thenReturn(false);

        Jwt gmJwt = jwt("tw-gm-001", List.of(Map.of("name", "game-master")));
        AbstractAuthenticationToken auth = authFor(gmJwt, "GAME-MASTER");
        var ex = MockServerHttpRequest.get("/api/games/abbott-village/launch").build();
        MockServerWebExchange mwex = MockServerWebExchange.from(ex);
        filter.filter(new ExchangeWithPrincipal(mwex, auth), forwarded).block();

        assertThat(downstreamCalled).isTrue();
    }

    @Test
    void playerWithoutGrant_isRejected_with403AndHeader() {
        when(authz.isGranted(anyString(), anyString(), anyString())).thenReturn(false);
        when(authz.hasAnyRoleGrant(anyString(), anyString(), any())).thenReturn(false);

        Jwt playerJwt = jwt("tw-player-001", List.of(Map.of("name", "player")));
        AbstractAuthenticationToken auth = authFor(playerJwt, "PLAYER");
        var ex = MockServerHttpRequest.get("/api/games/abbott-village/launch").build();
        MockServerWebExchange mwex = MockServerWebExchange.from(ex);
        filter.filter(new ExchangeWithPrincipal(mwex, auth), forwarded).block();

        assertThat(downstreamCalled).isFalse();
        assertThat(mwex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(mwex.getResponse().getHeaders().getFirst("X-Resource-Denied"))
            .isEqualTo("game:abbott-village");
    }

    @Test
    void playerWithDirectGrant_isForwarded() {
        when(authz.isGranted("game", "abbott-village", "tw-player-001")).thenReturn(true);

        Jwt playerJwt = jwt("tw-player-001", List.of(Map.of("name", "player")));
        AbstractAuthenticationToken auth = authFor(playerJwt, "PLAYER");
        var ex = MockServerHttpRequest.get("/api/games/abbott-village/launch").build();
        MockServerWebExchange mwex = MockServerWebExchange.from(ex);
        filter.filter(new ExchangeWithPrincipal(mwex, auth), forwarded).block();

        assertThat(downstreamCalled).isTrue();
    }

    @Test
    void playerWithRoleGrant_isForwarded() {
        when(authz.isGranted(anyString(), anyString(), anyString())).thenReturn(false);
        // All three arguments must be matchers — mixing raw values with
        // argThat(...) throws InvalidUseOfMatchersException and leaks a matcher
        // onto Mockito's thread-local stack, which then spuriously fails the
        // next test. Use eq(...) for the literals.
        when(authz.hasAnyRoleGrant(eq("game"), eq("abbott-village"),
                org.mockito.ArgumentMatchers.argThat(it -> {
                    if (it == null) return false;
                    for (String s : it) if ("PLAYER".equals(s)) return true;
                    return false;
                })))
            .thenReturn(true);

        Jwt playerJwt = jwt("tw-player-001", List.of(Map.of("name", "player")));
        AbstractAuthenticationToken auth = authFor(playerJwt, "PLAYER");
        var ex = MockServerHttpRequest.get("/api/games/abbott-village/launch").build();
        MockServerWebExchange mwex = MockServerWebExchange.from(ex);
        filter.filter(new ExchangeWithPrincipal(mwex, auth), forwarded).block();

        assertThat(downstreamCalled).isTrue();
    }

    // ── ROLE_GAMES floor for "game" tuples (games member + games admin screens
    //    contract, 2026-10-28) ──────────────────────────────────────────────────

    /** The games-member bug: a ROLE_GAMES holder asking for a game bundle the
     *  catalog offered them was 403'd with X-Resource-Denied: game:chess, because
     *  the per-slug grant tuples this filter consults have no writer. The
     *  network-wide games-access role IS the floor; zero grant lookups happen. */
    @Test
    void gamesRole_reachesGameBundle_withZeroGrants() {
        // No authz stubs at all: the floor must forward BEFORE any grant lookup.
        Jwt gamesJwt = jwt("e2e-gamesonly", List.of(Map.of("name", "ROLE_GAMES"), Map.of("name", "ROLE_USER")));
        AbstractAuthenticationToken auth = authFor(gamesJwt, "GAMES");
        var ex = MockServerHttpRequest.get("/_remotes/wasm-fragment/chess/index.html").build();
        MockServerWebExchange mwex = MockServerWebExchange.from(ex);
        filter.filter(new ExchangeWithPrincipal(mwex, auth), forwarded).block();

        assertThat(downstreamCalled).as("games member must reach the game bundle").isTrue();
        assertThat(mwex.getResponse().getStatusCode()).isNotEqualTo(HttpStatus.FORBIDDEN);
        assertThat(mwex.getResponse().getHeaders().getFirst("X-Resource-Denied")).isNull();
        Mockito.verifyNoInteractions(authz);
    }

    /** The floor also covers the /api/games/{slug}/… game tuple (launch), with
     *  the bare `games` claim spelling Casdoor's object shape may carry. */
    @Test
    void gamesRole_bareSpelling_reachesGameLaunch_withZeroGrants() {
        Jwt gamesJwt = jwt("e2e-gamesonly", List.of(Map.of("name", "games")));
        AbstractAuthenticationToken auth = authFor(gamesJwt, "GAMES");
        var ex = MockServerHttpRequest.post("/api/games/chess/launch").build();
        MockServerWebExchange mwex = MockServerWebExchange.from(ex);
        filter.filter(new ExchangeWithPrincipal(mwex, auth), forwarded).block();

        assertThat(downstreamCalled).isTrue();
        Mockito.verifyNoInteractions(authz);
    }

    /** A plain ROLE_USER holds no games access: still grant-gated, still 403 +
     *  the game:<slug> tuple in the header. */
    @Test
    void userRole_withoutGames_isStillRejected_onGameBundle() {
        when(authz.isGranted(anyString(), anyString(), anyString())).thenReturn(false);
        when(authz.hasAnyRoleGrant(anyString(), anyString(), any())).thenReturn(false);

        Jwt userJwt = jwt("e2e-user", List.of(Map.of("name", "ROLE_USER")));
        AbstractAuthenticationToken auth = authFor(userJwt);
        var ex = MockServerHttpRequest.get("/_remotes/wasm-fragment/chess/index.html").build();
        MockServerWebExchange mwex = MockServerWebExchange.from(ex);
        filter.filter(new ExchangeWithPrincipal(mwex, auth), forwarded).block();

        assertThat(downstreamCalled).isFalse();
        assertThat(mwex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(mwex.getResponse().getHeaders().getFirst("X-Resource-Denied"))
            .isEqualTo("game:chess");
    }

    /** The floor is scoped to the "game" resource type: a games member on a
     *  session tuple is still grant-gated (and denied without a grant). */
    @Test
    void gamesRole_onSessionTuple_isStillGrantGated() {
        when(authz.isGranted(anyString(), anyString(), anyString())).thenReturn(false);
        when(authz.hasAnyRoleGrant(anyString(), anyString(), any())).thenReturn(false);

        Jwt gamesJwt = jwt("e2e-gamesonly", List.of(Map.of("name", "ROLE_GAMES")));
        AbstractAuthenticationToken auth = authFor(gamesJwt, "GAMES");
        var ex = MockServerHttpRequest.get("/api/sessions/abc/state").build();
        MockServerWebExchange mwex = MockServerWebExchange.from(ex);
        filter.filter(new ExchangeWithPrincipal(mwex, auth), forwarded).block();

        assertThat(downstreamCalled).as("session tuples are NOT covered by the games floor").isFalse();
        assertThat(mwex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(mwex.getResponse().getHeaders().getFirst("X-Resource-Denied"))
            .isEqualTo("session:abc");
        Mockito.verify(authz).isGranted("session", "abc", "e2e-gamesonly");
    }

    /** ...and a games member WITH a session grant is forwarded through the
     *  unchanged grant path. */
    @Test
    void gamesRole_onSessionTuple_withGrant_isForwarded() {
        when(authz.isGranted("session", "abc", "e2e-gamesonly")).thenReturn(true);

        Jwt gamesJwt = jwt("e2e-gamesonly", List.of(Map.of("name", "ROLE_GAMES")));
        AbstractAuthenticationToken auth = authFor(gamesJwt, "GAMES");
        var ex = MockServerHttpRequest.get("/api/sessions/abc/state").build();
        MockServerWebExchange mwex = MockServerWebExchange.from(ex);
        filter.filter(new ExchangeWithPrincipal(mwex, auth), forwarded).block();

        assertThat(downstreamCalled).isTrue();
    }

    /** Admin on a game bundle: unchanged — the admin bypass still fires first,
     *  with zero grant lookups. */
    @Test
    void adminRole_onGameBundle_unchanged_bypassesWithZeroGrants() {
        Jwt adminJwt = jwt("e2e-adminonly", List.of(Map.of("name", "ROLE_ADMIN")));
        AbstractAuthenticationToken auth = authFor(adminJwt, "ADMIN");
        var ex = MockServerHttpRequest.get("/_remotes/wasm-fragment/chess/index.html").build();
        MockServerWebExchange mwex = MockServerWebExchange.from(ex);
        filter.filter(new ExchangeWithPrincipal(mwex, auth), forwarded).block();

        assertThat(downstreamCalled).isTrue();
        Mockito.verifyNoInteractions(authz);
    }

    @Test
    void nonResourcePath_isForwardedWithoutCheck() {
        Jwt playerJwt = jwt("tw-player-001", List.of(Map.of("name", "player")));
        AbstractAuthenticationToken auth = authFor(playerJwt, "PLAYER");
        var ex = MockServerHttpRequest.get("/api/catalog").build();
        MockServerWebExchange mwex = MockServerWebExchange.from(ex);
        filter.filter(new ExchangeWithPrincipal(mwex, auth), forwarded).block();

        assertThat(downstreamCalled).isTrue();
        Mockito.verifyNoInteractions(authz);
    }

    /**
     * Thin wrapper that populates {@code getPrincipal()} on a
     * MockServerWebExchange — Spring's mock infrastructure leaves it
     * as an empty Mono otherwise, so the filter's
     * {@code exchange.getPrincipal()} call returns {@code empty}.
     */
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
