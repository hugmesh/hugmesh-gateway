package systems.hugmesh.gateway.filter;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Trust-boundary contract for {@link ExternalAuthHeaderFilter}.
 *
 * <p>The canonical {@code External-Authorization} / {@code External-Auth-Provider}
 * / {@code External-Auth-Id} headers are stamped by the gateway and trusted by
 * downstream services as a normalized external OAuth identity. The client-supplied
 * {@code X-External-Token} / {@code X-External-Provider} request headers (and any
 * direct copies of the canonical output names) MUST never be forwarded unless they
 * are cryptographically bound to the validated Casdoor JWT. These tests prove the
 * forgery holes are closed:
 *
 * <ul>
 *   <li>Unauthenticated request with forged X-External-* → stripped, not forwarded.</li>
 *   <li>Authenticated request whose JWT was NOT minted via an external provider,
 *       but with forged X-External-* → stripped (header cannot stand on its own).</li>
 *   <li>Authenticated request whose X-External-Provider DISAGREES with the JWT's
 *       identityProvider claim → forged token dropped, only the validated claim
 *       identity is forwarded.</li>
 *   <li>Authenticated request whose X-External-Provider MATCHES the JWT claim →
 *       the (now-bound) token is forwarded as External-Authorization.</li>
 *   <li>A client trying to inject the canonical External-Authorization /
 *       External-Auth-Id output headers directly → stripped / overwritten with the
 *       gateway-derived values only.</li>
 * </ul>
 */
class ExternalAuthHeaderFilterTest {

    private final ExternalAuthHeaderFilter filter = new ExternalAuthHeaderFilter();

    // ── helpers ───────────────────────────────────────────────────────────────

    private static Jwt jwt(String sub, String identityProvider, String identityProviderUserId) {
        Jwt.Builder b = Jwt.withTokenValue("test")
                .header("alg", "none")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .subject(sub)
                .claim("name", sub);
        if (identityProvider != null) b.claim("identityProvider", identityProvider);
        if (identityProviderUserId != null) b.claim("identityProviderUserId", identityProviderUserId);
        return b.build();
    }

    private static AbstractAuthenticationToken authFor(Jwt jwt) {
        var authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        return new JwtAuthenticationToken(jwt, authorities);
    }

    /** Recording chain that captures the request HEADERS the downstream would see. */
    private static final class CapturingChain implements WebFilterChain {
        final AtomicReference<HttpHeaders> seen = new AtomicReference<>();
        @Override public Mono<Void> filter(ServerWebExchange exchange) {
            seen.set(exchange.getRequest().getHeaders());
            return Mono.empty();
        }
    }

    /** Populates getPrincipal() on a MockServerWebExchange (mock leaves it empty). */
    private static ServerWebExchange withPrincipal(ServerWebExchange delegate,
                                                   java.security.Principal principal) {
        return new org.springframework.web.server.ServerWebExchangeDecorator(delegate) {
            @Override
            @SuppressWarnings("unchecked")
            public <T extends java.security.Principal> Mono<T> getPrincipal() {
                return principal == null ? Mono.empty() : Mono.just((T) principal);
            }
        };
    }

    private HttpHeaders runForged(java.security.Principal principal) {
        return runForged(principal, "X-External-Provider", "github");
    }

    private HttpHeaders runForged(java.security.Principal principal,
                                  String providerHeaderName, String providerHeaderValue) {
        MockServerHttpRequest req = MockServerHttpRequest.get("/api/games/x/launch")
                .header("X-External-Token", "ATTACKER-TOKEN")
                .header(providerHeaderName, providerHeaderValue)
                .build();
        MockServerWebExchange mwex = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();
        filter.filter(withPrincipal(mwex, principal), chain).block();
        assertThat(chain.seen.get()).as("downstream must be reached").isNotNull();
        return chain.seen.get();
    }

    // ── unauthenticated forgery ─────────────────────────────────────────────────

    @Test
    void unauthenticated_forgedHeaders_areStripped_notForwarded() {
        HttpHeaders downstream = runForged(null);

        // No JWT to bind to → the inbound X-* AND any canonical External-* are dropped.
        assertThat(downstream.getFirst("External-Authorization")).isNull();
        assertThat(downstream.getFirst("External-Auth-Provider")).isNull();
        assertThat(downstream.getFirst("External-Auth-Id")).isNull();
        assertThat(downstream.getFirst("X-External-Token")).isNull();
        assertThat(downstream.getFirst("X-External-Provider")).isNull();
    }

    // ── authenticated, but JWT not minted via an external provider ──────────────

    @Test
    void authenticatedInternalOnly_forgedHeaders_areStripped() {
        // JWT has NO identityProvider claim (pure internal Casdoor login). A forged
        // X-External-Token must NOT be promoted to External-Authorization.
        var auth = authFor(jwt("casdoor-internal-1", null, null));
        HttpHeaders downstream = runForged(auth);

        assertThat(downstream.getFirst("External-Authorization")).isNull();
        assertThat(downstream.getFirst("External-Auth-Provider")).isNull();
        assertThat(downstream.getFirst("External-Auth-Id")).isNull();
        assertThat(downstream.getFirst("X-External-Token")).isNull();
        assertThat(downstream.getFirst("X-External-Provider")).isNull();
    }

    // ── authenticated, provider MISMATCH → forged token dropped ─────────────────

    @Test
    void providerMismatch_forgedTokenDropped_onlyValidatedClaimForwarded() {
        // JWT was minted via google; attacker claims github + an attacker token.
        var auth = authFor(jwt("casdoor-2", "google", "google-uid-9"));
        HttpHeaders downstream = runForged(auth, "X-External-Provider", "github");

        // The attacker token is NOT forwarded (mismatch → unbound).
        assertThat(downstream.getFirst("External-Authorization")).isNull();
        // Provider/id come from the VALIDATED claim, never the forged header.
        assertThat(downstream.getFirst("External-Auth-Provider")).isEqualTo("google");
        assertThat(downstream.getFirst("External-Auth-Id")).isEqualTo("google-uid-9");
        // Raw client headers never leak downstream.
        assertThat(downstream.getFirst("X-External-Token")).isNull();
        assertThat(downstream.getFirst("X-External-Provider")).isNull();
    }

    // ── authenticated, provider MATCH → token is bound + forwarded ──────────────

    @Test
    void providerMatch_boundTokenForwarded() {
        // JWT identityProvider == github (case-insensitive match with "GitHub").
        var auth = authFor(jwt("casdoor-3", "github", "gh-uid-7"));
        HttpHeaders downstream = runForged(auth, "X-External-Provider", "GitHub");

        // Now the supplied token IS bound to the validated github identity → forwarded.
        assertThat(downstream.getFirst("External-Authorization")).isEqualTo("ATTACKER-TOKEN");
        assertThat(downstream.getFirst("External-Auth-Provider")).isEqualTo("github");
        assertThat(downstream.getFirst("External-Auth-Id")).isEqualTo("gh-uid-7");
        assertThat(downstream.getFirst("X-External-Token")).isNull();
        assertThat(downstream.getFirst("X-External-Provider")).isNull();
    }

    // ── direct injection of the canonical output headers ────────────────────────

    @Test
    void directlyInjectedCanonicalHeaders_areOverwrittenWithGatewayValues() {
        // Attacker (authenticated as themselves via github) tries to inject the
        // canonical External-Auth-Id pointing at a VICTIM's external account.
        var auth = authFor(jwt("casdoor-4", "github", "attacker-gh-uid"));
        MockServerHttpRequest req = MockServerHttpRequest.get("/api/games/x/launch")
                .header("External-Authorization", "VICTIM-TOKEN")
                .header("External-Auth-Provider", "github")
                .header("External-Auth-Id", "VICTIM-gh-uid")
                .build();
        MockServerWebExchange mwex = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();
        filter.filter(withPrincipal(mwex, auth), chain).block();
        HttpHeaders downstream = chain.seen.get();

        assertThat(downstream).isNotNull();
        // Identity is the gateway-derived (validated-claim) identity, NOT the
        // attacker-injected victim values. No external token is forwarded because
        // none was supplied via the bound X-* channel.
        assertThat(downstream.getFirst("External-Auth-Id")).isEqualTo("attacker-gh-uid");
        assertThat(downstream.getFirst("External-Authorization")).isNull();
        assertThat(downstream.getFirst("External-Auth-Provider")).isEqualTo("github");
    }

    @Test
    void unauthenticated_directlyInjectedCanonicalHeaders_areStripped() {
        MockServerHttpRequest req = MockServerHttpRequest.get("/api/games/x/launch")
                .header("External-Authorization", "VICTIM-TOKEN")
                .header("External-Auth-Provider", "github")
                .header("External-Auth-Id", "VICTIM-gh-uid")
                .build();
        MockServerWebExchange mwex = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();
        filter.filter(withPrincipal(mwex, null), chain).block();
        HttpHeaders downstream = chain.seen.get();

        assertThat(downstream).isNotNull();
        assertThat(downstream.getFirst("External-Authorization")).isNull();
        assertThat(downstream.getFirst("External-Auth-Provider")).isNull();
        assertThat(downstream.getFirst("External-Auth-Id")).isNull();
    }
}
