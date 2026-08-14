package net.hugmesh.gateway.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;
import net.hugmesh.gateway.cache.RevocationListService;
import net.hugmesh.gateway.cache.RevocationListService.HsToken;
import net.hugmesh.gateway.filter.HomeserverTokenRevocationFilter; // assembled into the chain under test
import net.hugmesh.gateway.security.DomainRegistry;
import net.hugmesh.gateway.testsupport.TestIssuer;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * TIER-1 ASSEMBLED-CHAIN slice for the HOMESERVER-token passthrough + revocation
 * surface — wiring the REAL {@link SecurityConfig#filterChain} (the {@code permitAll}
 * homeserver passthrough + the {@code authorizeExchange} floor + the multi-issuer
 * resource server) TOGETHER WITH the REAL {@link HomeserverTokenRevocationFilter}
 * (order 11) in front of a downstream-hit oracle, via the shared
 * {@link SecuritySliceSupport} harness.
 *
 * <p><b>Why this slice exists (the gap it closes).</b> The JWT-revocation control is
 * proven end-to-end through {@code SecurityConfig.filterChain} by
 * {@code GatewayDenyChainSliceTest}. The HS-token control on the OPAQUE-bearer
 * channel (Matrix {@code access_token} / Mastodon OAuth token) was tested ONLY in
 * isolation ({@code HomeserverTokenRevocationFilterTest}) against a bare
 * {@code MockServerWebExchange} — NEVER through the assembled chain. No existing test
 * sends an opaque (non-JWT) bearer to a {@code permitAll} homeserver path through the
 * real {@link SecurityConfig}. This slice closes that gap and, in doing so, surfaces a
 * documented behaviour (see the FINDING below) about how the resource-server bearer
 * filter treats a present-but-non-JWT bearer on a {@code permitAll} path.
 *
 * <p><b>Mutation-resistant oracle.</b> The downstream {@link DownstreamEchoController}
 * is reached ONLY if the whole chain forwards; every "reaches downstream" assertion
 * keys off {@code downstreamHits()}, and every "blocked" assertion pairs the rejected
 * status with {@code downstreamHits() == 0} — a fail-OPEN would forward and bump the
 * counter, failing loudly rather than passing vacuously.
 *
 * <p><b>★ FINDING (documented, NOT fixed here — a shared-gateway behaviour change
 * needs separate review).</b> {@code SecurityConfig.HOMESERVER_PASSTHROUGH_PATHS}
 * are {@code permitAll} expressly so an opaque Matrix/Mastodon bearer is not 401'd at
 * the OAuth2 resource-server layer (per the class Javadoc + README: "requiring a JWT
 * here would 401 every homeserver request"). This slice shows that, on the
 * MULTI-ISSUER resolver path, a request to such a {@code permitAll} path that CARRIES
 * an {@code Authorization: Bearer <opaque>} header is nonetheless rejected
 * {@code 401} by the resource-server authentication filter — BEFORE the
 * {@code authorizeExchange} permitAll decision and BEFORE the
 * {@link HomeserverTokenRevocationFilter} ever runs. {@code permitAll} suppresses the
 * AUTHORIZATION check, not the AUTHENTICATION of a presented credential: the bearer
 * filter tries to resolve the token's {@code iss} to a per-issuer manager, the opaque
 * token is not a parseable JWT, and that authentication failure surfaces as 401. The
 * no-credential case (and discovery without a bearer) is unaffected and reaches
 * downstream. The tests below PIN this current behaviour so any future change (a fix
 * that lets opaque bearers reach the HS-revocation gate, or a regression in the other
 * direction) is caught. See the PR description for the full finding + the suggested
 * follow-up (a full-context {@code @SpringBootTest} to confirm the assembled-runtime
 * behaviour matches this slice, then — if confirmed — a reviewed gateway change so the
 * HS-revocation filter, not a blanket 401, adjudicates opaque homeserver bearers).
 *
 * <p>TEST-ONLY: no production code changes; no secrets; no network beyond the
 * in-process {@link TestIssuer} JWKS servers (the multi-issuer decoder seam the
 * existing slices use).
 */
class HomeserverRevocationAssembledChainSliceTest extends SecuritySliceSupport {

    /** An opaque bearer the gateway has a mint record for (resolves to an HsToken). */
    private static final String BROKERED = "brokered-bearer-token";
    /** An opaque bearer the gateway has NEVER recorded a mint for. */
    private static final String NEVER_MINTED = "never-minted-bearer-token";

    private DownstreamEchoController echo;
    // Two trusted issuers so isMultiIssuer() holds and SecurityConfig takes the
    // per-issuer resolver path (the no-network decoder seam the existing slices use),
    // avoiding the single-issuer o.jwt(...) path that needs an auto-configured
    // jwtDecoder bean a slice doesn't have. The opaque homeserver bearers are never
    // JWT-decoded successfully — the issuers are pure scaffolding for the chain wiring.
    private TestIssuer brandX;
    private TestIssuer brandY;

    @BeforeEach
    void setUp() {
        echo = new DownstreamEchoController();
        brandX = new TestIssuer();
        brandY = new TestIssuer();
    }

    @AfterEach
    void tearDown() {
        brandX.close();
        brandY.close();
    }

    /** A multi-issuer registry (brandX + brandY trusted) so SecurityConfig takes the
     *  per-issuer resolver path — the production wiring for a multi-brand gateway. */
    private DomainRegistry multiIssuerRegistry() {
        String issuers = brandX.issuerUri() + "=brandx," + brandY.issuerUri() + "=brandy";
        DomainRegistry registry = new DomainRegistry(brandX.issuerUri(), issuers, "");
        assertThat(registry.isMultiIssuer())
                .as("two trusted issuers => multi-issuer mode (the resolver swap is taken)").isTrue();
        return registry;
    }

    /** A revocation service (no live Cassandra) primed with the given revoked keys and
     *  hs_tokens registry — exactly what the poll would mirror from Cassandra. */
    private static RevocationListService revocations(Set<String> revoked, Map<String, HsToken> tokens) {
        RevocationListService svc = new RevocationListService(null, true);
        svc.primeRevokedForTest(revoked);
        svc.primeHsTokensForTest(tokens);
        return svc;
    }

    /** Assemble the WebTestClient through the production chain: the REAL
     *  {@link SecurityConfig#filterChain} (permitAll homeserver passthrough +
     *  authenticated() floor + multi-issuer resource server) FIRST, then the REAL
     *  HS-revocation filter (enabled), in front of the echo controller. Uses the REAL
     *  per-issuer resolver (built exactly as {@link TenancyResourceServerConfig}
     *  contributes it). */
    private WebTestClient client(RevocationListService revocations) {
        DomainRegistry registry = multiIssuerRegistry();
        TenancyResourceServerConfig tenancy = new TenancyResourceServerConfig(registry, "", "");
        List<WebFilter> gatewayFilters = List.of(
                new HomeserverTokenRevocationFilter(revocations, /* enabled */ true));
        return sliceClientWithGatewayFilters(
                registry, provider(tenancy.tenantAuthManagerResolver()), gatewayFilters, echo);
    }

    private int downstreamHits() {
        return echo.hits.get();
    }

    // ── PUBLIC-SURFACE ALLOW — no-credential passthrough works end-to-end ───────
    // These are the clean, unambiguous positive controls: with NO Authorization
    // header the permitAll homeserver paths reach downstream through the FULL chain,
    // so the passthrough surface itself is correctly open (the design's headline).

    @Test
    void homeserverPath_noBearer_reachesDownstream_throughAssembledChain() {
        // A homeserver request with NO bearer (a client mid-discovery, or our UI
        // proxying an as-yet-unauthenticated call) is permitAll at the resource-server
        // layer, not adjudicated by the HS-revocation filter (no bearer to resolve),
        // and reaches downstream. This is the property HOMESERVER_PASSTHROUGH_PATHS
        // exists to guarantee.
        RevocationListService svc = revocations(Set.of("hs:matrix:alice"), Map.of());
        WebTestClient client = client(svc);

        client.get().uri("/_matrix/client/v3/sync")
                .exchange()
                .expectStatus().isOk();

        assertThat(downstreamHits())
                .as("a no-bearer homeserver request flows through the permitAll passthrough")
                .isEqualTo(1);
    }

    @Test
    void discoverySurface_noBearer_reachesDownstream_throughAssembledChain() {
        // The discovery exemption with NO Authorization header — the anonymous
        // first-run bootstrap case. A regression that made these paths require auth
        // (dropping them from HOMESERVER_PASSTHROUGH_PATHS) would 401 here.
        RevocationListService svc = revocations(Set.of(), Map.of());
        WebTestClient client = client(svc);

        for (String path : List.of("/_matrix/client/versions", "/.well-known/matrix/client")) {
            int before = downstreamHits();
            client.get().uri(path)
                    .exchange()
                    .expectStatus().isOk();
            assertThat(downstreamHits())
                    .as("discovery path %s reaches downstream anonymously", path)
                    .isEqualTo(before + 1);
        }
    }

    // ── ★ FINDING PIN — opaque bearer on a permitAll path is 401'd by the RS ────
    // The current ASSEMBLED-CHAIN behaviour (see the class-level FINDING): a present,
    // non-JWT bearer on a permitAll homeserver path is rejected 401 at the
    // resource-server authentication filter, BEFORE the HS-revocation filter runs and
    // BEFORE the downstream surface is reached. We PIN it (not as an endorsement, but
    // so the behaviour is visible + change-detected) and assert the request never
    // reaches downstream either way. The expected security INTENT — a revoked opaque
    // bearer is 403'd by the HS-revocation filter, an unrevoked one forwarded — is
    // proven at the filter level by HomeserverTokenRevocationFilterTest; this pin
    // documents the gap between that filter-level intent and the assembled-chain reality.

    @Test
    void findingPin_opaqueBearer_onPermitAllHomeserverPath_is401AtResourceServer_notReachingHsFilterNorDownstream() {
        // A "brokered" opaque bearer the gateway HAS a mint record for and which is NOT
        // revoked — at the filter level (HomeserverTokenRevocationFilterTest) this
        // FORWARDS. Through the assembled chain it is instead 401'd by the
        // resource-server bearer filter (the opaque token is not a parseable JWT, so
        // the per-issuer resolver cannot authenticate it; permitAll does not suppress
        // that authentication attempt). The downstream surface is NOT reached.
        RevocationListService svc = revocations(
                Set.of(),
                Map.of(/* hash(BROKERED) -> ... */)); // contents irrelevant: RS rejects before the HS filter
        WebTestClient client = client(svc);

        client.get().uri("/_matrix/client/v3/sync")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + BROKERED)
                .exchange()
                // ★ CURRENT behaviour: 401 from the resource server, NOT the 403/200
                // the filter-level intent would produce. Pinned so a change is caught.
                .expectStatus().isUnauthorized();

        assertThat(downstreamHits())
                .as("the opaque bearer is stopped before downstream (whether by the RS 401 "
                        + "today or, after the documented follow-up, by the HS-revocation gate)")
                .isZero();
    }

    @Test
    void findingPin_unrecognizedOpaqueBearer_onGatedPath_is401AtResourceServer_notReachingDownstream() {
        // The same RS-level 401 for an unrecognized opaque bearer. At the filter level
        // this is the FAIL-CLOSED 403 path (unknown token on a gated path); through the
        // assembled chain the resource-server 401 pre-empts it. Either way the request
        // never reaches the homeserver surface — the security outcome (blocked) holds,
        // only the status code + the deciding layer differ from the filter-level intent.
        RevocationListService svc = revocations(Set.of(), Map.of());
        WebTestClient client = client(svc);

        client.get().uri("/api/v1/timelines/home")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + NEVER_MINTED)
                .exchange()
                .expectStatus().isUnauthorized();

        assertThat(downstreamHits())
                .as("an unrecognized opaque bearer never reaches downstream").isZero();
    }

    @Test
    void findingPin_discoverySurface_withOpaqueBearer_is401AtResourceServer() {
        // EVEN the discovery exemption — which the HS-revocation filter explicitly lets
        // through regardless of token — is 401'd at the assembled chain when an opaque
        // bearer is PRESENT, because the resource-server filter authenticates the
        // presented bearer before the request reaches the (discovery-exempting) HS
        // filter. Contrast discoverySurface_noBearer_* above (200). This sharpens the
        // finding: the 401 is purely a function of a present non-JWT bearer, not of the
        // path. A real first-run Element/Tusky client probing /_matrix/client/versions
        // WITH a stale token in its header would hit this.
        RevocationListService svc = revocations(Set.of(), Map.of());
        WebTestClient client = client(svc);

        client.get().uri("/_matrix/client/versions")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + NEVER_MINTED)
                .exchange()
                .expectStatus().isUnauthorized();

        assertThat(downstreamHits())
                .as("a present opaque bearer 401s even on the discovery surface (RS authenticates "
                        + "the credential before the discovery exemption is consulted)").isZero();
    }

    /**
     * The downstream homeserver surface. Reached ONLY if the full assembled chain
     * forwards; the blocked tests assert {@link #hits} stays 0. Mirrors the
     * {@code GatewayDenyChainSliceTest} oracle — here the "DB re-read" is the hit
     * counter on the homeserver passthrough paths.
     */
    @RestController
    @RequestMapping
    static class DownstreamEchoController {
        final AtomicInteger hits = new AtomicInteger(0);

        @GetMapping({
                "/_matrix/client/v3/sync",
                "/_matrix/client/versions",
                "/.well-known/matrix/client",
                "/api/v1/timelines/home",
        })
        Mono<String> getEcho() {
            hits.incrementAndGet();
            return Mono.just("REACHED");
        }
    }
}
