package net.hugmesh.gateway.filter;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.gateway.testsupport.TestIssuer;

import java.net.URI;
import java.util.List;

/**
 * END-TO-END keystone for the raw-path route-access bypass: the route-access table is
 * keyed on the DECODED spelling ({@code /bff/mesh/internal/**}) but
 * {@link GatewayRouteAccessFilter} used to match the RAW percent-encoded request path,
 * so {@code /bff/mesh/%69nternal/x} matched no row (NO_RULE, which forwards any
 * authenticated caller) while the router still decoded it and reached the same
 * handler. Same recipe as {@link FeInternalIngestDenyAuthzSpringBootTest}: real RSA
 * JWTs, the full production filter chain, the baked {@code CanonicalSeed.fe()} rules.
 *
 * <p>Every request is sent through a pre-encoded {@link URI}: the template overloads
 * of {@code WebTestClient#uri} would re-encode the {@code %} and silently test a
 * different path.
 *
 * <p>The probe controller answers 200 for the DECODED spellings, exactly as the real
 * router does, so a forwarded encoded request is an unambiguous 200 (the exploit).
 */
@SpringBootTest(properties = {"spring.application.name=hugmesh-fe-gateway"})
@AutoConfigureWebTestClient
class FeRouteAccessEncodedPathSpringBootTest {

    private static final TestIssuer BRAND_X = new TestIssuer();

    @AfterAll
    static void stopIssuers() {
        BRAND_X.close();
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("app.tenancy.issuers", () -> BRAND_X.issuerUri() + "=brandx");
        registry.add("app.tenancy.hosts", () -> "brandx.example=brandx");
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", BRAND_X::issuerUri);
        registry.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri",
                () -> BRAND_X.issuerUri() + "/.well-known/jwks.json");
        registry.add("app.route-access.enabled", () -> "true");
        registry.add("app.revocation.enabled", () -> "false");
        registry.add("app.url-registry.enabled", () -> "false");
        registry.add("app.resource-access.enabled", () -> "false");
        registry.add("spring.autoconfigure.exclude", () ->
                "org.springframework.boot.cassandra.autoconfigure.CassandraAutoConfiguration,"
                        + "org.springframework.boot.data.cassandra.autoconfigure.DataCassandraAutoConfiguration,"
                        + "org.springframework.boot.data.cassandra.autoconfigure.DataCassandraReactiveAutoConfiguration");
    }

    @Autowired
    WebTestClient http;

    private WebTestClient.ResponseSpec get(String rawPath, List<String> roles) {
        return http.get().uri(URI.create(rawPath))
                .header(HttpHeaders.HOST, "brandx.example")
                .header("Authorization", "Bearer " + BRAND_X.mint("some-user", roles))
                .exchange();
    }

    private void assertRouteDenied(String rawPath, List<String> roles) {
        get(rawPath, roles).expectStatus().isForbidden()
                .expectHeader().exists("X-Route-Denied");
    }

    /** The spelling is refused by SOME layer (Spring Security's strict firewall answers 400
     *  for dot segments and semicolons before route-access runs; route-access answers 403):
     *  either way it must never reach the handler. The filter's own handling of the same
     *  spellings is pinned without the firewall in GatewayRouteAccessFilterEncodedPathTest. */
    private void assertNeverForwarded(String rawPath, List<String> roles) {
        get(rawPath, roles).expectStatus().is4xxClientError();
    }

    private void assertRefusedAsAmbiguous(String rawPath, List<String> roles) {
        get(rawPath, roles).expectStatus().isBadRequest()
                .expectHeader().doesNotExist("X-Route-Denied");
    }

    // ── the plain forms are denied (the baseline every spelling below must equal) ──

    @Test
    void plainForms_areDenied() {
        assertRouteDenied("/bff/mesh/internal/bridge-sync", List.of("user"));
        assertRouteDenied("/bff/user/internal/mesh-devices", List.of("user"));
        assertRouteDenied("/bff/internal/session/introspect", List.of("user"));
        assertRouteDenied("/bff/superadmin/anything", List.of("user"));
    }

    // ── percent-encoding: EXPLOIT, red on the raw-path match ─────────────────────

    @Test
    void denyRow_percentEncodedSegment_isDeniedLikeThePlainForm() {
        assertRouteDenied("/bff/mesh/%69nternal/bridge-sync", List.of("user"));      // %69 = i
        assertRouteDenied("/bff/%6Desh/internal/bridge-sync", List.of("user"));      // %6D = m
        assertRouteDenied("/bff/mesh/internal/%62ridge-sync", List.of("user"));      // under the row
        assertRouteDenied("/bff/user/%69nternal/mesh-devices", List.of("user"));
        assertRouteDenied("/bff/%69nternal/session/introspect", List.of("user"));
    }

    @Test
    void denyRow_lowercaseHexEscape_isDeniedToo() {
        assertRouteDenied("/bff/%6desh/internal/bridge-sync", List.of("user"));
    }

    @Test
    void roleGatedRow_percentEncodedSegment_isDeniedLikeThePlainForm() {
        // /bff/superadmin/** is ROLE_SUPERADMIN: an ordinary user is denied plain AND encoded.
        assertRouteDenied("/bff/%73uperadmin/anything", List.of("user"));            // %73 = s
        // /social/matrix/** needs ROLE_MATRIX (or MOD): a plain user is denied encoded too.
        assertRouteDenied("/social/matrix/rooms", List.of("user"));
        assertRouteDenied("/social/%6Datrix/rooms", List.of("user"));
        assertRouteDenied("/%73ocial/matrix/rooms", List.of("user"));
    }

    @Test
    void entirePathEncoded_isDeniedLikeThePlainForm() {
        assertRouteDenied("/%62%66%66/%6d%65%73%68/%69%6e%74%65%72%6e%61%6c/bridge-sync", List.of("user"));
    }

    // ── other spellings of the same path ─────────────────────────────────────────

    @Test
    void dotSegments_resolveBeforeTheMatch() {
        assertNeverForwarded("/bff/mesh/x/../internal/bridge-sync", List.of("user"));
        assertNeverForwarded("/bff/mesh/./internal/bridge-sync", List.of("user"));
        assertNeverForwarded("/bff/mesh/x/%2e%2e/internal/bridge-sync", List.of("user"));
        assertNeverForwarded("/bff/mesh/x/%2E%2E/internal/bridge-sync", List.of("user"));
        assertNeverForwarded("/bff/mesh/..;/mesh/internal/bridge-sync", List.of("user"));
    }

    @Test
    void repeatedSlashes_collapseBeforeTheMatch() {
        assertNeverForwarded("/bff//mesh///internal/bridge-sync", List.of("user"));
    }

    @Test
    void trailingSlash_isDeniedLikeThePlainForm() {
        assertRouteDenied("/bff/mesh/internal/", List.of("user"));
        assertRouteDenied("/bff/mesh/internal/bridge-sync/", List.of("user"));
    }

    @Test
    void semicolonPathParameters_areIgnoredLikeTheRouterDoes() {
        assertNeverForwarded("/bff/mesh/internal;a=b/bridge-sync", List.of("user"));
        assertNeverForwarded("/bff/mesh;x=1/internal/bridge-sync", List.of("user"));
        assertNeverForwarded("/bff/mesh/internal/bridge-sync;jsessionid=1", List.of("user"));
    }

    // ── ambiguous paths are refused outright (fail closed) ───────────────────────

    @Test
    void doubleEncoding_isRefused() {
        assertRefusedAsAmbiguous("/bff/mesh/%2569nternal/bridge-sync", List.of("user"));
    }

    @Test
    void encodedSlashAndBackslash_areRefused() {
        assertRefusedAsAmbiguous("/bff/mesh%2Finternal/bridge-sync", List.of("user"));
        assertRefusedAsAmbiguous("/bff/mesh%2finternal/bridge-sync", List.of("user"));
        assertRefusedAsAmbiguous("/bff/mesh%5Cinternal/bridge-sync", List.of("user"));
        assertRefusedAsAmbiguous("/bff/mesh%5cinternal/bridge-sync", List.of("user"));
    }

    @Test
    void nulAndControlCharacters_areRefused() {
        assertRefusedAsAmbiguous("/bff/mesh/internal%00/bridge-sync", List.of("user"));
        assertRefusedAsAmbiguous("/bff/mesh/internal%0d%0a/bridge-sync", List.of("user"));
    }

    @Test
    void invalidUtf8_isRefused() {
        assertRefusedAsAmbiguous("/bff/mesh/internal%c3/bridge-sync", List.of("user"));
    }

    @Test
    void climbingAboveTheRoot_isRefused() {
        assertRefusedAsAmbiguous("/../bff/mesh/internal/bridge-sync", List.of("user"));
    }

    // ── controls: the fix is not a blanket lockdown ──────────────────────────────

    @Test
    void benignEncodedSibling_isStillForwarded() {
        get("/bff/user/pro%66ile", List.of("user")).expectStatus().isOk()
                .expectHeader().doesNotExist("X-Route-Denied");
        get("/bff/user/profile", List.of("user")).expectStatus().isOk();
        get("/bff/mesh/rooms/%21abc%3Aserver", List.of("user", "mesh")).expectStatus().isOk();
    }

    @Test
    void sameDomainAdmin_stillBypasses_encodedOrNot() {
        get("/bff/mesh/%69nternal/bridge-sync", List.of("admin")).expectStatus().isOk();
    }

    @TestConfiguration
    static class ProbeConfig {
        @Bean
        ProbeController probeController() {
            return new ProbeController();
        }
    }

    @RestController
    static class ProbeController {
        @GetMapping({
                "/bff/user/internal/mesh-devices",
                "/bff/mesh/internal/bridge-sync",
                "/bff/mesh/internal/{rest}",
                "/bff/internal/session/introspect",
                "/bff/superadmin/{rest}",
                "/social/matrix/rooms",
                "/bff/user/profile",
                "/bff/mesh/rooms/{id}",
        })
        Mono<ResponseEntity<Void>> probe() {
            return Mono.just(ResponseEntity.ok().build());
        }
    }
}
