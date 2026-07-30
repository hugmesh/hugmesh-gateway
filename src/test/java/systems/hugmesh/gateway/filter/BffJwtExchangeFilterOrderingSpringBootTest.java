package systems.hugmesh.gateway.filter;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.mock.http.client.reactive.MockClientHttpRequest;
import org.springframework.mock.http.client.reactive.MockClientHttpResponse;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import systems.hugmesh.gateway.testsupport.TestIssuer;

import java.util.List;

/**
 * END-TO-END ordering keystone for {@link BffJwtExchangeWebFilter} — the MIRROR of
 * {@link PrincipalFilterChainOrderingSpringBootTest}, but for the LONE pre-security
 * filter. It drives a real {@code bff_} bearer through the FULL production filter
 * chain ({@code WebHttpHandlerBuilder}-merged) and proves the swap fires BEFORE Spring
 * Security's {@code WebFilterChainProxy(-100)}.
 *
 * <p><b>Why ordering is the whole point.</b> The OAuth2 resource server's JWT decoder
 * (inside {@code WebFilterChainProxy} at order {@code -100}) CANNOT validate an opaque
 * {@code bff_} value. If this filter ran at a POSITIVE order (like its principal-reading
 * siblings) the decoder would 401 the {@code bff_} BEFORE the swap ever happened — the
 * SSO bridge would be silently broken. So the filter sits at
 * {@code Ordered.HIGHEST_PRECEDENCE + 5}, BEFORE {@code -100}. This boot pins the
 * ALLOW half: the stub admin-bff swaps the {@code bff_} for a REAL RSA-signed custody
 * JWT, the filter rewrites Authorization BEFORE the decoder runs, the decoder validates
 * the custody JWT, and the request reaches the local probe handler (200). PRE-FIX (a
 * positive order) the decoder rejects the raw {@code bff_} first → not 200. The
 * fail-CLOSED 401 half of the contract is pinned end-to-end by
 * {@link BffJwtExchangeFailClosedOrderingSpringBootTest} (a separate boot whose stub
 * admin-bff refuses) and exhaustively at the unit level by
 * {@link BffJwtExchangeWebFilterTest}.
 *
 * <p>The production {@link systems.hugmesh.gateway.config.BffJwtExchangeConfig}
 * WebClient is replaced by a {@code @Primary} in-process stub (an {@code exchangeFunction},
 * no socket) so the test exercises the GENUINE production filter wiring + ordering,
 * deterministically, without a live admin-bff.
 */
@SpringBootTest(properties = {
        "spring.application.name=hugmesh-be-gateway",
        "spring.main.allow-bean-definition-overriding=true",
})
@AutoConfigureWebTestClient
class BffJwtExchangeFilterOrderingSpringBootTest {

    /** The issuer that mints the custody JWT the swap returns — it is the gateway's
     *  OWN resource-server issuer here, so the swapped-in JWT validates. */
    private static final TestIssuer ISSUER = new TestIssuer();

    @AfterAll
    static void stop() {
        ISSUER.close();
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        // The resource server validates the custody JWT against ISSUER's JWKS.
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", ISSUER::issuerUri);
        registry.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri",
                () -> ISSUER.issuerUri() + "/.well-known/jwks.json");
        // Enable the bff-exchange seam (the filter bean activates); the WebClient it
        // depends on is replaced by the @Primary minting stub below.
        registry.add("hugmesh.gateway.bff-exchange.enabled", () -> "true");
        registry.add("hugmesh.gateway.bff-exchange.internal-token", () -> "test-internal-token");
        // Datastore-free recipe (same as the smoke / principal-ordering tests).
        registry.add("app.revocation.enabled", () -> "false");
        registry.add("app.route-access.enabled", () -> "false");
        registry.add("app.url-registry.enabled", () -> "false");
        registry.add("app.resource-access.enabled", () -> "false");
        registry.add("spring.autoconfigure.exclude", () ->
                "org.springframework.boot.cassandra.autoconfigure.CassandraAutoConfiguration,"
                        + "org.springframework.boot.data.cassandra.autoconfigure.DataCassandraAutoConfiguration,"
                        + "org.springframework.boot.data.cassandra.autoconfigure.DataCassandraReactiveAutoConfiguration");
    }

    @Autowired
    WebTestClient http;

    @Test
    void cleanBffSwap_reachesHandler200_filterRunsBeforeSecurity() {
        // The stub admin-bff swaps the bff_ for a valid custody JWT. The filter
        // (HIGHEST_PRECEDENCE+5) rewrites Authorization BEFORE WebFilterChainProxy(-100),
        // so the decoder validates the custody JWT and the request reaches the handler
        // (200). PRE-FIX (positive order): the decoder 401s the raw bff_ first -> not 200.
        http.get().uri("/probe/ping")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_good-session")
                .exchange()
                .expectStatus().isOk();
    }

    @TestConfiguration
    static class MintingStub {
        /** A @Primary stub WebClient built on an in-process {@link ClientHttpConnector}
         *  that DRAINS the request body (so no dangling write surfaces as a
         *  WebTestClient post-completion error) and returns a minted custody JWT. */
        @Bean
        @Primary
        WebClient bffExchangeWebClient() {
            return WebClient.builder()
                    .baseUrl("http://admin-bff-stub")
                    .clientConnector(mintingConnector())
                    .build();
        }

        private static ClientHttpConnector mintingConnector() {
            return (method, uri, requestCallback) -> {
                MockClientHttpRequest request = new MockClientHttpRequest(method, uri);
                // Drain the request body fully so reactor never has a pending write.
                request.setWriteHandler(body -> DataBufferUtils.join(body)
                        .doOnNext(DataBufferUtils::release)
                        .then());
                String custody = ISSUER.mint("swapped-user", List.of("user"));
                MockClientHttpResponse response = new MockClientHttpResponse(HttpStatus.OK);
                response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
                response.setBody("{\"bearer\":\"" + custody + "\"}");
                return requestCallback.apply(request).then(Mono.just(response));
            };
        }

        @Bean
        ProbeController probeController() {
            return new ProbeController();
        }
    }

    @RestController
    static class ProbeController {
        @GetMapping("/probe/ping")
        Mono<ResponseEntity<Void>> ping() {
            return Mono.just(ResponseEntity.ok().build());
        }
    }
}
