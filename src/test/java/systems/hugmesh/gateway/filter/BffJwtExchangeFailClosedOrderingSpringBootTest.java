package systems.hugmesh.gateway.filter;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * The fail-CLOSED half of the {@link BffJwtExchangeWebFilter} ordering contract (the
 * sibling of {@link BffJwtExchangeFilterOrderingSpringBootTest}, which pins the ALLOW
 * half). A separate {@code @SpringBootTest} boot so the stub admin-bff can deterministically
 * REFUSE every swap without a body-reading branch (which trips a WebTestClient
 * double-subscription footgun).
 *
 * <p>When the admin-bff refuses, the pre-security {@link BffJwtExchangeWebFilter} (order
 * {@code HIGHEST_PRECEDENCE + 5}) short-circuits with a {@code 401} and NEVER FORWARDS the
 * raw {@code bff_} (the request is dropped — {@code chain.filter} is never called) — so it
 * never reaches the JWT decoder (inside {@code WebFilterChainProxy}
 * at {@code -100}) NOR the local probe handler (which would return {@code 200}). The
 * assertion is therefore: a {@code bff_} whose swap fails yields {@code 401}, never the
 * handler's {@code 200}. (The exhaustive per-failure-mode coverage — non-2xx / timeout /
 * empty body / WebClient exception — lives at the unit level in
 * {@link BffJwtExchangeWebFilterTest}.)
 */
@SpringBootTest(properties = {
        "spring.application.name=hugmesh-be-gateway",
        "spring.main.allow-bean-definition-overriding=true",
})
@AutoConfigureWebTestClient
class BffJwtExchangeFailClosedOrderingSpringBootTest {

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        // A placeholder JWKS so the resource server's decoder builds without a network
        // call (no token is ever validated here — the bff_ is rejected before the
        // decoder). An empty value throws; an issuer-uri triggers eager OIDC discovery.
        registry.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri",
                () -> "http://localhost/jwks");
        registry.add("hugmesh.gateway.bff-exchange.enabled", () -> "true");
        registry.add("hugmesh.gateway.bff-exchange.internal-token", () -> "test-internal-token");
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
    void failClosedBff_is401_rawBffNeverForwarded() {
        // The stub admin-bff refuses (401). The filter short-circuits with 401 and the
        // raw bff_ is never forwarded (the request is dropped — chain.filter is never
        // called), so it never reaches the JWT decoder or the handler (which
        // would be 200). The contract: NOT 200, specifically 401.
        http.get().uri("/probe/ping")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_doomed-session")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @TestConfiguration
    static class RefusingStub {
        @Bean
        @Primary
        WebClient bffExchangeWebClient() {
            return WebClient.builder()
                    .baseUrl("http://admin-bff-stub")
                    .exchangeFunction(request ->
                            Mono.just(ClientResponse.create(HttpStatus.UNAUTHORIZED).build()))
                    .build();
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
