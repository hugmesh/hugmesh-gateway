package net.hugmesh.gateway.filter;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpCookie;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.gateway.config.BffSessionProperties;
import net.hugmesh.gateway.filter.BffSessionAuthFilter.MeResponse;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The second half of the {@code app.security.banned-remote-public} switch: with it
 * on, a {@code bff_} cookie on {@code /_remotes/banned/**} is NOT introspected (the
 * request stays anonymous, so a revoked player's cookie cannot turn the opt-in
 * permit into a revocation 403). With it off the prefix is introspected like any
 * gated path.
 */
class BffSessionBannedRemoteSkipTest {

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static WebClient introspectingClient() {
        WebClient client = mock(WebClient.class);
        WebClient.RequestHeadersUriSpec uriSpec = mock(WebClient.RequestHeadersUriSpec.class);
        WebClient.RequestHeadersSpec headersSpec = mock(WebClient.RequestHeadersSpec.class);
        WebClient.ResponseSpec responseSpec = mock(WebClient.ResponseSpec.class);
        doReturn(uriSpec).when(client).get();
        doReturn(headersSpec).when(uriSpec).uri(anyString());
        doReturn(headersSpec).when(headersSpec).header(anyString(), anyString());
        doReturn(headersSpec).when(headersSpec).accept(any());
        doReturn(responseSpec).when(headersSpec).retrieve();
        when(responseSpec.bodyToMono(MeResponse.class)).thenReturn(Mono.just(
                new MeResponse("casdoor:p@example.test", "casdoor", List.of("user"),
                        true, "active", false)));
        return client;
    }

    private static BffSessionAuthFilter filter(WebClient client, boolean bannedRemotePublic) {
        BffSessionProperties props = new BffSessionProperties();
        props.setEnabled(true);
        return new BffSessionAuthFilter(client, props, bannedRemotePublic);
    }

    private static ServerWebExchange cookieRequest(String path) {
        return MockServerWebExchange.from(MockServerHttpRequest.get(path)
                .cookie(new HttpCookie(BffSessionAuthFilter.SESSION_COOKIE, "bff_cookieval"))
                .build());
    }

    private static final class ForwardChain implements WebFilterChain {
        final AtomicBoolean forwarded = new AtomicBoolean(false);
        @Override
        public Mono<Void> filter(ServerWebExchange exchange) {
            forwarded.set(true);
            return Mono.empty();
        }
    }

    @Test
    void flagOn_bannedRemoteSkipsIntrospection() {
        WebClient client = introspectingClient();
        ForwardChain chain = new ForwardChain();
        StepVerifier.create(filter(client, true)
                .filter(cookieRequest("/_remotes/banned/remoteEntry.json"), chain)).verifyComplete();
        assertThat(chain.forwarded).isTrue();
        verify(client, never()).get();
    }

    @Test
    void flagOff_bannedRemoteIsIntrospected() {
        WebClient client = introspectingClient();
        ForwardChain chain = new ForwardChain();
        StepVerifier.create(filter(client, false)
                .filter(cookieRequest("/_remotes/banned/remoteEntry.json"), chain)).verifyComplete();
        verify(client).get();
    }

    @Test
    void twoArgConstructorIsFlagOff() {
        WebClient client = introspectingClient();
        BffSessionProperties props = new BffSessionProperties();
        props.setEnabled(true);
        StepVerifier.create(new BffSessionAuthFilter(client, props)
                .filter(cookieRequest("/_remotes/banned/x"), new ForwardChain())).verifyComplete();
        verify(client).get();
    }

    @Test
    void flagOn_doesNotSkipSiblingsOrOtherPaths() {
        for (String path : List.of("/_remotes/bannedx/y", "/_remotes/BANNED/x",
                "/api/reports/q3", "/_remotes/admin/remoteEntry.json")) {
            WebClient client = introspectingClient();
            StepVerifier.create(filter(client, true)
                    .filter(cookieRequest(path), new ForwardChain())).verifyComplete();
            verify(client).get();
        }
    }
}
