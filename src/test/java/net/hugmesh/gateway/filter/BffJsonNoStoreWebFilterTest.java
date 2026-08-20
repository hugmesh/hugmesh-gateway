package net.hugmesh.gateway.filter;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link BffJsonNoStoreWebFilter} — the defense-in-depth cache-bust for {@code /bff/**}
 * JSON. The regression it pins (operator 2026-08-19, "need to clear cache every time
 * after log out"): Spring Security's kept default writer only acts when NO cache header
 * is present, so an upstream that explicitly sent {@code private, max-age=300} on a
 * user-independent URL let the browser replay the PREVIOUS user's response after
 * sign-out. The filter must WIN over such an upstream value for JSON — and must NOT
 * touch non-JSON bodies (media cacheability stays the owning BFF's decision) nor
 * non-{@code /bff} paths (the {@code /_fragments/**} immutable bundles depend on that).
 *
 * <p>Each test drives the filter with a chain that mimics the PROXY shape: the
 * upstream's headers land on the response inside the chain (i.e. AFTER this filter's
 * inbound pass), and {@code setComplete()} commits — so the assertions prove the
 * beforeCommit hook sees the late-set upstream headers, exactly as it must for a
 * routed response.
 */
class BffJsonNoStoreWebFilterTest {

    private final BffJsonNoStoreWebFilter filter = new BffJsonNoStoreWebFilter();

    /** A chain that sets the given upstream content-type/cache-control late (proxy
     *  shape) and then commits the response. */
    private static WebFilterChain upstream(MediaType contentType, String cacheControl) {
        return exchange -> {
            HttpHeaders h = exchange.getResponse().getHeaders();
            if (contentType != null) h.setContentType(contentType);
            if (cacheControl != null) h.set(HttpHeaders.CACHE_CONTROL, cacheControl);
            return exchange.getResponse().setComplete();
        };
    }

    private MockServerWebExchange run(String path, MediaType contentType, String cacheControl) {
        MockServerWebExchange exchange =
                MockServerWebExchange.from(MockServerHttpRequest.get(path));
        filter.filter(exchange, upstream(contentType, cacheControl)).block();
        return exchange;
    }

    @Test
    void bffJson_withWeakUpstreamCacheControl_isForcedNoStore() {
        // The exact escape shape: an upstream /bff response that OPTED INTO caching.
        MockServerWebExchange ex =
                run("/bff/user/profile", MediaType.APPLICATION_JSON, "private, max-age=300");

        HttpHeaders h = ex.getResponse().getHeaders();
        assertThat(h.getFirst(HttpHeaders.CACHE_CONTROL))
                .isEqualTo(BffJsonNoStoreWebFilter.CACHE_CONTROL_VALUE);
        assertThat(h.getFirst(HttpHeaders.PRAGMA)).isEqualTo(BffJsonNoStoreWebFilter.PRAGMA_VALUE);
        assertThat(h.getFirst(HttpHeaders.EXPIRES)).isEqualTo(BffJsonNoStoreWebFilter.EXPIRES_VALUE);
    }

    @Test
    void bffJson_withNoUpstreamCacheControl_getsTheTrio() {
        MockServerWebExchange ex = run("/bff/session", MediaType.APPLICATION_JSON, null);

        assertThat(ex.getResponse().getHeaders().getFirst(HttpHeaders.CACHE_CONTROL))
                .isEqualTo(BffJsonNoStoreWebFilter.CACHE_CONTROL_VALUE);
    }

    @Test
    void bffProblemJson_suffixVariant_isCovered() {
        MockServerWebExchange ex = run("/bff/mod/actions",
                MediaType.parseMediaType("application/problem+json"), "max-age=60");

        assertThat(ex.getResponse().getHeaders().getFirst(HttpHeaders.CACHE_CONTROL))
                .isEqualTo(BffJsonNoStoreWebFilter.CACHE_CONTROL_VALUE);
    }

    @Test
    void bffNonJson_keepsTheUpstreamHeader() {
        // Media cacheability is the OWNING BFF's decision (e.g. hsproxy thumbnails);
        // the gateway must not strip it wholesale.
        MockServerWebExchange ex = run("/bff/user/matrix/media/thumb",
                MediaType.IMAGE_PNG, "private, max-age=300");

        assertThat(ex.getResponse().getHeaders().getFirst(HttpHeaders.CACHE_CONTROL))
                .isEqualTo("private, max-age=300");
    }

    @Test
    void nonBffPath_isUntouched_evenWhenJson() {
        // /_fragments/** (content-addressed immutable bundles) and every other
        // non-/bff surface keep their own caching policy.
        MockServerWebExchange ex = run("/_fragments/user-card/0a1b/remoteEntry.json",
                MediaType.APPLICATION_JSON, "public, max-age=31536000, immutable");

        assertThat(ex.getResponse().getHeaders().getFirst(HttpHeaders.CACHE_CONTROL))
                .isEqualTo("public, max-age=31536000, immutable");
    }

    @Test
    void bffResponseWithoutContentType_isLeftToTheSecurityDefaults() {
        MockServerWebExchange ex = run("/bff/session", null, null);

        // No content type => not identified as JSON; the kept Spring Security writer
        // owns these (bodyless 401s and other short-circuits).
        assertThat(ex.getResponse().getHeaders().getFirst(HttpHeaders.CACHE_CONTROL)).isNull();
    }
}
