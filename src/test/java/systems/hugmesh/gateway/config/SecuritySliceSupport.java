package systems.hugmesh.gateway.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import systems.hugmesh.gateway.security.DomainRegistry;

/**
 * Shared scaffolding for the gateway SECURITY-SLICE tests — builds a
 * {@link WebTestClient} that drives a real controller THROUGH the production
 * {@link SecurityConfig#filterChain} (the actual {@code authorizeExchange} path
 * policy + the OAuth2 resource-server wiring), with NO full Spring Boot context.
 *
 * <p>This is the load-bearing half of the copyable multi-issuer pattern (see
 * {@code docs/testing/MULTI-ISSUER-SLICE.md}): a resource-server repo replicates the
 * slice by (1) constructing its own {@code SecurityConfig.filterChain} the same way
 * here, (2) supplying issuer-specific tokens via
 * {@link systems.hugmesh.gateway.testsupport.TestIssuer}, and (3) asserting
 * authority emission / 401 fail-closed against {@code WebTestClient}.
 */
abstract class SecuritySliceSupport {

    /**
     * Build a {@link WebTestClient} bound to {@code controllers}, routed THROUGH the
     * real {@link SecurityConfig#filterChain} built from a fresh
     * {@link ServerHttpSecurity}. The chain is installed as a {@link WebFilterChainProxy}
     * web filter so the resource-server authentication + the {@code authorizeExchange}
     * policy run exactly as in production.
     *
     * @param registry        the issuer-&gt;domain registry (single- or multi-issuer)
     * @param tenantResolver  the OPTIONAL per-issuer resolver provider — pass
     *                        {@link #provider(Object)} with the real resolver to take
     *                        the multi-issuer swap, or {@link #absent()} to stay on
     *                        the single-issuer {@code o.jwt(...)} path
     * @param controllers     the @RestController instances under test
     */
    static WebTestClient sliceClient(
            DomainRegistry registry,
            ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>> tenantResolver,
            Object... controllers) {
        // Blank instance name — the UNKNOWN tier (no fe shell permits), i.e. the
        // legacy policy every pre-existing slice asserts.
        return sliceClient("", registry, tenantResolver, controllers);
    }

    /**
     * Like {@link #sliceClient(DomainRegistry, ObjectProvider, Object...)} but with
     * an explicit {@code spring.application.name}, so a slice can drive the
     * TIER-SCOPED path policy (the fe front door's anonymous SPA-shell permits vs
     * the pki/be tiers' authenticated() floor on the same paths).
     */
    static WebTestClient sliceClient(
            String applicationName,
            DomainRegistry registry,
            ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>> tenantResolver,
            Object... controllers) {

        SecurityConfig config = new SecurityConfig(
                registry, tenantResolver, applicationName, false, 600_000L);
        SecurityWebFilterChain chain = config.filterChain(ServerHttpSecurity.http());
        WebFilterChainProxy securityFilter = new WebFilterChainProxy(chain);

        return WebTestClient.bindToController(controllers)
                .webFilter(securityFilter)
                .configureClient()
                .responseTimeout(sliceResponseTimeout())
                .build();
    }

    /**
     * Like {@link #sliceClient} but additionally installs {@code gatewayFilters}
     * (the principal-dependent gateway {@link WebFilter}s — revocation, route-access)
     * AFTER the security {@link WebFilterChainProxy}, so a request flows through the
     * production order: resource-server authentication + {@code authorizeExchange}
     * floor FIRST (the principal is populated), then the gateway filters that read
     * {@code exchange.getPrincipal()} and short-circuit a revoked / cross-tenant /
     * unauthorized principal — exactly the ordering the production
     * {@code WebHttpHandlerBuilder} assembles (security chain at order -100, the
     * gateway filters at their small positive {@code getOrder()} values).
     *
     * <p>This is the load-bearing seam for the KEYSTONE full-chain DENY tests: it
     * assembles the REAL {@code SecurityConfig} chain and the REAL gateway filters
     * together, so a denied request is proven NOT to reach the downstream controller
     * (the mutation-resistant oracle — if the echo controller ran, the deny
     * fail-OPENed). The caller passes the gateway filter instances pre-ordered
     * (revocation before route-access) since {@link WebTestClient.Builder#webFilter}
     * preserves insertion order.
     */
    static WebTestClient sliceClientWithGatewayFilters(
            DomainRegistry registry,
            ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>> tenantResolver,
            java.util.List<WebFilter> gatewayFilters,
            Object... controllers) {

        SecurityConfig config = new SecurityConfig(registry, tenantResolver);
        SecurityWebFilterChain chain = config.filterChain(ServerHttpSecurity.http());
        WebFilterChainProxy securityFilter = new WebFilterChainProxy(chain);

        // Order: the security chain FIRST (authenticates + applies the
        // authorizeExchange floor, populating the principal), then the gateway
        // filters in the order the caller supplied (revocation then route-access),
        // each reading the now-populated principal. WebFilter[] preserves order.
        WebFilter[] ordered = new WebFilter[gatewayFilters.size() + 1];
        ordered[0] = securityFilter;
        for (int i = 0; i < gatewayFilters.size(); i++) {
            ordered[i + 1] = gatewayFilters.get(i);
        }
        return WebTestClient.bindToController(controllers)
                .webFilter(ordered)
                .configureClient()
                .responseTimeout(sliceResponseTimeout())
                .build();
    }

    /**
     * The slice's {@link WebTestClient} blocking-read budget. Generous by default (30s)
     * so a cold first-touch OIDC discovery on a constrained CI runner never trips the
     * framework's 5s default; overridable via {@code gateway.slice.responseTimeoutSeconds}.
     *
     * <p>FLAKE FIX: the multi-issuer path's FIRST touch of a given brand lazily builds
     * that brand's decoder via {@code ReactiveJwtDecoders.fromIssuerLocation(iss)} — a
     * SYNCHRONOUS OIDC discovery (two sequential HTTP round-trips to the in-process
     * {@link systems.hugmesh.gateway.testsupport.TestIssuer}, whose JDK HttpServer runs
     * on a single synchronous executor). On a 1-2 core CI runner (cold JVM + cold Netty
     * WebClient bootstrap + JUnit's non-deterministic method ordering deciding which test
     * eats the cold start) it can exceed {@code WebTestClient}'s DEFAULT 5s blocking-read
     * budget, surfacing as a "~5s reactive blocking-read timeout" flake. Pinning an
     * explicit, generous budget makes the slice deterministic WITHOUT touching any
     * assertion: a tampered/unknown/cross-brand token still runs the REAL decoder and
     * still fail-closes 401; we only stop a slow first-touch from being misread as a
     * failure. (Mirrors the fix already in hugmesh-federation-api's SecuritySliceSupport.)
     */
    private static java.time.Duration sliceResponseTimeout() {
        long secs = Long.getLong("gateway.slice.responseTimeoutSeconds", 30L);
        if (secs < 5L) secs = 5L; // never go below the framework default
        return java.time.Duration.ofSeconds(secs);
    }

    /** An {@link ObjectProvider} that yields the given value from
     *  {@code getIfAvailable()} (what {@code SecurityConfig} calls). */
    @SuppressWarnings("unchecked")
    static <T> ObjectProvider<T> provider(T value) {
        return new ObjectProvider<>() {
            @Override public T getObject() { return value; }
            @Override public T getObject(Object... args) { return value; }
            @Override public T getIfAvailable() { return value; }
            @Override public T getIfUnique() { return value; }
        };
    }

    /** An empty {@link ObjectProvider} ({@code getIfAvailable()} returns {@code null})
     *  — the single-issuer path, where no tenant resolver was contributed. */
    static <T> ObjectProvider<T> absent() {
        return new ObjectProvider<>() {
            @Override public T getObject() { throw new IllegalStateException("no value"); }
            @Override public T getObject(Object... args) { throw new IllegalStateException("no value"); }
            @Override public T getIfAvailable() { return null; }
            @Override public T getIfUnique() { return null; }
        };
    }
}
