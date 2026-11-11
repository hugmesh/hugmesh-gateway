package net.hugmesh.gateway.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;
import net.hugmesh.gateway.cache.GatewayRouteAccessService;
import net.hugmesh.gateway.cache.GatewayRouteAccessService.Rule;
import net.hugmesh.gateway.filter.GatewayRouteAccessFilter;
import net.hugmesh.gateway.security.DomainRegistry;
import net.hugmesh.gateway.testsupport.TestIssuer;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * GUI-08 — a HARD LOAD of a route the caller may not see (a bookmark, a typed URL, a
 * reload) on the fe front door. Before the fix the gateway answered the browser's
 * top-level document request with a bodiless 401 (anonymous) or 403 (signed in, no
 * role), which Chrome can only render as its own "HTTP ERROR 401/403" page: no shell,
 * no menu, no way back. The same route reached by an in-app click showed the shell's
 * answer (/login, or /home?denied=&lt;path&gt;).
 *
 * <p>This drives the REAL assembled chain — the production {@link SecurityConfig}
 * (named tier, multi-issuer resource server, the fe entry point) followed by the REAL
 * {@link GatewayRouteAccessFilter} over a REAL {@link GatewayRouteAccessService} — with
 * real RS256 tokens from in-process issuers, in front of an echo controller that counts
 * every request that got through. Every refusal below also asserts the echo was never
 * reached.
 *
 * <p>What is pinned:
 * <ul>
 *   <li><b>Anonymous document navigation, fe tier</b> -&gt; {@code 302 /login?next=<path>},
 *       no body, no {@code WWW-Authenticate}, no cookie, {@code Cache-Control: no-store}.</li>
 *   <li><b>Signed-in document navigation refused by a route-access row, fe tier</b> -&gt;
 *       {@code 302 /home?denied=<path>} with the usual {@code X-Route-Denied}.</li>
 *   <li><b>Everything that is not a document navigation</b> — {@code *}{@code /*},
 *       JSON, no Accept, a fetch's {@code Sec-Fetch-Mode}, a frame, XHR, non-GET — gets
 *       a response IDENTICAL, header for header, to the one the blank tier (which has no
 *       fe entry point) gives the same request: the 401 with
 *       {@code WWW-Authenticate: Bearer}, or the 403 with {@code X-Route-Denied}.</li>
 *   <li><b>The pki and be tiers</b> keep the 401/403 even for a document navigation.</li>
 *   <li><b>/home and /about</b> are anonymous on the fe tier (the shell's public pages)
 *       and nowhere else; a refusal of /home itself is never redirected to /home.</li>
 * </ul>
 */
class FeDocumentNavigationSliceTest extends SecuritySliceSupport {

    private static final String FE = "hugmesh-fe-gateway";
    private static final String BE = "hugmesh-be-gateway";
    private static final String PKI = "hugmesh-pki-gateway";
    /** The blank name: the UNKNOWN tier, which never gets the fe entry point. Used as the
     *  "what the response was before" oracle for non-navigation requests. */
    private static final String BLANK = "";
    private static final String HOST = "www.brandx.tld";

    /** What Chrome sends for a typed URL, a bookmark or a reload. */
    private static final Map<String, String> CHROME_NAVIGATION = Map.of(
            HttpHeaders.ACCEPT, "text/html,application/xhtml+xml,application/xml;q=0.9,"
                    + "image/avif,image/webp,image/apng,*/*;q=0.8",
            "Sec-Fetch-Mode", "navigate",
            "Sec-Fetch-Dest", "document",
            "Sec-Fetch-Site", "none",
            "Sec-Fetch-User", "?1",
            "Upgrade-Insecure-Requests", "1");

    /** Request shapes that are NOT a top-level document navigation. Each must get the
     *  pre-fix response. Keyed by a label for the failure message. */
    private static Map<String, Map<String, String>> nonNavigationShapes() {
        Map<String, Map<String, String>> shapes = new LinkedHashMap<>();
        shapes.put("Accept */* (fetch, curl, Playwright API client)", Map.of(HttpHeaders.ACCEPT, "*/*"));
        shapes.put("no Accept header", Map.of());
        shapes.put("Accept application/json", Map.of(HttpHeaders.ACCEPT, "application/json"));
        shapes.put("Angular HttpClient", Map.of(HttpHeaders.ACCEPT, "application/json, text/plain, */*"));
        shapes.put("text/* is not text/html by name", Map.of(HttpHeaders.ACCEPT, "text/*"));
        shapes.put("text/html;q=0 refuses html", Map.of(HttpHeaders.ACCEPT, "text/html;q=0, */*"));
        shapes.put("fetch() asking for html (Sec-Fetch-Mode cors)", Map.of(
                HttpHeaders.ACCEPT, "text/html", "Sec-Fetch-Mode", "cors", "Sec-Fetch-Dest", "empty"));
        shapes.put("same-origin fetch", Map.of(
                HttpHeaders.ACCEPT, "text/html", "Sec-Fetch-Mode", "same-origin"));
        shapes.put("a frame navigation is not top level", Map.of(
                HttpHeaders.ACCEPT, "text/html", "Sec-Fetch-Mode", "navigate", "Sec-Fetch-Dest", "iframe"));
        shapes.put("legacy XHR marker", Map.of(
                HttpHeaders.ACCEPT, "text/html", "X-Requested-With", "XMLHttpRequest"));
        shapes.put("a script request", Map.of(
                HttpHeaders.ACCEPT, "*/*", "Sec-Fetch-Mode", "cors", "Sec-Fetch-Dest", "script"));
        return shapes;
    }

    private TestIssuer issuer;
    private TestIssuer issuer2;
    private Echo echo;

    @BeforeEach
    void setUp() {
        issuer = new TestIssuer();
        issuer2 = new TestIssuer();
        echo = new Echo();
    }

    @AfterEach
    void tearDown() {
        issuer.close();
        issuer2.close();
    }

    // ── wiring ─────────────────────────────────────────────────────────────────

    private DomainRegistry registry() {
        String issuers = issuer.issuerUri() + "=brandx," + issuer2.issuerUri() + "=brandy";
        return new DomainRegistry(issuer.issuerUri(), issuers, HOST + "=brandx");
    }

    /** The fe rows these routes are governed by in CanonicalSeed.fe() (the console
     *  floors, the login and shell PUBLIC rows), primed under the given gateway name. */
    private static List<Rule> rowsFor(String gw, Rule... extra) {
        List<Rule> rows = new ArrayList<>(List.of(
                new Rule("admin", gw, "/admin/**", "ROLE_ADMIN", null, true, null, false),
                new Rule("mod", gw, "/mod/**", "ROLE_MOD", null, true, null, false),
                new Rule("mod-admin", gw, "/mod/**", "ROLE_ADMIN", null, true, null, false),
                new Rule("user", gw, "/user/**", "ROLE_USER", null, true, null, false),
                new Rule("login", gw, "/login/**", "PUBLIC", null, true, null, false),
                new Rule("home", gw, "/home", "PUBLIC", null, true, null, false),
                new Rule("about", gw, "/about", "PUBLIC", null, true, null, false)));
        rows.addAll(List.of(extra));
        return rows;
    }

    private WebTestClient client(String applicationName, Rule... extraRows) {
        DomainRegistry registry = registry();
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                new TenancyResourceServerConfig(registry, "", "").tenantAuthManagerResolver();
        SecurityConfig config = new SecurityConfig(registry, provider(resolver), applicationName,
                false, 600_000L);
        GatewayRouteAccessService routeAccess =
                new GatewayRouteAccessService(null, null, applicationName, true, false, null);
        routeAccess.primeForTest(rowsFor(applicationName, extraRows));
        List<WebFilter> gatewayFilters = List.of(new GatewayRouteAccessFilter(routeAccess, registry));
        return sliceClientWithGatewayFilters(config, gatewayFilters, echo);
    }

    private String userToken() {
        return issuer.mint("member-1", List.of("user"));
    }

    private static EntityExchangeResult<byte[]> send(WebTestClient client, HttpMethod method, String uri,
                                                     Map<String, String> headers, String bearer) {
        return client.method(method).uri(uri)
                .headers(h -> {
                    h.set(HttpHeaders.HOST, HOST);
                    headers.forEach(h::set);
                    if (bearer != null) h.set(HttpHeaders.AUTHORIZATION, "Bearer " + bearer);
                })
                .exchange()
                .expectBody()
                .returnResult();
    }

    private static EntityExchangeResult<byte[]> navigate(WebTestClient client, String uri, String bearer) {
        return send(client, HttpMethod.GET, uri, CHROME_NAVIGATION, bearer);
    }

    private static void assertRedirect(EntityExchangeResult<byte[]> r, String location) {
        assertThat(r.getStatus()).as("status of %s", r.getUrl()).isEqualTo(HttpStatus.FOUND);
        HttpHeaders h = r.getResponseHeaders();
        assertThat(h.getFirst(HttpHeaders.LOCATION)).as("Location of %s", r.getUrl()).isEqualTo(location);
        assertThat(h.getFirst(HttpHeaders.CACHE_CONTROL)).as("a redirect must never be replayed")
                .contains("no-store");
        assertThat(h.get(HttpHeaders.SET_COOKIE)).as("the redirect starts no session").isNull();
        assertThat(h.get(HttpHeaders.WWW_AUTHENTICATE)).isNull();
        assertThat(r.getResponseBody()).as("body of %s", r.getUrl()).isNullOrEmpty();
    }

    /** Headers minus the ones that legitimately differ between two runs. */
    private static Map<String, List<String>> comparable(HttpHeaders h) {
        Map<String, List<String>> out = new LinkedHashMap<>();
        h.forEach((k, v) -> {
            if (!k.equalsIgnoreCase(HttpHeaders.DATE)) out.put(k.toLowerCase(java.util.Locale.ROOT), v);
        });
        return out;
    }

    // ── anonymous: the sign-in redirect ───────────────────────────────────────

    @Test
    void anonymousDocumentNavigation_toAGatedRoute_redirectsToLogin_onFeTier() {
        WebTestClient fe = client(FE);
        for (String path : List.of("/admin", "/user", "/games", "/mod/queue", "/wiki/Main_Page")) {
            String expected = "/login?next=" + path.replace("/", "%2F");
            assertRedirect(navigate(fe, path, null), expected);
        }
        assertThat(echo.hits.get()).as("no refused navigation reached a downstream").isZero();
    }

    @Test
    void anonymousRedirect_carriesThePathAndQuery_encodedAsOneValue() {
        assertRedirect(navigate(client(FE), "/admin/users?tab=2&q=a+b", null),
                "/login?next=%2Fadmin%2Fusers%3Ftab%3D2%26q%3Da%2Bb");
    }

    @Test
    void anonymousRedirect_alsoForAClientThatSendsOnlyAcceptTextHtml() {
        // No Sec-Fetch-* at all: an older browser, or `curl -H 'Accept: text/html'` (the
        // retest lane's probe). Accept naming text/html is enough.
        assertRedirect(send(client(FE), HttpMethod.GET, "/admin",
                Map.of(HttpHeaders.ACCEPT, "text/html"), null), "/login?next=%2Fadmin");
    }

    @Test
    void anonymousNonNavigation_getsExactlyTheResponseItGotBefore() {
        WebTestClient fe = client(FE);
        WebTestClient before = client(BLANK);
        for (var shape : nonNavigationShapes().entrySet()) {
            for (String path : List.of("/admin", "/bff/user/profile")) {
                EntityExchangeResult<byte[]> now = send(fe, HttpMethod.GET, path, shape.getValue(), null);
                EntityExchangeResult<byte[]> was = send(before, HttpMethod.GET, path, shape.getValue(), null);
                assertThat(now.getStatus()).as("%s %s", shape.getKey(), path).isEqualTo(HttpStatus.UNAUTHORIZED);
                assertThat(now.getResponseHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                        .as("%s %s: the Bearer challenge #290 asserts", shape.getKey(), path)
                        .isEqualTo("Bearer");
                assertThat(comparable(now.getResponseHeaders()))
                        .as("%s %s: header for header what the tier without the fe entry point answers",
                                shape.getKey(), path)
                        .isEqualTo(comparable(was.getResponseHeaders()));
                assertThat(now.getResponseBody()).isNullOrEmpty();
            }
        }
        assertThat(echo.hits.get()).isZero();
    }

    @Test
    void anonymousNonGetNavigation_isNeverRedirected() {
        WebTestClient fe = client(FE);
        WebTestClient before = client(BLANK);
        for (HttpMethod method : List.of(HttpMethod.POST, HttpMethod.PUT, HttpMethod.DELETE,
                HttpMethod.PATCH, HttpMethod.HEAD)) {
            EntityExchangeResult<byte[]> now = send(fe, method, "/admin", CHROME_NAVIGATION, null);
            EntityExchangeResult<byte[]> was = send(before, method, "/admin", CHROME_NAVIGATION, null);
            assertThat(now.getStatus()).as("%s /admin", method).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(comparable(now.getResponseHeaders())).as("%s /admin", method)
                    .isEqualTo(comparable(was.getResponseHeaders()));
        }
        assertThat(echo.hits.get()).isZero();
    }

    @Test
    void pkiBeAndBlankTiers_keepThe401_evenForADocumentNavigation() {
        for (String tier : List.of(PKI, BE, BLANK, "brandx-be-gateway")) {
            EntityExchangeResult<byte[]> r = navigate(client(tier), "/admin", null);
            assertThat(r.getStatus()).as("tier '%s'", tier).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(r.getResponseHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE)).isEqualTo("Bearer");
            assertThat(r.getResponseHeaders().getFirst(HttpHeaders.LOCATION)).as("tier '%s'", tier).isNull();
        }
        assertThat(echo.hits.get()).isZero();
    }

    @Test
    void perBrandFeInstance_redirectsLikeTheCanonicalOne() {
        assertRedirect(navigate(client("brandx-fe-gateway"), "/admin", null), "/login?next=%2Fadmin");
    }

    @Test
    void theLoginPage_isServed_notRedirectedToItself() {
        EntityExchangeResult<byte[]> r = navigate(client(FE), "/login?next=%2Fadmin", null);
        assertThat(r.getStatus()).isEqualTo(HttpStatus.OK);
        assertThat(echo.hits.get()).isEqualTo(1);
    }

    @Test
    void theEntryPointItself_neverSendsTheLoginPageToTheLoginPage() {
        // /login/** is anonymous on the fe tier, so the chain never asks the entry point
        // about it. Pinned on the entry point directly so that, if the permit were ever
        // narrowed, a hard load of /login would get the 401 rather than a redirect loop.
        for (String path : List.of("/login", "/login/appeal")) {
            var exchange = org.springframework.mock.web.server.MockServerWebExchange.from(navigationRequest(path));
            SecurityConfig.feEntryPoint().commence(exchange,
                    new org.springframework.security.authentication.InsufficientAuthenticationException("anon"))
                    .block();
            assertThat(exchange.getResponse().getStatusCode()).as(path).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.LOCATION)).as(path).isNull();
            assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                    .isEqualTo("Bearer");
        }
        var gated = org.springframework.mock.web.server.MockServerWebExchange.from(navigationRequest("/loginx"));
        SecurityConfig.feEntryPoint().commence(gated,
                new org.springframework.security.authentication.InsufficientAuthenticationException("anon")).block();
        assertThat(gated.getResponse().getStatusCode()).as("/loginx is not /login").isEqualTo(HttpStatus.FOUND);
        assertThat(gated.getResponse().getHeaders().getFirst(HttpHeaders.LOCATION)).isEqualTo("/login?next=%2Floginx");
        // Outside the chain there is no default cache-control header writer, so this
        // pins the entry point's OWN no-store: the redirect must not be replayed even
        // where that writer is not in play.
        assertThat(gated.getResponse().getHeaders().getFirst(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
    }

    private static org.springframework.mock.http.server.reactive.MockServerHttpRequest navigationRequest(String path) {
        var builder = org.springframework.mock.http.server.reactive.MockServerHttpRequest.get(path);
        CHROME_NAVIGATION.forEach((k, v) -> builder.header(k, v));
        return builder.build();
    }

    // ── /home and /about: the shell's public pages ─────────────────────────────

    @Test
    void homeAndAbout_areAnonymous_onTheFeTier() {
        WebTestClient fe = client(FE);
        for (String path : List.of("/home", "/about", "/home?denied=%2Fadmin")) {
            assertThat(navigate(fe, path, null).getStatus()).as(path).isEqualTo(HttpStatus.OK);
            // and for a non-navigation GET too: it is a plain permitAll, not a redirect rule
            assertThat(send(fe, HttpMethod.GET, path, Map.of(HttpHeaders.ACCEPT, "*/*"), null).getStatus())
                    .as("%s with */*", path).isEqualTo(HttpStatus.OK);
        }
        assertThat(echo.hits.get()).isEqualTo(6);
    }

    @Test
    void homeAndAbout_stayOnTheAuthenticatedFloor_offTheFeTier() {
        for (String tier : List.of(PKI, BE, BLANK)) {
            for (String path : List.of("/home", "/about")) {
                assertThat(navigate(client(tier), path, null).getStatus())
                        .as("tier '%s' %s", tier, path).isEqualTo(HttpStatus.UNAUTHORIZED);
            }
        }
        assertThat(echo.hits.get()).isZero();
    }

    @Test
    void homeAndAbout_permitIsGetOnly() {
        EntityExchangeResult<byte[]> r = send(client(FE), HttpMethod.POST, "/home",
                Map.of(HttpHeaders.ACCEPT, "*/*"), null);
        assertThat(r.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(echo.hits.get()).isZero();
    }

    // ── signed in without the role: the denied-page redirect ──────────────────

    @Test
    void signedInDocumentNavigation_refusedByARouteAccessRow_redirectsToTheDeniedPage() {
        WebTestClient fe = client(FE);
        String token = userToken();
        for (String path : List.of("/admin", "/admin/users", "/mod", "/mod/queue")) {
            EntityExchangeResult<byte[]> r = navigate(fe, path, token);
            assertRedirect(r, "/home?denied=" + path.replace("/", "%2F"));
            assertThat(r.getResponseHeaders().getFirst("X-Route-Denied"))
                    .as("the redirect still says WHICH gateway refused WHICH path")
                    .isEqualTo(FE + ":" + path);
        }
        assertThat(echo.hits.get()).as("no refused navigation reached a downstream").isZero();
        // ...and the page it lands on is reachable for that same user.
        EntityExchangeResult<byte[]> landing = navigate(fe, "/home?denied=%2Fadmin", token);
        assertThat(landing.getStatus()).isEqualTo(HttpStatus.OK);
        assertThat(echo.hits.get()).isEqualTo(1);
    }

    @Test
    void signedInNonNavigation_keepsTheBare403_headerForHeader() {
        WebTestClient fe = client(FE);
        String token = userToken();
        for (var shape : nonNavigationShapes().entrySet()) {
            EntityExchangeResult<byte[]> r = send(fe, HttpMethod.GET, "/admin", shape.getValue(), token);
            assertThat(r.getStatus()).as(shape.getKey()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(r.getResponseHeaders().getFirst("X-Route-Denied")).isEqualTo(FE + ":/admin");
            assertThat(r.getResponseHeaders().getFirst(HttpHeaders.LOCATION)).as(shape.getKey()).isNull();
            assertThat(r.getResponseBody()).isNullOrEmpty();
        }
        for (HttpMethod method : List.of(HttpMethod.POST, HttpMethod.PUT, HttpMethod.DELETE, HttpMethod.HEAD)) {
            EntityExchangeResult<byte[]> r = send(fe, method, "/admin", CHROME_NAVIGATION, token);
            assertThat(r.getStatus()).as("%s", method).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(r.getResponseHeaders().getFirst(HttpHeaders.LOCATION)).as("%s", method).isNull();
        }
        assertThat(echo.hits.get()).isZero();
    }

    @Test
    void signedInDocumentNavigation_onTheBeTier_keepsThe403() {
        EntityExchangeResult<byte[]> r = navigate(client(BE), "/admin", userToken());
        assertThat(r.getStatus()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(r.getResponseHeaders().getFirst("X-Route-Denied")).isEqualTo(BE + ":/admin");
        assertThat(r.getResponseHeaders().getFirst(HttpHeaders.LOCATION)).isNull();
        assertThat(echo.hits.get()).isZero();
    }

    @Test
    void aRefusalOfTheDeniedPageItself_isNeverRedirectedBackToIt() {
        // An operator row that refuses /home to plain users (an explicit deny, which wins
        // over the PUBLIC row) must not turn every refusal into a redirect loop: the
        // refusal of /home itself stays a 403.
        WebTestClient fe = client(FE,
                new Rule("home-deny-users", FE, "/home", "ROLE_USER", null, false, null, false));
        EntityExchangeResult<byte[]> r = navigate(fe, "/home", userToken());
        assertThat(r.getStatus()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(r.getResponseHeaders().getFirst(HttpHeaders.LOCATION)).isNull();
        assertThat(echo.hits.get()).isZero();
    }

    /** Counts every request the chain let through. */
    @RestController
    static class Echo {
        final AtomicInteger hits = new AtomicInteger();

        @RequestMapping({"/admin", "/admin/users", "/mod", "/mod/queue", "/user", "/games",
                "/wiki/Main_Page", "/home", "/about", "/login", "/bff/user/profile"})
        Mono<String> reached() {
            hits.incrementAndGet();
            return Mono.just("REACHED");
        }
    }
}
