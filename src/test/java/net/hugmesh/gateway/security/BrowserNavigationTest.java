package net.hugmesh.gateway.security;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The GUI-08 request classifier and redirect builder ({@link BrowserNavigation}) on its
 * own: which requests count as a top-level document navigation, and what the two
 * redirect targets look like for awkward paths.
 */
class BrowserNavigationTest {

    private static final String CHROME_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,"
            + "image/avif,image/webp,image/apng,*/*;q=0.8";

    private static MockServerHttpRequest.BaseBuilder<?> get(String path) {
        return MockServerHttpRequest.get(path);
    }

    @Test
    void chromeTopLevelNavigation_isADocumentNavigation() {
        assertThat(BrowserNavigation.isDocumentNavigation(get("/admin")
                .header(HttpHeaders.ACCEPT, CHROME_ACCEPT)
                .header("Sec-Fetch-Mode", "navigate")
                .header("Sec-Fetch-Dest", "document")
                .build())).isTrue();
    }

    @Test
    void acceptTextHtmlAlone_isADocumentNavigation() {
        assertThat(BrowserNavigation.isDocumentNavigation(get("/admin")
                .header(HttpHeaders.ACCEPT, "text/html").build())).isTrue();
        assertThat(BrowserNavigation.isDocumentNavigation(get("/admin")
                .header(HttpHeaders.ACCEPT, "TEXT/HTML; charset=utf-8").build())).isTrue();
    }

    @Test
    void wildcardsAndMissingAccept_areNot() {
        for (String accept : new String[] {"*/*", "text/*", "application/json",
                "application/json, text/plain, */*", "text/html;q=0", "text/html;q=0, */*"}) {
            assertThat(BrowserNavigation.isDocumentNavigation(get("/admin")
                    .header(HttpHeaders.ACCEPT, accept).build())).as(accept).isFalse();
        }
        assertThat(BrowserNavigation.isDocumentNavigation(get("/admin").build()))
                .as("no Accept").isFalse();
        assertThat(BrowserNavigation.isDocumentNavigation(get("/admin")
                .header(HttpHeaders.ACCEPT, "text/html;q=abc").build()))
                .as("an unparseable Accept").isFalse();
    }

    @Test
    void fetchModesFramesAndXhr_areNot() {
        assertThat(BrowserNavigation.isDocumentNavigation(get("/admin").header(HttpHeaders.ACCEPT, "text/html")
                .header("Sec-Fetch-Mode", "cors").build())).isFalse();
        assertThat(BrowserNavigation.isDocumentNavigation(get("/admin").header(HttpHeaders.ACCEPT, "text/html")
                .header("Sec-Fetch-Mode", "no-cors").build())).isFalse();
        assertThat(BrowserNavigation.isDocumentNavigation(get("/admin").header(HttpHeaders.ACCEPT, "text/html")
                .header("Sec-Fetch-Mode", "navigate").header("Sec-Fetch-Dest", "iframe").build())).isFalse();
        assertThat(BrowserNavigation.isDocumentNavigation(get("/admin").header(HttpHeaders.ACCEPT, "text/html")
                .header("X-Requested-With", "XMLHttpRequest").build())).isFalse();
        assertThat(BrowserNavigation.isDocumentNavigation(get("/admin").header(HttpHeaders.ACCEPT, "text/html")
                .header("Sec-Fetch-Mode", "navigate", "cors").build()))
                .as("a repeated Sec-Fetch-Mode is a navigation only if every value says so").isFalse();
    }

    @Test
    void androidWebViewPackageNameInXRequestedWith_isStillAPageLoad() {
        // Android WebView sends X-Requested-With: <embedding app's package> on its
        // top-level navigations. Only the XHR marker value means "script request".
        assertThat(BrowserNavigation.isDocumentNavigation(get("/admin")
                .header(HttpHeaders.ACCEPT, CHROME_ACCEPT)
                .header("Sec-Fetch-Mode", "navigate").header("Sec-Fetch-Dest", "document")
                .header("X-Requested-With", "com.example.app").build())).isTrue();
        assertThat(BrowserNavigation.isDocumentNavigation(get("/admin")
                .header(HttpHeaders.ACCEPT, "text/html")
                .header("X-Requested-With", "xmlhttprequest").build()))
                .as("the XHR marker, any case").isFalse();
    }

    @Test
    void onlyGet() {
        for (HttpMethod m : new HttpMethod[] {HttpMethod.POST, HttpMethod.PUT, HttpMethod.DELETE,
                HttpMethod.PATCH, HttpMethod.HEAD, HttpMethod.OPTIONS}) {
            assertThat(BrowserNavigation.isDocumentNavigation(MockServerHttpRequest.method(m, URI.create("/admin"))
                    .header(HttpHeaders.ACCEPT, "text/html").header("Sec-Fetch-Mode", "navigate").build()))
                    .as(m.name()).isFalse();
        }
        assertThat(BrowserNavigation.isDocumentNavigation(null)).isFalse();
    }

    @Test
    void redirectTargets_carryThePathAndQuery_asOneEncodedValue() {
        assertThat(BrowserNavigation.loginRedirect(get("/admin").build()))
                .isEqualTo(URI.create("/login?next=%2Fadmin"));
        assertThat(BrowserNavigation.deniedRedirect(get("/mod/queue?x=1&y=a+b").build()))
                .isEqualTo(URI.create("/home?denied=%2Fmod%2Fqueue%3Fx%3D1%26y%3Da%2Bb"));
        assertThat(BrowserNavigation.loginRedirect(MockServerHttpRequest.method(HttpMethod.GET,
                        URI.create("http://h/wiki/Caf%C3%A9")).build()))
                .as("an already-encoded path is carried raw, so one decode gives it back")
                .isEqualTo(URI.create("/login?next=%2Fwiki%2FCaf%25C3%25A9"));
        assertThat(BrowserNavigation.loginRedirect(get("/").build()))
                .isEqualTo(URI.create("/login?next=%2F"));
    }

    @Test
    void aPathThatCouldReadAsAnotherOrigin_getsTheBareTarget() {
        for (String raw : new String[] {"http://h//evil.example/x", "http://h/%5C%5Cevil", "http://h/\\evil"}) {
            URI uri;
            try {
                uri = URI.create(raw);
            } catch (IllegalArgumentException e) {
                continue;   // not even a URI a server would hand us
            }
            MockServerHttpRequest req = MockServerHttpRequest.method(HttpMethod.GET, uri).build();
            String rawPath = req.getURI().getRawPath();
            URI login = BrowserNavigation.loginRedirect(req);
            if (rawPath.startsWith("//") || rawPath.startsWith("/\\")) {
                assertThat(login).as(raw).isEqualTo(URI.create("/login"));
                assertThat(BrowserNavigation.deniedRedirect(req)).as(raw).isEqualTo(URI.create("/home"));
            } else {
                // %5C stays encoded in the raw path, so it is a plain path segment
                assertThat(login.toString()).as(raw).startsWith("/login?next=%2F");
            }
        }
        MockServerHttpRequest protocolRelative =
                MockServerHttpRequest.method(HttpMethod.GET, URI.create("http://h//evil.example/x")).build();
        assertThat(protocolRelative.getURI().getRawPath()).isEqualTo("//evil.example/x");
        assertThat(BrowserNavigation.loginRedirect(protocolRelative)).isEqualTo(URI.create("/login"));
    }

    @Test
    void redirectTargetsAreAlwaysRelative() {
        URI login = BrowserNavigation.loginRedirect(get("/admin").build());
        assertThat(login.isAbsolute()).isFalse();
        assertThat(login.getRawAuthority()).isNull();
        assertThat(login.getRawPath()).isEqualTo("/login");
        URI denied = BrowserNavigation.deniedRedirect(get("/admin").build());
        assertThat(denied.isAbsolute()).isFalse();
        assertThat(denied.getRawPath()).isEqualTo("/home");
    }

    @Test
    void feTierBySuffix() {
        assertThat(BrowserNavigation.isFeTier("hugmesh-fe-gateway")).isTrue();
        assertThat(BrowserNavigation.isFeTier("brandx-fe-gateway")).isTrue();
        assertThat(BrowserNavigation.isFeTier("hugmesh-be-gateway")).isFalse();
        assertThat(BrowserNavigation.isFeTier("hugmesh-pki-gateway")).isFalse();
        assertThat(BrowserNavigation.isFeTier("")).isFalse();
        assertThat(BrowserNavigation.isFeTier(null)).isFalse();
    }

    @Test
    void isUnder() {
        assertThat(BrowserNavigation.isUnder("/login", "/login")).isTrue();
        assertThat(BrowserNavigation.isUnder("/login/appeal", "/login")).isTrue();
        assertThat(BrowserNavigation.isUnder("/loginx", "/login")).isFalse();
        assertThat(BrowserNavigation.isUnder("/home", "/home")).isTrue();
        assertThat(BrowserNavigation.isUnder(null, "/home")).isFalse();
    }
}
