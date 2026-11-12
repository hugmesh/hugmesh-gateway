package net.hugmesh.gateway.security;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Pattern;

/**
 * The fe-tier answer to a browser that hard-loads a route it may not see.
 *
 * <p><b>The defect this exists for (GUI-08).</b> A bookmark, a typed URL or a reload is
 * a top-level document navigation. When the gateway refuses one with a bodiless 401 or
 * 403, the browser has nothing to render and shows its own "HTTP ERROR 401/403" page:
 * no shell, no menu, no way back. The same route reached by an in-app click shows the
 * host shell's answer instead, because the shell's guards send an anonymous visitor to
 * {@code /login} and a signed-in visitor without the role to {@code /home?denied=<path>}
 * (host-shell {@code role-guard.factory.ts}, {@code DENIED_PATH}). This class gives the
 * gateway the same two answers, for document navigations only:
 *
 * <ul>
 *   <li>not signed in: {@code 302 Location: /login?next=<path>};</li>
 *   <li>signed in, refused by a route-access rule:
 *       {@code 302 Location: /home?denied=<path>}.</li>
 * </ul>
 *
 * <p><b>What counts as a document navigation.</b> All of:
 * <ul>
 *   <li>the method is {@code GET};</li>
 *   <li>{@code Accept} lists {@code text/html} by name with a non-zero quality.
 *       {@code *}{@code /*}, {@code text/*} and a missing header do not count: that is
 *       what {@code fetch()}, curl, Playwright's API client and every BFF client send,
 *       and each of them must keep getting the 401/403;</li>
 *   <li>{@code Sec-Fetch-Mode} is absent or {@code navigate} (a browser sends
 *       {@code cors}, {@code same-origin} or {@code no-cors} for every script request);</li>
 *   <li>{@code Sec-Fetch-Dest} is absent or {@code document} (a frame or an embed is not
 *       a top-level page);</li>
 *   <li>{@code X-Requested-With} is not {@code XMLHttpRequest} (the legacy XHR marker).
 *       Only that value counts: Android WebView puts the embedding app's package name in
 *       the same header on its top-level navigations, and those are page loads.</li>
 * </ul>
 * A request that fails any of these gets exactly the response it got before.
 *
 * <p><b>The same rule also decides who sees the shell's two public pages.</b>
 * {@code /home} and {@code /about} are served to an anonymous visitor only when the
 * request is a document navigation ({@code SecurityConfig.feShellPageNavigation()}); in
 * every other shape those two paths keep the 401, like any other gated path. So this
 * one predicate is the whole difference between "a person opened a page" and "something
 * asked for a URL" on the fe tier. It is a classification of the request, not a
 * credential: the headers are the caller's to send. Nothing it lets through is private
 * (two redirects to fixed pages, and the document {@code /} already serves to anyone).
 *
 * <p><b>Nothing leaks.</b> Both targets are fixed, same-origin, relative paths. The only
 * request-derived part is the caller's own path and query, carried as one encoded query
 * value, and only when it has the shape login-ui accepts for a return path
 * ({@code SAFE_RETURN_TO} in its {@code mfa-challenge-page.component.ts}): a single
 * leading {@code /}, no {@code //} or {@code /\} prefix, no whitespace, backslash or
 * control character. Anything else gets the bare target with no parameter.
 */
public final class BrowserNavigation {

    private BrowserNavigation() {}

    /** The login-ui route. A hard load of it is anonymous on the fe tier
     *  ({@code /login/**} in {@code SecurityConfig.FE_SHELL_PUBLIC_GET_PATHS}). */
    public static final String LOGIN_PATH = "/login";

    /** Query parameter that carries the refused path to the login page. login-ui does not
     *  read it yet; the host-shell menu already treats {@code /login?next=…} as a login
     *  URL. */
    public static final String NEXT_PARAM = "next";

    /** The host shell's {@code DENIED_PATH} (host-shell {@code role-guard.factory.ts}). */
    public static final String DENIED_PATH = "/home";

    /** The query parameter the shell's {@code DeniedNoticeComponent} reads. */
    public static final String DENIED_PARAM = "denied";

    /** login-ui's {@code SAFE_RETURN_TO}, applied to the RAW path and query. */
    private static final Pattern SAFE_RETURN = Pattern.compile(
            "^/(?![/\\\\])[^\\s\\\\\\u0000-\\u001f\\u007f]*$");

    /** Front-door tier, by instance-name suffix. The same derivation
     *  {@code CanonicalSeed.bySuffix} and {@code SecurityConfig} use, so all three agree
     *  on which instance is the front door. Blank and unknown names are not fe. */
    public static boolean isFeTier(String applicationName) {
        return applicationName != null && applicationName.endsWith("-fe-gateway");
    }

    /** True iff {@code request} is a top-level document navigation (see the class
     *  comment for the exact rule). */
    public static boolean isDocumentNavigation(ServerHttpRequest request) {
        if (request == null || !HttpMethod.GET.equals(request.getMethod())) return false;
        HttpHeaders headers = request.getHeaders();
        if (isXmlHttpRequest(headers)) return false;
        if (!absentOr(headers, "Sec-Fetch-Mode", "navigate")) return false;
        if (!absentOr(headers, "Sec-Fetch-Dest", "document")) return false;
        return acceptsHtmlByName(headers);
    }

    private static boolean isXmlHttpRequest(HttpHeaders headers) {
        List<String> values = headers.get("X-Requested-With");
        if (values == null) return false;
        for (String v : values) {
            if (v != null && "XMLHttpRequest".equalsIgnoreCase(v.trim())) return true;
        }
        return false;
    }

    private static boolean absentOr(HttpHeaders headers, String name, String expected) {
        List<String> values = headers.get(name);
        if (values == null) return true;
        for (String v : values) {
            if (v == null || !expected.equalsIgnoreCase(v.trim())) return false;
        }
        return true;
    }

    private static boolean acceptsHtmlByName(HttpHeaders headers) {
        List<MediaType> accepted;
        try {
            accepted = headers.getAccept();
        } catch (IllegalArgumentException e) {   // InvalidMediaTypeException and kin
            return false;
        }
        for (MediaType type : accepted) {
            if ("text".equalsIgnoreCase(type.getType())
                    && "html".equalsIgnoreCase(type.getSubtype())
                    && type.getQualityValue() > 0) {
                return true;
            }
        }
        return false;
    }

    /** {@code /login?next=<path and query>}, or bare {@code /login}. */
    public static URI loginRedirect(ServerHttpRequest request) {
        return withReturnPath(LOGIN_PATH, NEXT_PARAM, request);
    }

    /** {@code /home?denied=<path and query>}, or bare {@code /home}. */
    public static URI deniedRedirect(ServerHttpRequest request) {
        return withReturnPath(DENIED_PATH, DENIED_PARAM, request);
    }

    private static URI withReturnPath(String target, String param, ServerHttpRequest request) {
        String raw = request.getURI().getRawPath();
        if (raw == null || raw.isEmpty()) raw = request.getPath().value();
        String query = request.getURI().getRawQuery();
        String requested = query == null ? raw : raw + "?" + query;
        if (requested == null || !SAFE_RETURN.matcher(requested).matches()) {
            return URI.create(target);
        }
        return URI.create(target + "?" + param + "="
                + URLEncoder.encode(requested, StandardCharsets.UTF_8));
    }

    /** True iff the canonical {@code path} is {@code target} or lies under it. Used to
     *  refuse a redirect whose target is the refused path itself. */
    public static boolean isUnder(String path, String target) {
        return path != null && (path.equals(target) || path.startsWith(target + "/"));
    }
}
