package net.hugmesh.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for the BFF session introspection bridge.
 *
 * <p>Bound from {@code app.bff-session.*}. The filter bean
 * ({@link net.hugmesh.gateway.filter.BffSessionAuthFilter}) is only
 * registered when {@code app.bff-session.enabled=true}.
 *
 * <p><b>DEPLOYMENT INVARIANT:</b> {@code bff-base-url} MUST be the direct
 * in-cluster service address of admin-bff (e.g. {@code http://admin-bff:8080}),
 * never the public gateway hostname. The gateway must not route the BFF
 * introspection call back through itself — that would create an infinite loop.
 * Use the Kubernetes internal service DNS name so the call goes directly to
 * the pod, not via any gateway route.
 */
@ConfigurationProperties(prefix = "app.bff-session")
public class BffSessionProperties {

    /**
     * Master feature flag. When {@code false} the BFF session bridge is entirely
     * absent — no bean, no WebClient, no introspection calls. This Java-level
     * default is {@code false} (fail-safe if the property is ever entirely
     * unbound), but {@code application.yml}'s {@code APP_BFF_SESSION_ENABLED:true}
     * placeholder makes the bridge LIVE by default in a real deployment (PR #70)
     * — set {@code APP_BFF_SESSION_ENABLED=false} to dark-disable it.
     */
    private boolean enabled = false;

    /**
     * Internal in-cluster base URL of admin-bff.
     *
     * <p>MUST be the direct k8s service address, e.g. {@code http://admin-bff:8080}.
     * Never set this to the public gateway URL — see deployment invariant above.
     */
    private String bffBaseUrl = "http://admin-bff:8080";

    /**
     * Timeout (milliseconds) for each introspection call to the BFF.
     * If the BFF does not respond within this window the filter fails closed
     * with 503 Service Unavailable.
     */
    private int timeoutMs = 2000;

    /**
     * Path patterns to skip without calling the BFF. Requests whose path
     * matches any of these patterns are passed through immediately (the BFF
     * has nothing to resolve on public / unauthenticated endpoints, and
     * calling it would be wasteful).
     *
     * <p>These mirror the {@code PUBLIC_PATHS} and
     * {@code HOMESERVER_PASSTHROUGH_PATHS} sets from
     * {@link SecurityConfig} plus infrastructure endpoints.
     */
    /**
     * The value sent as {@code X-Internal-Token} to the BFF's
     * {@code /bff/internal/session/introspect} endpoint. The BFF's
     * {@code InternalTokenWebFilter} is non-enforcing when blank (dev) and
     * enforcing (constant-time compare) when non-blank (prod). Supply via
     * {@code INTERNAL_TOKEN} env var; never commit the value.
     */
    private String internalToken = "";

    /**
     * Header name for the internal-token. Default matches admin-bff's
     * {@code InternalTokenWebFilter} default.
     */
    private String internalTokenHeader = "X-Internal-Token";

    private List<String> skipPaths = new ArrayList<>(List.of(
            "/api/auth/**",
            "/api/registration/**",
            "/api/login/**",
            "/_remotes/login/**",
            "/_remotes/registration/**",
            "/bff/public/announcements/**",
            "/bff/public/appeal-contact",
            "/_matrix/**",
            "/api/v1/**",
            "/api/v2/**",
            "/oauth/**",
            "/.well-known/**",
            "/actuator/**"
    ));

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getBffBaseUrl() {
        return bffBaseUrl;
    }

    public void setBffBaseUrl(String bffBaseUrl) {
        this.bffBaseUrl = bffBaseUrl;
    }

    public int getTimeoutMs() {
        return timeoutMs;
    }

    public void setTimeoutMs(int timeoutMs) {
        this.timeoutMs = timeoutMs;
    }

    public String getInternalToken() {
        return internalToken;
    }

    public void setInternalToken(String internalToken) {
        this.internalToken = internalToken;
    }

    public String getInternalTokenHeader() {
        return internalTokenHeader;
    }

    public void setInternalTokenHeader(String internalTokenHeader) {
        this.internalTokenHeader = internalTokenHeader;
    }

    public List<String> getSkipPaths() {
        return List.copyOf(skipPaths);
    }

    public void setSkipPaths(List<String> skipPaths) {
        this.skipPaths = new ArrayList<>(skipPaths);
    }
}
