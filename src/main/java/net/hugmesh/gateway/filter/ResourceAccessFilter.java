package net.hugmesh.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import net.hugmesh.gateway.cache.ResourceAuthorizationService;
import net.hugmesh.gateway.security.Roles;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Per-resource authorization gate — pairs with {@link
 * net.hugmesh.gateway.cache.UrlRegistryService} so that even
 * after a route resolves to a registered downstream, the request only
 * forwards when the principal has an access grant for the specific
 * {@code resource_id} the URL targets.
 *
 * <p>Examples (path → resource tuple this filter extracts):
 *
 * <pre>
 *   /api/games/{slug}/launch                  → game:{slug}
 *   /api/games/{slug}/levels                  → game:{slug}
 *   /api/assets/levels/{slug}/...             → game:{slug}
 *   /api/sessions/{id}/...                    → session:{id}
 *   /api/chapters/{numeric-id}/...            → asset:{numeric-id}
 * </pre>
 *
 * <p>Auth chain (short-circuits on first match):
 *
 * <ol>
 *   <li>{@code ROLE_ADMIN} OR {@code ROLE_GAME-MASTER} on the
 *       internal JWT — forwards unconditionally. This is the
 *       "admin's authorization still works without an external
 *       provider" contract: an admin token issued by Casdoor sails
 *       through every resource check regardless of whether an
 *       External-Authorization header is also present.</li>
 *   <li>Cassandra-cached user-specific grant ({@code <type>:<id>:<user>}).</li>
 *   <li>Cassandra-cached all-users grant ({@code <type>:<id>:*}).</li>
 *   <li>Cassandra-cached role grant for any role the user holds
 *       ({@code <type>:<id>:role:<role-name>}).</li>
 * </ol>
 *
 * <p>If none of the above match, the gateway rejects with 403 +
 * {@code X-Resource-Denied: <resource-tuple>} so a debug pass can
 * see why the request was killed without leaking the grant set.
 *
 * <p>Paths that don't carry a recognisable resource id (e.g. catalog
 * listings) are forwarded — SecurityConfig's role-based filter has
 * already authenticated the request, so a public/listing route is
 * by design above this layer.
 */
@Component
public class ResourceAccessFilter implements WebFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(ResourceAccessFilter.class);

    /** Pattern → (resource_type, capture-group-of-id). Evaluated in
     *  declaration order; first match wins. Add new patterns as new
     *  controllers come online. */
    private static final List<PatternRule> PATH_PATTERNS = List.of(
        new PatternRule("game",    Pattern.compile("^/api/games/([^/]+)(?:/.*)?$")),
        new PatternRule("game",    Pattern.compile("^/api/assets/levels/([^/]+)(?:/.*)?$")),
        new PatternRule("game",    Pattern.compile("^/_remotes/wasm-fragment/([^/]+)(?:/.*)?$")),
        new PatternRule("session", Pattern.compile("^/api/sessions/([^/]+)(?:/.*)?$")),
        new PatternRule("session", Pattern.compile("^/api/game/stream/?$")) // session-id is on the query; handled below
    );

    private final ResourceAuthorizationService authz;

    public ResourceAccessFilter(ResourceAuthorizationService authz) {
        this.authz = authz;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        ResourceTuple tuple = matchResource(path, exchange);
        if (tuple == null) {
            // Not a per-resource path — let SecurityConfig's coarse
            // role gates decide.
            return chain.filter(exchange);
        }

        // Wrap the principal in Optional + defaultIfEmpty so the stream emits
        // exactly one element. A bare flatMap(...).switchIfEmpty(chain.filter)
        // is WRONG: the flatMap body returns Mono<Void> (always empty on the
        // onNext channel), so switchIfEmpty fires even after reject() and the
        // request is forwarded downstream regardless — a 403 that doesn't
        // actually stop the request. The Optional makes present-vs-anonymous
        // unambiguous so a reject truly terminates the chain.
        return exchange.getPrincipal()
            .cast(AbstractAuthenticationToken.class)
            .map(java.util.Optional::of)
            .defaultIfEmpty(java.util.Optional.empty())
            .flatMap(maybeAuth -> {
                // Unauthenticated traffic: SecurityConfig already would have
                // 401'd anything that needed auth, so reaching here means the
                // SecurityConfig matcher matched a public path. We respect
                // that decision and forward without a resource check.
                if (maybeAuth.isEmpty()) {
                    return chain.filter(exchange);
                }
                AbstractAuthenticationToken auth = maybeAuth.get();
                // Admin / game-master bypass. The internal Casdoor JWT
                // alone is sufficient — no external-OAuth header
                // required. This is the explicit contract for "admin
                // authorization works without an external provider".
                if (auth.getPrincipal() instanceof Jwt jwt && (Roles.isAdmin(jwt) || Roles.isGameMaster(jwt))) {
                    return chain.filter(exchange);
                }
                String userId = (auth.getPrincipal() instanceof Jwt jwt)
                        ? Roles.casdoorIdOf(jwt) : null;
                if (authz.isGranted(tuple.type(), tuple.id(), userId)) {
                    return chain.filter(exchange);
                }
                List<String> roles = Roles.namesOf(auth.getAuthorities());
                if (authz.hasAnyRoleGrant(tuple.type(), tuple.id(), roles)) {
                    return chain.filter(exchange);
                }
                return reject(exchange, tuple);
            });
    }

    private Mono<Void> reject(ServerWebExchange exchange, ResourceTuple tuple) {
        log.warn("[resource-access] denied — path={} resource={}",
                exchange.getRequest().getPath().value(), tuple);
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        exchange.getResponse().getHeaders().add("X-Resource-Denied",
                tuple.type() + ":" + tuple.id());
        return exchange.getResponse().setComplete();
    }

    private static ResourceTuple matchResource(String path, ServerWebExchange exchange) {
        for (PatternRule rule : PATH_PATTERNS) {
            Matcher m = rule.pattern().matcher(path);
            if (m.matches()) {
                if (m.groupCount() >= 1 && m.group(1) != null) {
                    return new ResourceTuple(rule.resourceType(), m.group(1));
                }
                // Query-string fallback for routes whose id lives in
                // ?sessionId= rather than the path (matches the BFF's
                // /api/game/stream contract).
                String sessionId = exchange.getRequest().getQueryParams().getFirst("sessionId");
                if (sessionId != null && !sessionId.isBlank()) {
                    return new ResourceTuple(rule.resourceType(), sessionId);
                }
            }
        }
        return null;
    }

    @Override
    public int getOrder() {
        // Run AFTER Spring Security's WebFilterChainProxy (order -100) so
        // exchange.getPrincipal() resolves — see the ordering note on
        // RevocationGatewayFilter#getOrder. Before the ordering fix this filter ran
        // at Integer.MIN_VALUE+300 (far before -100), saw no principal, and forwarded
        // every authenticated per-resource request through its anonymous branch — so
        // the per-resource grant check failed OPEN. A positive order keeps it after
        // revocation (10) + External-Authorization header injection (20) +
        // route-access (25) but before downstream routing.
        return 30;
    }

    private record PatternRule(String resourceType, Pattern pattern) {}
    private record ResourceTuple(String type, String id) {}
}
