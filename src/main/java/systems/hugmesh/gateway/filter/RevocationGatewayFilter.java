package systems.hugmesh.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import systems.hugmesh.gateway.cache.RevocationListService;
import systems.hugmesh.gateway.security.Roles;

import java.util.Optional;

import java.util.Optional;

/**
 * Cuts off both incoming and outgoing traffic for revoked principals
 * by short-circuiting the gateway filter chain with a 403. Checks
 * both the internal-OAuth subject ({@code subject:<casdoor-id>}) and
 * the external-OAuth identity ({@code external:<provider>:<id>}) so
 * a single block kills every authenticated channel for the user.
 *
 * <p>Reactive — pulls the JWT from the SecurityContext on each
 * request, hash-lookups the local RevocationListService snapshot
 * (constant time), and either rejects with 403 or forwards. No
 * Cassandra hit per request — the polling refresh inside the cache
 * service is what reconciles cluster-wide.
 */
@Component
public class RevocationGatewayFilter implements WebFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(RevocationGatewayFilter.class);

    private final RevocationListService revocations;

    /**
     * When {@code true} (default), an AUTHENTICATED request is held fail-CLOSED with a
     * {@code 503} during the never-primed cold-start window — the gap between boot and
     * the first successful revocation-cache poll, where the snapshot is empty and a
     * genuinely-revoked subject would otherwise be let through ({@code isRevoked}
     * returns {@code false} for every key). Once the cache is primed (or when
     * revocation is disabled / Cassandra unwired, where {@link RevocationListService#isPrimed}
     * is {@code true} unconditionally) this gate is inert. Set {@code false} to restore
     * the legacy never-primed fail-OPEN behaviour. This is distinct from — and does NOT
     * touch — the intentional transient-blip fail-open (a poll error retains the prior
     * primed snapshot rather than gating every request).
     */
    private final boolean failClosedUntilPrimed;

    public RevocationGatewayFilter(
            RevocationListService revocations,
            @Value("${app.revocation.fail-closed-until-primed:true}") boolean failClosedUntilPrimed) {
        this.revocations = revocations;
        this.failClosedUntilPrimed = failClosedUntilPrimed;
        log.info("[revocation] never-primed gate {} (app.revocation.fail-closed-until-primed)",
                failClosedUntilPrimed ? "fail-CLOSED (503)" : "fail-OPEN");
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        // Wrap the principal in Optional + defaultIfEmpty so the stream emits EXACTLY
        // ONE element: a present auth, or an explicit "absent". A bare
        // flatMap(...).switchIfEmpty(chain.filter(exchange)) is WRONG here — the
        // flatMap body returns Mono<Void> (always empty on the onNext channel), so the
        // switchIfEmpty fires AGAIN after a forward (and after a reject), re-subscribing
        // the WHOLE downstream chain a second time. That double-execution was masked
        // while this filter ran before Spring Security (no principal => the single
        // switchIfEmpty branch), but once it runs AFTER security (principal present) it
        // would re-run every downstream filter on every authenticated request. The
        // Optional makes present-vs-anonymous unambiguous so the chain is subscribed
        // exactly once — identical authorization decisions, mirroring the sibling
        // ExternalAuthHeaderFilter / GatewayRouteAccessFilter / ResourceAccessFilter
        // which already avoid this switchIfEmpty-on-a-Void-chain footgun.
        return exchange.getPrincipal()
            .cast(AbstractAuthenticationToken.class)
            .map(Optional::of)
            .defaultIfEmpty(Optional.empty())
            .flatMap(maybeAuth -> {
                if (maybeAuth.isEmpty()) {
                    // Unauthenticated traffic — let SecurityConfig decide. Forward once.
                    return chain.filter(exchange);
                }
                var auth = maybeAuth.get();
                // Never-primed cold-start fail-CLOSED gate. Only an AUTHENTICATED
                // principal reaches here (anonymous forwarded above for SecurityConfig).
                // Before the first successful poll, the snapshot is empty and isRevoked()
                // can't tell a revoked subject from a clean one — so we cannot SAFELY
                // make the allow/deny decision. We hold the request with a 503
                // SERVICE_UNAVAILABLE + Retry-After (NOT a 403: the subject is not
                // known-revoked, the gate is simply not yet authoritative). isPrimed()
                // is TRUE when revocation is disabled / Cassandra unwired, so single-
                // tenant / dev never gates here.
                if (failClosedUntilPrimed && !revocations.isPrimed()) {
                    return notPrimed(exchange);
                }
                if (auth.getPrincipal() instanceof Jwt jwt) {
                    String casdoorId = Roles.casdoorIdOf(jwt);
                    if (casdoorId != null && revocations.isRevoked("subject:" + casdoorId)) {
                        return reject(exchange, "subject:" + casdoorId);
                    }
                    // Defense-in-depth: ALSO check the bare-username-keyed form. Admin-bff's
                    // suspension code (AbstractAccessSyncAction#enforceSuspension) writes
                    // "subject:<casdoorUsername>" using the bare Casdoor USERNAME (via
                    // casdoorUsernameOf — org/username and provider-prefix stripped), NOT
                    // necessarily the same string as casdoorIdOf(jwt) above (jwt "sub"/"id").
                    // Whether Casdoor's real "sub" claim equals the bare username or an
                    // opaque generated user id is unresolved in this org's docs; this check
                    // closes the gap regardless of which form "sub" turns out to be. Purely
                    // additive — guarded against null/blank and against redundantly
                    // re-checking the identical string already checked above.
                    String username = Roles.usernameOf(jwt);
                    if (username != null && !username.isBlank() && !username.equals(casdoorId)
                            && revocations.isRevoked("subject:" + username)) {
                        return reject(exchange, "subject:" + username);
                    }
                }
                // External-Authorization side: if the gateway has
                // appended an external-auth header, also check the
                // matching `external:<provider>:<id>` key. Header
                // shape is set by ExternalAuthHeaderFilter below.
                String extProvider = exchange.getRequest().getHeaders().getFirst("External-Auth-Provider");
                String extId       = exchange.getRequest().getHeaders().getFirst("External-Auth-Id");
                if (extProvider != null && extId != null) {
                    String key = "external:" + extProvider + ":" + extId;
                    if (revocations.isRevoked(key)) return reject(exchange, key);
                }
                return chain.filter(exchange);
            });
    }

    /** Cold-start fail-CLOSED hold: the revocation cache has never been primed, so the
     *  gate cannot yet make an authoritative allow/deny call. Respond 503 with a short
     *  Retry-After so the client backs off and retries once the first poll lands —
     *  intentionally NOT a 403 (the subject is not known-revoked). */
    private Mono<Void> notPrimed(ServerWebExchange exchange) {
        log.warn("[revocation] holding request fail-CLOSED — cache not yet primed, path={}",
                exchange.getRequest().getPath().value());
        exchange.getResponse().setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
        // Refresh interval default is 5s; advise the client to retry shortly.
        exchange.getResponse().getHeaders().add(HttpHeaders.RETRY_AFTER, "5");
        return exchange.getResponse().setComplete();
    }

    private Mono<Void> reject(ServerWebExchange exchange, String key) {
        log.warn("[revocation] denied request — key={} path={}",
                key, exchange.getRequest().getPath().value());
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        exchange.getResponse().getHeaders().add("X-Revoked", revocations.reasonFor(key));
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        // Run AFTER Spring Security's WebFilterChainProxy (registered at order
        // -100), NOT before it. These principal-dependent filters share ONE
        // ascending @Order namespace with WebFilterChainProxy because
        // WebHttpHandlerBuilder merges every WebFilter bean together; ordering at
        // Ordered.HIGHEST_PRECEDENCE (Integer.MIN_VALUE) put us far BEFORE -100, so
        // we ran before the SecurityContext was populated and exchange.getPrincipal()
        // was always empty — the revocation check FAILED OPEN (forwarded every
        // revoked subject as anonymous). A small POSITIVE order keeps us after the
        // security chain (principal now resolves) but still before the routing filter
        // (RoutePredicateHandlerMapping/forwarding), so a revoked subject never
        // reaches the downstream service. Relative order preserved: revocation (10) <
        // external-auth (20) < route-access (25) < resource-access (30).
        return 10;
    }
}
