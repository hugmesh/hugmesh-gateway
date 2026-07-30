package systems.hugmesh.gateway.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import systems.hugmesh.gateway.cache.RevocationListService;
import systems.hugmesh.gateway.security.DomainRegistry;
import systems.hugmesh.gateway.security.Roles;

import java.util.Set;

/**
 * Internal HTTP surface for external callers (admin-bff ban path, user-bff personal-token
 * revocation) to write and clear keys on the gateway revocation list. The gateway's
 * {@link RevocationListService} was previously read-only from the HTTP perspective:
 * only its Cassandra-backed poll and the two test seams populated the local cache. This
 * controller exposes the write primitives ({@link RevocationListService#revoke} and
 * {@link RevocationListService#clear}) over HTTP so inter-BFF callers can durably
 * persist a revocation without waiting for the next Cassandra poll cycle.
 *
 * <p><b>Endpoint contract</b>
 * <ul>
 *   <li>{@code POST /api/gateway/revocations} — write (or refresh) a revocation key.
 *       Body: {@code {"key": "...", "reason": "...", "ttlSeconds": 86400}}. Returns
 *       204 on success. {@code ttlSeconds} is optional (defaults to 0, meaning the
 *       table-level TTL applies); a non-positive value falls back to the table default.
 *       {@code reason} is optional — omitted or null is stored as-is in Cassandra.</li>
 *   <li>{@code DELETE /api/gateway/revocations/{key}} — lift a key off the list (the
 *       restore path: un-ban, suspension expiry, re-grant of an external-client role).
 *       Returns 204. The gateway enforces the key's absence immediately on this pod;
 *       other pods converge on their next poll tick.</li>
 * </ul>
 *
 * <p><b>Security.</b> Both endpoints require {@code ROLE_ADMIN} (or
 * {@code ROLE_SUPERADMIN} via the role hierarchy). The caller is an internal BFF
 * that presents a Casdoor JWT with at minimum {@code ROLE_ADMIN} — user-bff and
 * admin-bff share the same Casdoor realm as the gateway and thus have a suitable
 * service-account JWT. An external non-authenticated actor can never reach this
 * endpoint.
 *
 * <p><b>Cross-tenant gate (multi-brand; CWE-639).</b> {@code ROLE_ADMIN} alone is
 * NOT enough: a per-brand admin must only revoke / restore within their OWN brand.
 * The caller's tenant is derived from the cryptographically-VALIDATED JWT issuer
 * via {@link Roles#domainOf(Jwt, DomainRegistry)} (never a user-settable claim),
 * exactly as the gateway route-access filter does. Each revocation row records the
 * writer's owning {@code domain}; a non-SUPERADMIN caller is rejected with 403 when
 * it tries to clear — or overwrite/refresh — a key owned by a DIFFERENT domain, so
 * a brand-X admin can no longer ban or un-ban a brand-Y subject. {@code SUPERADMIN}
 * (the infra control plane) is exempt and may act across brands; single-tenant
 * clusters ({@code default}) and pre-existing unscoped rows are unaffected
 * (back-compat). A caller whose domain cannot be proven (null — e.g. an untrusted
 * issuer slipping past upstream) fails CLOSED with 403.
 *
 * <p><b>Key shapes</b> (per the design; see {@link RevocationListService}):
 * <ul>
 *   <li>{@code subject:<casdoor-id>} — full Casdoor-auth revocation;</li>
 *   <li>{@code external:<provider>:<external-id>} — external-OAuth revocation;</li>
 *   <li>{@code hs:<platform>:<localpart>} — coarse homeserver ban;</li>
 *   <li>{@code hs:<platform>:<localpart>:<deviceId|appId>} — per-credential;</li>
 *   <li>{@code external-client:<localpart>:<platform>} — personal-token-only gate.</li>
 * </ul>
 *
 * <p>This controller deliberately does NOT validate which prefix a caller uses —
 * that is the caller's responsibility (admin-bff writes {@code subject:*} and
 * {@code hs:*} for bans; user-bff writes {@code hs:*:<id>} and
 * {@code external-client:*} for per-credential / personal-client revocations). The
 * revocation list is a durable key store; semantic correctness is the caller's domain.
 *
 * <p>The companion feature flag {@code app.hs-revocation.enabled} is intentionally
 * NOT checked here — that gate is on the filter that reads the list, not the write
 * path. Writing revocation keys while the read gate is off is safe and useful: keys
 * accumulate in Cassandra and the filter picks them up immediately when the seam is
 * flipped on, with no data-loss race.
 */
@RestController
@RequestMapping("/api/gateway/revocations")
@PreAuthorize("hasRole('ADMIN')")
public class GatewayRevocationController {

    private static final Logger log = LoggerFactory.getLogger(GatewayRevocationController.class);

    private final RevocationListService revocationListService;
    private final DomainRegistry domainRegistry;

    public GatewayRevocationController(RevocationListService revocationListService,
                                       DomainRegistry domainRegistry) {
        this.revocationListService = revocationListService;
        this.domainRegistry = domainRegistry;
    }

    /**
     * The caller's tenant from the cryptographically-validated JWT issuer
     * ({@code null}/blank/"default" -&gt; UNSCOPED single-tenant). NEVER derived from
     * a user-settable claim. Mirrors {@code GatewayRouteAccessFilter}.
     */
    private String callerDomain(Jwt jwt) {
        String d = Roles.domainOf(jwt, domainRegistry);
        return (d == null || d.isBlank()
                || DomainRegistry.DEFAULT_DOMAIN.equalsIgnoreCase(d.trim())) ? null : d.trim();
    }

    /**
     * Cross-tenant gate (CWE-639). The owner is the key's recorded owning domain
     * ({@code null} = unscoped/back-compat, admits anyone). A SUPERADMIN bypasses.
     * A caller whose domain cannot be proven fails CLOSED. Otherwise the caller's
     * domain must equal the key's owner.
     *
     * @return a 403 {@link ResponseStatusException} signal to short-circuit, or
     *         empty (allowed). Fail-closed: assembled BEFORE the protected write.
     */
    private Mono<Void> requireSameTenant(Jwt jwt, String rawOwner, String key, String op) {
        if (Roles.isSuperadmin(jwt)) return Mono.empty();               // infra control plane — cross-brand
        // A null/blank/"default" owner is UNSCOPED (single-tenant + pre-domain-column
        // rows) — admits any admin, exactly like an unscoped route-access row.
        if (rawOwner == null || rawOwner.isBlank()
                || DomainRegistry.DEFAULT_DOMAIN.equalsIgnoreCase(rawOwner.trim())) {
            return Mono.empty();
        }
        String owner = rawOwner.trim();
        String caller = callerDomain(jwt);
        if (caller != null && caller.equalsIgnoreCase(owner)) return Mono.empty();
        log.warn("[gateway-revocation] cross-tenant {} DENIED — caller-domain={} key-owner={} key={}",
                op, caller, owner, key);
        return Mono.error(new ResponseStatusException(
                HttpStatus.FORBIDDEN, "cross-tenant revocation denied"));
    }

    /**
     * Write (or refresh) a revocation key. Persists the key to Cassandra and immediately
     * reflects it in the local cache on this pod; other pods converge within one poll tick
     * (≈ the {@code app.revocation.refresh-interval-ms} value, default 5 s).
     *
     * <p>Scoped to the caller's validated-issuer brand: the row is stamped with the
     * caller's domain, and a non-SUPERADMIN caller is rejected (403) if the key is
     * already OWNED by a different brand — so it can neither hijack nor refresh
     * another brand's revocation. The tenant gate is assembled and evaluated BEFORE
     * the write (fail-CLOSED): on a cross-tenant attempt the {@code revoke} below is
     * never reached.
     *
     * @param body JSON object with required {@code key} field, optional {@code reason}, and
     *             optional {@code ttlSeconds} (non-positive defaults to the table TTL of 86400 s).
     * @param jwt  the authenticated caller (the validated-issuer tenant discriminator).
     * @return 204 No Content on success; 403 on a cross-tenant attempt.
     */
    @PostMapping
    public Mono<ResponseEntity<Void>> revoke(@RequestBody RevocationRequest body,
                                             @AuthenticationPrincipal Jwt jwt) {
        String key = body.key();
        if (key == null || key.isBlank()) {
            return Mono.just(ResponseEntity.badRequest().<Void>build());
        }
        String reason = body.reason() != null ? body.reason() : "";
        long ttl = body.ttlSeconds() != null ? body.ttlSeconds() : 0L;
        String caller = callerDomain(jwt);
        log.debug("[gateway-revocation] POST revoke key={} ttl={}s caller-domain={}", key, ttl, caller);
        String existingOwner = revocationListService.domainOfKey(key);
        // Fail-CLOSED: the cross-tenant gate (overwrite/refresh of a foreign brand's
        // key) short-circuits with 403 BEFORE the write is assembled, so a denied
        // caller never persists or refreshes the row.
        return requireSameTenant(jwt, existingOwner, key, "revoke")
                .then(Mono.defer(() -> revocationListService.revoke(key, reason, ttl, caller)))
                .thenReturn(ResponseEntity.noContent().<Void>build());
    }

    /**
     * Lift a key off the revocation list (the restore path). The gateway denies the key
     * immediately on this pod; other pods converge on their next poll tick.
     *
     * <p>Scoped to the caller's validated-issuer brand: a non-SUPERADMIN caller is
     * rejected (403) if the key is OWNED by a different brand — so a brand-X admin
     * cannot un-ban a brand-Y subject. The tenant gate is evaluated BEFORE the
     * DELETE (fail-CLOSED): on a cross-tenant attempt the {@code clear} below is
     * never reached.
     *
     * @param key URL-encoded revocation key (e.g. {@code hs:matrix:alice:dev1}).
     * @param jwt the authenticated caller (the validated-issuer tenant discriminator).
     * @return 204 No Content on success; 403 on a cross-tenant attempt.
     */
    @DeleteMapping("/{key}")
    public Mono<ResponseEntity<Void>> clear(@PathVariable String key,
                                            @AuthenticationPrincipal Jwt jwt) {
        log.debug("[gateway-revocation] DELETE clear key={} caller-domain={}", key, callerDomain(jwt));
        String owner = revocationListService.domainOfKey(key);
        return requireSameTenant(jwt, owner, key, "clear")
                .then(Mono.defer(() -> revocationListService.clear(key)))
                .thenReturn(ResponseEntity.noContent().<Void>build());
    }

    /**
     * Return the current revoked-key snapshot from this pod's local cache.
     * Intended for SUPERADMIN observability — the set contains user identifiers and
     * must not be exposed to lower-privilege callers.
     *
     * @return 200 with the snapshot set (empty set when revocation is disabled or
     *         Cassandra is not wired).
     */
    @GetMapping
    @PreAuthorize("hasRole('SUPERADMIN')")
    public Mono<ResponseEntity<Set<String>>> snapshot() {
        return Mono.just(ResponseEntity.ok(revocationListService.snapshot()));
    }

    /**
     * Request body for {@link #revoke}. All fields except {@code key} are optional.
     *
     * @param key        The revocation key to write (required, non-blank).
     * @param reason     Human-readable reason stored in Cassandra and surfaced in 403
     *                   response headers (optional).
     * @param ttlSeconds TTL in seconds for the Cassandra row; non-positive or omitted
     *                   values fall back to the table-level default (86400 s). Should
     *                   be {@code >=} the remaining token lifetime so the key outlives
     *                   the credential it gates.
     */
    public record RevocationRequest(String key, String reason, Long ttlSeconds) {}
}
