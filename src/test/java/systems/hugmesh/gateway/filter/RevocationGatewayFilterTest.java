package systems.hugmesh.gateway.filter;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ServerWebExchangeDecorator;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import systems.hugmesh.gateway.cache.RevocationListService;

import java.security.Principal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * KEYSTONE test (D3 — {@link RevocationGatewayFilter} previously had ZERO tests).
 *
 * <p>The filter sits after authentication and before routing. It cuts off BOTH the
 * internal-OAuth channel ({@code subject:<casdoor-id>}) and the external-OAuth
 * channel ({@code external:<provider>:<id>}) for a revoked principal by
 * short-circuiting the gateway filter chain with a {@code 403}. These tests drive
 * the filter directly with a {@link MockServerWebExchange} + a primed
 * {@link RevocationListService} snapshot — no Cassandra, fully deterministic.
 *
 * <p>Categories per the comprehensive test standard:
 * <ul>
 *   <li>USER-SITUATIONAL — one principal's own request is allowed (not revoked) or
 *       denied (revoked) across the internal + external channels;</li>
 *   <li>CROSS-USER (ISOLATION) — revoking principal A's key denies A's request but
 *       leaves principal B's request flowing (the revocation is scoped to the key,
 *       not the path);</li>
 *   <li>FAIL-MODE — the never-primed cold-start window is asserted explicitly: it
 *       fails CLOSED with a 503 by default (see
 *       {@link #failMode_notPrimed_failsClosedWith503_default}), fails OPEN when the
 *       {@code app.revocation.fail-closed-until-primed} flag is off, stays inert when
 *       revocation is disabled / unwired, and lifts once the cache is primed.</li>
 * </ul>
 */
class RevocationGatewayFilterTest {

    /** A revocation service with no datastore wired (cql==null). Its local snapshot
     *  is whatever the test primes via {@link RevocationListService#primeRevokedForTest}. */
    private static RevocationListService serviceWith(Set<String> revoked) {
        RevocationListService svc = new RevocationListService(null, true);
        svc.primeRevokedForTest(revoked);
        return svc;
    }

    /** A filter with the default-TRUE never-primed fail-CLOSED gate. With a
     *  {@code serviceWith(...)} service (cql==null) {@code isPrimed()} is TRUE
     *  unconditionally, so the gate is inert and the allow/deny assertions read
     *  exactly as before — single-tenant / dev never gates. */
    private static RevocationGatewayFilter filterFor(RevocationListService svc) {
        return new RevocationGatewayFilter(svc, true);
    }

    /** A filter with the never-primed gate explicitly DISABLED (legacy fail-OPEN). */
    private static RevocationGatewayFilter filterFailOpen(RevocationListService svc) {
        return new RevocationGatewayFilter(svc, false);
    }

    private static Jwt jwt(String subject) {
        return Jwt.withTokenValue("test")
                .header("alg", "none")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .subject(subject)
                .issuer("http://casdoor:8000")
                .claim("roles", List.of(Map.of("name", "user")))
                .claim("name", subject)
                .build();
    }

    /** A JWT whose "sub" claim is an opaque, UUID-shaped Casdoor-generated id and
     *  whose "name" claim is the bare, human-readable username — the two claims
     *  are DELIBERATELY DIFFERENT strings, mirroring the real ambiguity: admin-bff's
     *  suspension code writes the gateway revocation key off the bare USERNAME, not
     *  off whatever "sub" turns out to be. */
    private static Jwt jwtWithUuidSubjectAndUsername(String uuidSubject, String username) {
        return Jwt.withTokenValue("test")
                .header("alg", "none")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .subject(uuidSubject)
                .issuer("http://casdoor:8000")
                .claim("roles", List.of(Map.of("name", "user")))
                .claim("name", username)
                .build();
    }

    private static AbstractAuthenticationToken authFor(Jwt jwt) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        return new JwtAuthenticationToken(jwt, authorities);
    }

    /** Run the filter against a request; returns the exchange + whether the
     *  downstream chain was invoked (i.e. the request was forwarded, not 403'd). */
    private static Outcome run(RevocationGatewayFilter filter,
                               MockServerHttpRequest.BaseBuilder<?> reqBuilder,
                               AbstractAuthenticationToken auth) {
        MockServerWebExchange mwex = MockServerWebExchange.from(reqBuilder.build());
        AtomicBoolean chainSubscribed = new AtomicBoolean(false);
        WebFilterChain chain = ex -> Mono.fromRunnable(() -> chainSubscribed.set(true));
        ServerWebExchange exchange = auth == null ? mwex : new ExchangeWithPrincipal(mwex, auth);
        filter.filter(exchange, chain).block();
        // The AUTHORITATIVE signal of a deny is the committed response status (403).
        // Since the filter now emits exactly one element (Optional + defaultIfEmpty),
        // chain-subscription IS a reliable discriminator too — a reject subscribes the
        // chain ZERO times, a forward exactly ONCE (see reject_doesNotSubscribe... /
        // forward_subscribesChainExactlyOnce). We still key `forwarded` off the absence
        // of a 403 so the existing allow/deny assertions read identically.
        boolean denied = mwex.getResponse().getStatusCode() == HttpStatus.FORBIDDEN;
        return new Outcome(mwex, !denied, chainSubscribed.get());
    }

    private record Outcome(MockServerWebExchange exchange, boolean forwarded, boolean chainSubscribed) {}

    // ── USER-SITUATIONAL — internal (subject:) channel ────────────────────────

    @Test
    void userSituational_revokedSubject_isRejectedWith403_atTheFilter() {
        // A JWT whose subject is on the revoked list (key "subject:<id>") is denied
        // at the filter with 403 — the downstream chain is NEVER invoked.
        RevocationGatewayFilter filter =
                filterFor(serviceWith(Set.of("subject:revoked-1")));
        Outcome out = run(filter, MockServerHttpRequest.get("/api/anything"),
                authFor(jwt("revoked-1")));

        assertThat(out.forwarded())
                .as("a revoked subject must be short-circuited, never forwarded").isFalse();
        assertThat(out.exchange().getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        // The 403 carries the revocation reason header (empty string when no reason
        // was primed — the filter still stamps the header).
        assertThat(out.exchange().getResponse().getHeaders().headerNames())
                .as("the deny response advertises the revocation").contains("X-Revoked");
    }

    @Test
    void userSituational_nonRevokedSubject_passesThrough() {
        // A JWT whose subject is NOT on the revoked list flows to the downstream
        // chain — no 403, no short-circuit.
        RevocationGatewayFilter filter =
                filterFor(serviceWith(Set.of("subject:someone-else")));
        Outcome out = run(filter, MockServerHttpRequest.get("/api/anything"),
                authFor(jwt("good-user")));

        assertThat(out.forwarded()).as("a non-revoked subject must pass through").isTrue();
        assertThat(out.chainSubscribed()).as("the downstream chain is actually reached").isTrue();
        assertThat(out.exchange().getResponse().getStatusCode()).isNull();
    }

    @Test
    void userSituational_revokedByUsername_uuidSubjectStillRejected_usernameFallback() {
        // The gap this test pins: admin-bff's suspension code writes
        // "subject:<bare-casdoor-username>" (AbstractAccessSyncAction#enforceSuspension),
        // NOT "subject:<sub>". If a real Casdoor-issued JWT's "sub" claim turns out to be
        // an opaque generated user id (UUID-shaped) rather than the bare username, the
        // casdoorIdOf-only check can never match that revocation key. Only
        // "subject:<username>" (NOT "subject:<uuid>") is on the revoked list here — the
        // request must still be rejected via the Roles.usernameOf(jwt) fallback check.
        String uuidSubject = "8f14e45f-ceea-4a4a-9d1f-7f6cd2b8a9e0";
        String username = "alice.suspended";
        RevocationGatewayFilter filter =
                filterFor(serviceWith(Set.of("subject:" + username)));
        Outcome out = run(filter, MockServerHttpRequest.get("/api/anything"),
                authFor(jwtWithUuidSubjectAndUsername(uuidSubject, username)));

        assertThat(out.forwarded())
                .as("a JWT whose bare username is revoked must be rejected even though its "
                        + "opaque 'sub' (UUID) is NOT itself on the revoked list").isFalse();
        assertThat(out.exchange().getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(out.chainSubscribed())
                .as("the username-fallback reject is terminal — downstream chain not reached").isFalse();
    }

    @Test
    void userSituational_neitherUuidSubjectNorUsernameRevoked_passesThrough() {
        // Companion non-vacuity check: when NEITHER "subject:<uuid>" nor
        // "subject:<username>" is on the revoked list, the request forwards normally —
        // the new username-fallback check does not over-trigger.
        String uuidSubject = "8f14e45f-ceea-4a4a-9d1f-7f6cd2b8a9e0";
        String username = "alice.suspended";
        RevocationGatewayFilter filter =
                filterFor(serviceWith(Set.of("subject:someone-else-entirely")));
        Outcome out = run(filter, MockServerHttpRequest.get("/api/anything"),
                authFor(jwtWithUuidSubjectAndUsername(uuidSubject, username)));

        assertThat(out.forwarded()).isTrue();
        assertThat(out.chainSubscribed()).isTrue();
        assertThat(out.exchange().getResponse().getStatusCode()).isNull();
    }

    // ── USER-SITUATIONAL — external (external:provider:id) channel ─────────────

    @Test
    void userSituational_revokedExternalIdentity_isRejectedWith403() {
        // The external-OAuth side: the gateway appended External-Auth-Provider /
        // External-Auth-Id headers; the matching "external:<provider>:<id>" key is
        // on the revoked list -> 403, even though the JWT subject itself is clean.
        RevocationGatewayFilter filter = filterFor(serviceWith(Set.of("external:github:gh-9000")));
        Outcome out = run(filter,
                MockServerHttpRequest.get("/api/anything")
                        .header("External-Auth-Provider", "github")
                        .header("External-Auth-Id", "gh-9000"),
                authFor(jwt("clean-subject")));

        assertThat(out.forwarded())
                .as("a revoked external identity must be denied even with a clean JWT subject")
                .isFalse();
        assertThat(out.exchange().getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void userSituational_nonRevokedExternalIdentity_passesThrough() {
        RevocationGatewayFilter filter = filterFor(serviceWith(Set.of("external:github:some-other")));
        Outcome out = run(filter,
                MockServerHttpRequest.get("/api/anything")
                        .header("External-Auth-Provider", "github")
                        .header("External-Auth-Id", "gh-9000"),
                authFor(jwt("clean-subject")));

        assertThat(out.forwarded()).isTrue();
        assertThat(out.exchange().getResponse().getStatusCode()).isNull();
    }

    @Test
    void unauthenticated_request_passesThrough_securityConfigDecides() {
        // No principal at all (anonymous traffic). The filter's switchIfEmpty path
        // forwards — SecurityConfig's authorizeExchange floor (401) is what gates
        // anonymous access, not the revocation filter.
        RevocationGatewayFilter filter =
                filterFor(serviceWith(Set.of("subject:revoked-1")));
        Outcome out = run(filter, MockServerHttpRequest.get("/api/anything"), null);

        assertThat(out.forwarded())
                .as("unauthenticated traffic is forwarded for SecurityConfig to decide").isTrue();
    }

    // ── CROSS-USER (ISOLATION) ────────────────────────────────────────────────

    @Test
    void crossUser_revokingA_deniesA_butLeavesBFlowing() {
        // The revocation is scoped to the KEY, not the path. Revoking user A's
        // subject denies A's request (DENY) while user B (same path, different
        // subject) still flows (ALLOW). Both directions on one snapshot.
        RevocationGatewayFilter filter =
                filterFor(serviceWith(Set.of("subject:user-A")));

        Outcome a = run(filter, MockServerHttpRequest.get("/api/shared"), authFor(jwt("user-A")));
        Outcome b = run(filter, MockServerHttpRequest.get("/api/shared"), authFor(jwt("user-B")));

        assertThat(a.forwarded()).as("revoked A is denied").isFalse();
        assertThat(a.exchange().getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(b.forwarded()).as("non-revoked B is unaffected by A's revocation").isTrue();
    }

    // ── BEHAVIOURAL PIN — a reject subscribes the chain EXACTLY ZERO times ─────

    @Test
    void reject_doesNotSubscribeDownstreamChain_singleSubscription() {
        // FORMER FINDING, NOW FIXED. The filter previously used
        // flatMap(...).switchIfEmpty(chain.filter(exchange)): reject() returns an empty
        // Mono<Void> (setComplete), and switchIfEmpty treated that empty completion the
        // same as "no principal" — so the downstream chain WAS subscribed even on the
        // deny path (and, worse, the WHOLE chain re-ran after a forward, double-
        // executing every downstream filter on every authenticated request). That was
        // harmless while this filter ran BEFORE Spring Security (no principal), but the
        // ordering fix makes it run AFTER security with a principal present, where the
        // double-subscription would re-fire downstream filters (a downstream filter's
        // reject() then writes a header on an already-committed, read-only response).
        // The filter now uses the same Optional + defaultIfEmpty single-emission
        // pattern as its siblings, so a reject subscribes the chain ZERO times and a
        // forward subscribes it exactly ONCE. The security contract — a revoked
        // principal gets 403 — is unchanged AND now strictly terminal.
        RevocationGatewayFilter filter =
                filterFor(serviceWith(Set.of("subject:revoked-1")));
        Outcome out = run(filter, MockServerHttpRequest.get("/api/anything"),
                authFor(jwt("revoked-1")));

        assertThat(out.exchange().getResponse().getStatusCode())
                .as("the committed response is 403 — the security contract").isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(out.chainSubscribed())
                .as("a revoked-subject reject is terminal — the downstream chain is NOT subscribed")
                .isFalse();
    }

    @Test
    void forward_subscribesChainExactlyOnce() {
        // The companion to the reject pin: a non-revoked principal forwards, and the
        // downstream chain is subscribed (once). Together with the reject pin above
        // this nails the single-emission contract that eliminates the former
        // switchIfEmpty-on-a-Void-chain double-subscription.
        RevocationGatewayFilter filter =
                filterFor(serviceWith(Set.of("subject:someone-else")));
        Outcome out = run(filter, MockServerHttpRequest.get("/api/anything"),
                authFor(jwt("good-user")));

        assertThat(out.forwarded()).isTrue();
        assertThat(out.chainSubscribed())
                .as("a non-revoked principal is forwarded — chain subscribed exactly once").isTrue();
        assertThat(out.exchange().getResponse().getStatusCode()).isNull();
    }

    // ── FAIL-MODE — never-primed cold-start window ────────────────────────────
    //
    // Supersedes the former failMode_emptySnapshot_failsOpen_FLAG. That test pinned
    // the never-primed fail-OPEN as a flagged window and noted a future fail-CLOSED
    // would be a "conscious, reviewed decision". This is that decision: the default-
    // TRUE app.revocation.fail-closed-until-primed gate holds an AUTHENTICATED request
    // with a 503 + Retry-After during the cold-start window (Cassandra wired but the
    // first poll has not yet primed the cache), where isRevoked() cannot tell a
    // revoked subject from a clean one. The flag can be set FALSE to restore the
    // legacy fail-OPEN. The intentional TRANSIENT-BLIP fail-open (a poll error retains
    // the prior PRIMED snapshot) is untouched — isPrimed() stays true once primed.

    @Test
    void failMode_notPrimed_failsClosedWith503_default() {
        // Cassandra is WIRED but no poll has succeeded — lastRefreshAt is still EPOCH,
        // so isPrimed()==false. With the default-TRUE gate, an authenticated request is
        // held fail-CLOSED with 503 SERVICE_UNAVAILABLE + Retry-After. NOT a 403: the
        // subject is not known-revoked, the gate is simply not yet authoritative. The
        // downstream chain is NEVER subscribed.
        RevocationListService svc = new RevocationListService(null, true);
        svc.markCassandraWiredForTest();      // isPrimed() now consults lastRefreshAt
        // deliberately NOT primed — lastRefreshAt stays Instant.EPOCH
        assertThat(svc.isPrimed())
                .as("a Cassandra-wired service before its first poll is NOT primed").isFalse();

        RevocationGatewayFilter filter = filterFor(svc); // fail-closed-until-primed = true
        Outcome out = run(filter, MockServerHttpRequest.get("/api/anything"),
                authFor(jwt("would-be-revoked")));

        assertThat(out.exchange().getResponse().getStatusCode())
                .as("FAIL-CLOSED: never-primed cold start holds the request with 503, not 403")
                .isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(out.exchange().getResponse().getStatusCode())
                .as("the hold is 503, distinctly NOT the 403 a known-revoked subject gets")
                .isNotEqualTo(HttpStatus.FORBIDDEN);
        assertThat(out.exchange().getResponse().getHeaders().getFirst(HttpHeaders.RETRY_AFTER))
                .as("the 503 advises the client to back off and retry once primed").isEqualTo("5");
        assertThat(out.chainSubscribed())
                .as("a fail-CLOSED hold is terminal — the downstream chain is NOT subscribed")
                .isFalse();
    }

    @Test
    void failMode_notPrimed_butGateDisabled_failsOpen() {
        // The flag is the off-switch: with app.revocation.fail-closed-until-primed=FALSE
        // the SAME never-primed state forwards the request (legacy fail-OPEN), proving
        // the 503 above is caused by the gate and not by some unrelated short-circuit
        // (non-vacuous).
        RevocationListService svc = new RevocationListService(null, true);
        svc.markCassandraWiredForTest();
        assertThat(svc.isPrimed()).isFalse();

        RevocationGatewayFilter filter = filterFailOpen(svc); // fail-closed-until-primed = false
        Outcome out = run(filter, MockServerHttpRequest.get("/api/anything"),
                authFor(jwt("would-be-revoked")));

        assertThat(out.forwarded())
                .as("FAIL-OPEN when the gate is disabled: an unprimed cache forwards").isTrue();
        assertThat(out.chainSubscribed()).as("the downstream chain is reached").isTrue();
        assertThat(out.exchange().getResponse().getStatusCode()).isNull();
    }

    @Test
    void failMode_revocationDisabledOrUnwired_failsOpen_singleTenantNeverGates() {
        // Single-tenant / dev: Cassandra UNWIRED (cql==null). isPrimed() returns TRUE
        // unconditionally — there is no poll to prime and no list to enforce — so the
        // default-TRUE gate is inert and a clean subject forwards normally. The
        // never-primed gate must NEVER hold these deployments closed.
        RevocationListService svc = serviceWith(Set.of()); // cql==null, enabled=true
        assertThat(svc.isPrimed())
                .as("an unwired (single-tenant) revocation service is always 'primed'").isTrue();

        RevocationGatewayFilter filter = filterFor(svc); // default-TRUE gate
        Outcome out = run(filter, MockServerHttpRequest.get("/api/anything"),
                authFor(jwt("good-user")));

        assertThat(out.forwarded())
                .as("disabled/unwired revocation forwards — the never-primed gate is inert").isTrue();
        assertThat(out.exchange().getResponse().getStatusCode()).isNull();
    }

    @Test
    void failMode_oncePrimed_forwardsNormally_default() {
        // Once the cache is primed (a refresh succeeded — simulated by markPrimedForTest,
        // exactly what refreshRevocations() does when it advances lastRefreshAt off EPOCH),
        // the default-TRUE gate is satisfied and a NON-revoked subject forwards normally.
        // This is the recovery side: the 503 hold is bounded by the first poll, not
        // permanent.
        RevocationListService svc = new RevocationListService(null, true);
        svc.markCassandraWiredForTest();
        assertThat(svc.isPrimed()).as("not primed before the first poll").isFalse();
        svc.markPrimedForTest();              // a refresh has now succeeded
        svc.primeRevokedForTest(Set.of("subject:someone-else"));
        assertThat(svc.isPrimed()).as("primed after the first successful poll").isTrue();

        RevocationGatewayFilter filter = filterFor(svc);
        Outcome out = run(filter, MockServerHttpRequest.get("/api/anything"),
                authFor(jwt("good-user")));

        assertThat(out.forwarded())
                .as("a primed cache forwards a non-revoked subject — the hold lifts").isTrue();
        assertThat(out.chainSubscribed()).isTrue();
        assertThat(out.exchange().getResponse().getStatusCode()).isNull();
    }

    @Test
    void failMode_oncePrimed_stillRejectsRevokedSubjectWith403_default() {
        // Companion to the forward-once-primed case: once primed, a genuinely-revoked
        // subject still gets the terminal 403 (the gate does not swallow real
        // revocations). Confirms the 503 path is strictly the never-primed window, not
        // a replacement for the deny path.
        RevocationListService svc = new RevocationListService(null, true);
        svc.markCassandraWiredForTest();
        svc.markPrimedForTest();
        svc.primeRevokedForTest(Set.of("subject:revoked-1"));
        assertThat(svc.isPrimed()).isTrue();

        RevocationGatewayFilter filter = filterFor(svc);
        Outcome out = run(filter, MockServerHttpRequest.get("/api/anything"),
                authFor(jwt("revoked-1")));

        assertThat(out.exchange().getResponse().getStatusCode())
                .as("a known-revoked subject still gets 403 once the cache is primed")
                .isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(out.chainSubscribed()).isFalse();
    }

    /** Populates getPrincipal() on a MockServerWebExchange (the mock leaves it an
     *  empty Mono otherwise). Mirrors the helper in the route-access filter test. */
    static class ExchangeWithPrincipal extends ServerWebExchangeDecorator {
        private final Principal principal;
        ExchangeWithPrincipal(ServerWebExchange delegate, Principal principal) {
            super(delegate);
            this.principal = principal;
        }
        @Override
        @SuppressWarnings("unchecked")
        public <T extends Principal> Mono<T> getPrincipal() {
            return Mono.just((T) principal);
        }
    }
}
