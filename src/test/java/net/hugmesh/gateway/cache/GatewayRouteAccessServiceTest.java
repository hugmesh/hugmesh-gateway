package net.hugmesh.gateway.cache;

import org.junit.jupiter.api.Test;
import org.springframework.cloud.client.circuitbreaker.ConfigBuilder;
import org.springframework.cloud.client.circuitbreaker.ReactiveCircuitBreaker;
import org.springframework.cloud.client.circuitbreaker.ReactiveCircuitBreakerFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.gateway.cache.GatewayRouteAccessService.Decision;
import net.hugmesh.gateway.cache.GatewayRouteAccessService.Rule;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Decision-logic contract for the per-gateway route-access enforcement. Built
 * with null datastores and primed via the test seam, so no live Postgres /
 * Cassandra is needed — this exercises the pure longest-pattern-match +
 * role-resolution + deny-wins precedence + public-floor that the
 * {@link net.hugmesh.gateway.filter.GatewayRouteAccessFilter} relies on.
 *
 * <p>Rule shape mirrors the canonical {@code gateway_route_access} columns:
 * {@code (id, gateway, url_pattern, role, casdoor_user, allow, domain)}. Roles are
 * Spring authorities ({@code ROLE_USER}, {@code ROLE_ADMIN}) or the {@code PUBLIC}
 * sentinel; {@code domain} is the per-row brand scope ({@code null}/{@code default}
 * = any brand). {@code decide} now takes the request's target domain as its 2nd
 * argument.
 */
class GatewayRouteAccessServiceTest {

    private GatewayRouteAccessService svc(Rule... rules) {
        GatewayRouteAccessService s = new GatewayRouteAccessService(
                null, null, "hugmesh-be-gateway", true, false, null);
        s.primeForTest(List.of(rules));
        return s;
    }

    /** Like {@link #svc(Rule...)} but with {@code app.mfa.enabled=true} so the D8
     *  per-row mfa_required gate in decide() is LIVE (dark by default elsewhere). */
    private GatewayRouteAccessService svcMfaOn(Rule... rules) {
        GatewayRouteAccessService s = new GatewayRouteAccessService(
                null, null, "hugmesh-be-gateway", true, true, null);
        s.primeForTest(List.of(rules));
        return s;
    }

    private static Rule rule(String pattern, String role, String casdoorUser, boolean allow) {
        // domain=null => UNSCOPED (applies to any target brand) — the back-compat
        // shape these decision-logic tests exercise. mfaRequired=false (legacy).
        return new Rule("r-" + pattern + "-" + role, "hugmesh-be-gateway",
                pattern, role, casdoorUser, allow, null, false);
    }

    /** A per-brand (domain-scoped) rule — applies ONLY to {@code domain}. */
    private static Rule rule(String pattern, String role, String casdoorUser,
                             boolean allow, String domain) {
        return new Rule("r-" + pattern + "-" + role + "-" + domain, "hugmesh-be-gateway",
                pattern, role, casdoorUser, allow, domain, false);
    }

    /** An mfa_required rule (D8) — the deciding grant demands MFA_SATISFIED. */
    private static Rule mfaRule(String pattern, String role) {
        return new Rule("mfa-" + pattern + "-" + role, "hugmesh-be-gateway",
                pattern, role, null, true, null, true);
    }

    @Test
    void ungovernedPath_returnsNoRule() {
        var s = svc(rule("/api/admin/**", "ROLE_ADMIN", null, true));
        assertThat(s.decide("/api/public/health", "default", List.of(), List.of("ROLE_USER")))
            .isEqualTo(Decision.NO_RULE);
    }

    @Test
    void governedPath_withMatchingRoleAllow_returnsAllow() {
        var s = svc(rule("/api/reports/**", "ROLE_ANALYST", null, true));
        assertThat(s.decide("/api/reports/q3", "default", List.of("u1"), List.of("ROLE_USER", "ROLE_ANALYST")))
            .isEqualTo(Decision.ALLOW);
    }

    @Test
    void governedPath_butPrincipalLacksRole_returnsDeny() {
        var s = svc(rule("/api/reports/**", "ROLE_ANALYST", null, true));
        assertThat(s.decide("/api/reports/q3", "default", List.of("u1"), List.of("ROLE_USER")))
            .isEqualTo(Decision.DENY);
    }

    @Test
    void longestPattern_wins_adminOverridesBroadUser() {
        // /api/** allows USER, but /api/admin/** (longer, more specific) requires ADMIN.
        var s = svc(
            rule("/api/**", "ROLE_USER", null, true),
            rule("/api/admin/**", "ROLE_ADMIN", null, true));
        // a plain USER hitting /api/admin/x is governed by the ADMIN rule (longest match) -> DENY
        assertThat(s.decide("/api/admin/x", "default", List.of("u1"), List.of("ROLE_USER")))
            .isEqualTo(Decision.DENY);
        // an ADMIN hitting it is allowed
        assertThat(s.decide("/api/admin/x", "default", List.of("u1"), List.of("ROLE_USER", "ROLE_ADMIN")))
            .isEqualTo(Decision.ALLOW);
        // a plain USER hitting a non-admin /api path is allowed by the broad rule
        assertThat(s.decide("/api/widgets", "default", List.of("u1"), List.of("ROLE_USER")))
            .isEqualTo(Decision.ALLOW);
    }

    @Test
    void explicitDeny_winsAtSamePattern() {
        var s = svc(
            rule("/api/reports/**", "ROLE_USER", null, true),
            rule("/api/reports/**", "ROLE_CONTRACTOR", null, false));
        assertThat(s.decide("/api/reports/q3", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_CONTRACTOR")))
            .isEqualTo(Decision.DENY);
    }

    @Test
    void publicRole_grantsAnonymous() {
        var s = svc(rule("/login/**", "PUBLIC", null, true));
        // no authorities at all (anonymous-equivalent) still allowed
        assertThat(s.decide("/login/start", "default", List.of(), List.of()))
            .isEqualTo(Decision.ALLOW);
    }

    @Test
    void casdoorUserPin_matchesIdOrUsername() {
        var s = svc(rule("/api/billing/**", "ROLE_USER", "alice", true));
        assertThat(s.decide("/api/billing/invoices", "default",
                List.of("casdoor-123", "alice"), List.of("ROLE_USER")))
            .isEqualTo(Decision.ALLOW);
        // right role, wrong user -> the pin fails -> no granting rule -> DENY
        assertThat(s.decide("/api/billing/invoices", "default",
                List.of("casdoor-999", "bob"), List.of("ROLE_USER")))
            .isEqualTo(Decision.DENY);
    }

    @Test
    void roleMatch_isPrefixTolerantAndCaseInsensitive() {
        // rule stored as bare "ADMIN" still matches a held ROLE_ADMIN authority.
        var s = svc(rule("/api/ops/**", "admin", null, true));
        assertThat(s.decide("/api/ops/restart", "default", List.of("u1"), List.of("ROLE_ADMIN")))
            .isEqualTo(Decision.ALLOW);
    }

    // ── Authority-injection: bare role-named PERMISSION must NOT satisfy a role rule
    //    (CWE-863 — the role-perm bypass keystone) ─────────────────────────────────

    @Test
    void crossUser_bareRoleNamedPermission_doesNotSatisfyRoleRule() {
        // DENY: the converter passes a `permissions:["admin"]` entry through as the
        // verbatim, NON-ROLE_-prefixed authority "admin". A route rule that names a
        // ROLE (ROLE_ADMIN) must NOT be satisfied by it — otherwise any user who can
        // set a bare role-named permission escalates past the role gate.
        var admin = svc(rule("/api/admin/**", "ROLE_ADMIN", null, true));
        assertThat(admin.decide("/api/admin/x", "default", List.of("u1"), List.of("ROLE_USER", "admin")))
            .as("bare permission \"admin\" must NOT satisfy a ROLE_ADMIN route rule")
            .isEqualTo(Decision.DENY);
        // Upper-case + ROLE_-name-suffix variants of the injected permission are
        // ALSO inert (still non-prefixed, so still a permission, not a role).
        assertThat(admin.decide("/api/admin/x", "default", List.of("u1"), List.of("ROLE_USER", "ADMIN")))
            .as("bare permission \"ADMIN\" must NOT satisfy a ROLE_ADMIN route rule")
            .isEqualTo(Decision.DENY);

        // The same for the super-role: a bare "superadmin" permission must not reach
        // a ROLE_SUPERADMIN-gated surface.
        var sa = svc(rule("/bff/superadmin/**", "ROLE_SUPERADMIN", null, true));
        assertThat(sa.decide("/bff/superadmin/domains", "default", List.of("u1"),
                List.of("ROLE_USER", "superadmin")))
            .as("bare permission \"superadmin\" must NOT satisfy a ROLE_SUPERADMIN route rule")
            .isEqualTo(Decision.DENY);

        // ALLOW control: the GENUINE ROLE_-prefixed authority still satisfies the
        // rule, so legitimate role holders are unaffected by the bypass fix.
        assertThat(admin.decide("/api/admin/x", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_ADMIN")))
            .as("a genuine ROLE_ADMIN authority still satisfies the rule")
            .isEqualTo(Decision.ALLOW);
        assertThat(sa.decide("/bff/superadmin/domains", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_SUPERADMIN")))
            .as("a genuine ROLE_SUPERADMIN authority still satisfies the rule")
            .isEqualTo(Decision.ALLOW);
    }

    @Test
    void bareRoleNamedPermission_doesNotSatisfyEvenWhenRuleStoredBare() {
        // Defense-in-depth: even if the rule is stored in the legacy BARE form
        // ("admin"), it is still a ROLE rule and must be satisfied ONLY by a
        // ROLE_-prefixed held authority — never by a like-named bare permission.
        var s = svc(rule("/api/ops/**", "admin", null, true));
        assertThat(s.decide("/api/ops/restart", "default", List.of("u1"), List.of("ROLE_USER", "admin")))
            .as("bare permission must NOT satisfy a bare-stored role rule")
            .isEqualTo(Decision.DENY);
        // ...but the real ROLE_ADMIN authority still does (the back-compat ALLOW).
        assertThat(s.decide("/api/ops/restart", "default", List.of("u1"), List.of("ROLE_USER", "ROLE_ADMIN")))
            .isEqualTo(Decision.ALLOW);
    }

    @Test
    void nullPath_returnsNoRule() {
        var s = svc(rule("/api/admin/**", "ROLE_ADMIN", null, true));
        assertThat(s.decide(null, "default", List.of("u1"), List.of("ROLE_ADMIN")))
            .isEqualTo(Decision.NO_RULE);
    }

    @Test
    void canonicalSeed_beGateway_enforcesAdminPath() {
        // Exercise the baked-in seed directly: be-gateway /api/admin/** is ADMIN-only.
        var seed = CanonicalSeed.forGateway("hugmesh-be-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-be-gateway", true, false, null);
        s.primeForTest(seed);
        assertThat(s.decide("/api/admin/users", "default", List.of("u1"), List.of("ROLE_USER")))
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/api/admin/users", "default", List.of("u1"), List.of("ROLE_USER", "ROLE_ADMIN")))
            .isEqualTo(Decision.ALLOW);
        // a normal /api/** path is USER-allowed by the seed
        assertThat(s.decide("/api/games", "default", List.of("u1"), List.of("ROLE_USER")))
            .isEqualTo(Decision.ALLOW);
    }

    @Test
    void canonicalSeed_beGateway_homeserverGatedByPlatformRoles_notBroadUser() {
        // Account-states ban/congruence: /_matrix/** + /api/v1/** are gated by the
        // PLATFORM roles, not the broad ROLE_USER floor. A user holding only
        // ROLE_USER (e.g. just had ROLE_MATRIX removed by a ban) is DENIED on the
        // homeserver surfaces, but a ROLE_MATRIX / ROLE_MASTODON holder is allowed.
        var seed = CanonicalSeed.forGateway("hugmesh-be-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-be-gateway", true, false, null);
        s.primeForTest(seed);

        // Matrix
        assertThat(s.decide("/_matrix/client/v3/sync", "default", List.of("u1"), List.of("ROLE_USER")))
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/_matrix/client/v3/sync", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_MATRIX")))
            .isEqualTo(Decision.ALLOW);

        // Mastodon (v1 + v2 + oauth)
        assertThat(s.decide("/api/v1/timelines/home", "default", List.of("u1"), List.of("ROLE_USER")))
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/api/v1/timelines/home", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_MASTODON")))
            .isEqualTo(Decision.ALLOW);
        assertThat(s.decide("/api/v2/search", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_MASTODON")))
            .isEqualTo(Decision.ALLOW);
        // A non-issuance /oauth path (e.g. /oauth/revoke) stays on the USAGE gate:
        // ROLE_MASTODON allowed, ROLE_USER-only denied. (The issuance sub-paths
        // /oauth/authorize + /oauth/token are gated by the external-client role —
        // see externalClientIssuanceGate_* below.)
        assertThat(s.decide("/oauth/revoke", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_MASTODON")))
            .isEqualTo(Decision.ALLOW);
        assertThat(s.decide("/oauth/revoke", "default", List.of("u1"), List.of("ROLE_USER")))
            .isEqualTo(Decision.DENY);

        // A platform-role holder for the OTHER platform is still denied (matrix
        // role does not grant mastodon access).
        assertThat(s.decide("/api/v1/timelines/home", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_MATRIX")))
            .isEqualTo(Decision.DENY);
    }

    @Test
    void canonicalSeed_beGateway_modIsPairedOnPlatformRows() {
        // ROLE_MOD is paired on the platform rows (not a bare floor), so a mod with
        // no platform role still reaches the homeserver moderation surfaces.
        var seed = CanonicalSeed.forGateway("hugmesh-be-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-be-gateway", true, false, null);
        s.primeForTest(seed);
        assertThat(s.decide("/_matrix/client/v3/rooms/x", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_MOD")))
            .isEqualTo(Decision.ALLOW);
        assertThat(s.decide("/api/v1/admin/accounts", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_MOD")))
            .isEqualTo(Decision.ALLOW);
    }

    @Test
    void canonicalSeed_beGateway_edgeAiTtsSynthesizeFloorsOnRoleUser() {
        // edge-ai-tts (OPTIONAL slug `edge-ai-tts`): matrix-ui's voice synthesis
        // lives on its OWN /v1 path space, not under the /api/** floor, so it needs
        // its own baked row. Anonymous must be DENIED (governed-but-ungranted, NOT
        // NO_RULE — the baked floor keeps the surface governed on the
        // datastore-unreachable fallback) and a plain ROLE_USER reaches it.
        var seed = CanonicalSeed.forGateway("hugmesh-be-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-be-gateway", true, false, null);
        s.primeForTest(seed);
        assertThat(s.decide("/v1/synthesize", "default", List.of(), List.of()))
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/v1/synthesize/stream", "default", List.of(), List.of()))
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/v1/synthesize", "default", List.of("u1"), List.of("ROLE_USER")))
            .isEqualTo(Decision.ALLOW);
        assertThat(s.decide("/v1/synthesize/stream", "default", List.of("u1"), List.of("ROLE_USER")))
            .isEqualTo(Decision.ALLOW);
        // Congruence guard: the seed row itself must floor on ROLE_USER (no
        // ROLE_ADMIN pairing on a capability floor — admins reach it via the
        // cross-domain bypass), mirroring the cluster Postgres seed row.
        assertThat(seed)
            .as("/v1/synthesize/** must be a ROLE_USER allow row in the be seed")
            .anyMatch(r -> "/v1/synthesize/**".equals(r.urlPattern())
                    && "ROLE_USER".equals(r.role()) && r.allow());
        assertThat(seed)
            .as("/v1/synthesize/** must not carry any non-ROLE_USER rule")
            .noneMatch(r -> "/v1/synthesize/**".equals(r.urlPattern()) && !"ROLE_USER".equals(r.role()));
        // The row stays SCOPED to the synthesize sub-path — it must not be the row
        // that governs the rest of the /v1 space. That space is now governed by its
        // OWN rows (see canonicalSeed_beGateway_edgeAiV1SpaceIsFullyGoverned); what
        // matters here is that no /v1/synthesize/** rule leaks onto a sibling path.
        assertThat(seed)
            .as("no /v1/synthesize rule may match a sibling /v1 path")
            .noneMatch(r -> r.urlPattern() != null
                    && r.urlPattern().startsWith("/v1/synthesize")
                    && new org.springframework.util.AntPathMatcher()
                            .match(r.urlPattern(), "/v1/chat/completions"));
    }

    @Test
    void canonicalSeed_beGateway_edgeAiV1SpaceIsFullyGoverned() {
        // DUAL-WRITE PARITY (issue #4 follow-on). The cluster Postgres seed
        // (specs/cluster/manifests/route-access/initdb/20-schema.sql) carries THREE
        // be-gateway /v1 rows — /v1/analyze/**, /v1/synthesize/** and the /v1/**
        // base — and the gateway's baked CanonicalSeed carried only the synthesize
        // one. The be-gateway's `edge-ai` route is a Host-predicate CATCHALL with NO
        // Path predicate, so on the datastore-unreachable fallback EVERY other /v1
        // path (/v1/chat/completions, /v1/embeddings, /v1/models) decided NO_RULE —
        // and NO_RULE FORWARDS. The model API was ungoverned by this layer.
        //
        // POSTURE THE NEW ROWS CREATE: /v1/** and /v1/analyze/** each become a
        // ROLE_USER capability FLOOR. Anonymous is DENIED (governed-but-ungranted,
        // not NO_RULE); a principal authenticated but WITHOUT ROLE_USER (a
        // ROLE_MATRIX-only account) is DENIED where it previously forwarded; a plain
        // ROLE_USER is ALLOWED. Strictly closing — nothing that was reachable to a
        // ROLE_USER stops being reachable.
        var seed = CanonicalSeed.forGateway("hugmesh-be-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-be-gateway", true, false, null);
        s.primeForTest(seed);

        // Every /v1 surface the be-gateway fronts RESOLVES to a rule (never NO_RULE)
        // and is access-controlled to the ROLE_USER floor.
        List<String> v1Paths = List.of(
                "/v1",                          // the catchall root itself
                "/v1/chat/completions",         // edge-ai (Ollama model API)
                "/v1/embeddings",
                "/v1/models",
                "/v1/analyze/image/classify",   // edge-ai-analysis
                "/v1/analyze/content/moderate",
                "/v1/synthesize",               // edge-ai-tts
                "/v1/synthesize/stream");
        for (String path : v1Paths) {
            assertThat(s.decide(path, "default", List.of(), List.of()))
                .as("anonymous must be DENIED at %s (governed, not NO_RULE)", path)
                .isEqualTo(Decision.DENY);
            assertThat(s.decide(path, "default", List.of("u1"), List.of("ROLE_MATRIX")))
                .as("an authenticated non-ROLE_USER principal must be DENIED at %s", path)
                .isEqualTo(Decision.DENY);
            assertThat(s.decide(path, "default", List.of("u1"), List.of("ROLE_USER")))
                .as("a plain ROLE_USER must reach %s", path)
                .isEqualTo(Decision.ALLOW);
        }

        // Congruence guard: each of the three patterns is present exactly as a
        // ROLE_USER ALLOW row, and carries NO other role (no ROLE_ADMIN pairing on a
        // capability floor — admins reach it via the cross-domain bypass).
        for (String pattern : List.of("/v1/**", "/v1/analyze/**", "/v1/synthesize/**")) {
            assertThat(seed)
                .as("%s must be a ROLE_USER allow row in the be seed", pattern)
                .anyMatch(r -> pattern.equals(r.urlPattern())
                        && "ROLE_USER".equals(r.role()) && r.allow());
            assertThat(seed)
                .as("%s must not carry any non-ROLE_USER rule", pattern)
                .noneMatch(r -> pattern.equals(r.urlPattern()) && !"ROLE_USER".equals(r.role()));
        }

        // MOST-SPECIFIC-WINS RESOLUTION PROOF. Flip ONLY the /v1/** base row of the
        // real seed to an explicit deny and re-prime: the two sub-path rows must
        // still decide their own paths (ALLOW), while the base path now denies. If
        // the base row were shadowing the sub-paths — i.e. if the sub-paths did not
        // resolve to their own rules — /v1/analyze and /v1/synthesize would flip too.
        var flipped = new java.util.ArrayList<GatewayRouteAccessService.Rule>();
        for (var r : seed) {
            if ("/v1/**".equals(r.urlPattern())) {
                flipped.add(new GatewayRouteAccessService.Rule(r.id() + ":flipped", r.gateway(),
                        r.urlPattern(), r.role(), r.casdoorUser(), false, r.domain(), r.mfaRequired()));
            } else {
                flipped.add(r);
            }
        }
        var flippedService =
                new GatewayRouteAccessService(null, null, "hugmesh-be-gateway", true, false, null);
        flippedService.primeForTest(flipped);
        assertThat(flippedService.decide("/v1/chat/completions", "default",
                List.of("u1"), List.of("ROLE_USER")))
            .as("the flipped /v1/** base row must govern a bare /v1 path")
            .isEqualTo(Decision.DENY);
        assertThat(flippedService.decide("/v1/analyze/image/classify", "default",
                List.of("u1"), List.of("ROLE_USER")))
            .as("/v1/analyze/** must win over /v1/** (most-specific)")
            .isEqualTo(Decision.ALLOW);
        assertThat(flippedService.decide("/v1/synthesize", "default",
                List.of("u1"), List.of("ROLE_USER")))
            .as("/v1/synthesize/** must win over /v1/** (most-specific)")
            .isEqualTo(Decision.ALLOW);
    }

    @Test
    void canonicalSeed_beGateway_noResidualBroadUserHomeserverRow() {
        // Seed-parity guard: there must be NO ROLE_USER allow row at the bare
        // homeserver patterns (the ban/congruence design REMOVED them). If a
        // future edit re-introduces one, a ROLE_USER-only principal would wrongly
        // ALLOW on /_matrix/** + /api/v1/** + /oauth/** and this fails.
        var seed = CanonicalSeed.forGateway("hugmesh-be-gateway");
        for (var rule : seed) {
            boolean isBareHomeserver =
                    "/_matrix/**".equals(rule.urlPattern())
                    || "/api/v1/**".equals(rule.urlPattern())
                    || "/api/v2/**".equals(rule.urlPattern())
                    || "/oauth/**".equals(rule.urlPattern());
            if (isBareHomeserver && rule.allow()) {
                assertThat(rule.role())
                    .as("homeserver pattern %s must not be granted to ROLE_USER", rule.urlPattern())
                    .isNotEqualTo("ROLE_USER");
            }
        }
    }

    @Test
    void canonicalSeed_beGateway_externalClientIssuanceGate_mastodon() {
        // Token-ISSUANCE (mint a native personal-client token) is gated by the
        // external-client role on the credential-minting Mastodon sub-paths
        // (/api/v1/apps, /oauth/authorize, /oauth/token). Base ROLE_MASTODON alone
        // — which grants USAGE — is NOT enough to ISSUE a native token.
        var seed = CanonicalSeed.forGateway("hugmesh-be-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-be-gateway", true, false, null);
        s.primeForTest(seed);

        for (String issue : List.of("/api/v1/apps", "/oauth/authorize", "/oauth/authorize/native", "/oauth/token")) {
            // base platform role grants USAGE but NOT issuance
            assertThat(s.decide(issue, "default", List.of("u1"), List.of("ROLE_USER", "ROLE_MASTODON")))
                .as("base ROLE_MASTODON must NOT issue at %s", issue)
                .isEqualTo(Decision.DENY);
            // external-client role grants issuance
            assertThat(s.decide(issue, "default", List.of("u1"),
                    List.of("ROLE_USER", "ROLE_MASTODON", "ROLE_MASTODON_EXTERNAL_CLIENT")))
                .as("ROLE_MASTODON_EXTERNAL_CLIENT must issue at %s", issue)
                .isEqualTo(Decision.ALLOW);
            // mod is paired on the issuance rows
            assertThat(s.decide(issue, "default", List.of("u1"), List.of("ROLE_USER", "ROLE_MOD")))
                .as("ROLE_MOD must issue at %s", issue)
                .isEqualTo(Decision.ALLOW);
            // a bare ROLE_USER (no platform, no external-client) is denied
            assertThat(s.decide(issue, "default", List.of("u1"), List.of("ROLE_USER")))
                .as("ROLE_USER-only must be denied at %s", issue)
                .isEqualTo(Decision.DENY);
        }

        // USAGE on the same platform stays on the base role — issuing a native
        // token does NOT also require it for ordinary timeline/usage traffic, and
        // an app verifying its own credentials (a sub-path of /api/v1/apps) is
        // USAGE, so it falls through to the base ROLE_MASTODON gate.
        assertThat(s.decide("/api/v1/timelines/home", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_MASTODON")))
            .isEqualTo(Decision.ALLOW);
        assertThat(s.decide("/api/v1/apps/verify_credentials", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_MASTODON")))
            .isEqualTo(Decision.ALLOW);
        // and an external-client holder withOUT the base platform role cannot USE
        // the timeline (issuance role is not a usage grant).
        assertThat(s.decide("/api/v1/timelines/home", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_MASTODON_EXTERNAL_CLIENT")))
            .isEqualTo(Decision.DENY);
    }

    @Test
    void canonicalSeed_beGateway_externalClientIssuanceGate_matrix() {
        // Matrix native login + device registration are gated by
        // ROLE_MATRIX_EXTERNAL_CLIENT (+ ROLE_MOD); base ROLE_MATRIX grants USAGE
        // (/_matrix/** sync etc.) but not native issuance.
        var seed = CanonicalSeed.forGateway("hugmesh-be-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-be-gateway", true, false, null);
        s.primeForTest(seed);

        for (String issue : List.of(
                "/_matrix/client/v3/login",
                "/_matrix/client/r0/login",
                "/_matrix/client/v3/login/sso/redirect",
                "/_matrix/client/v3/register",
                "/_matrix/client/v3/register/available")) {
            assertThat(s.decide(issue, "default", List.of("u1"), List.of("ROLE_USER", "ROLE_MATRIX")))
                .as("base ROLE_MATRIX must NOT issue at %s", issue)
                .isEqualTo(Decision.DENY);
            assertThat(s.decide(issue, "default", List.of("u1"),
                    List.of("ROLE_USER", "ROLE_MATRIX", "ROLE_MATRIX_EXTERNAL_CLIENT")))
                .as("ROLE_MATRIX_EXTERNAL_CLIENT must issue at %s", issue)
                .isEqualTo(Decision.ALLOW);
            assertThat(s.decide(issue, "default", List.of("u1"), List.of("ROLE_USER", "ROLE_MOD")))
                .as("ROLE_MOD must issue at %s", issue)
                .isEqualTo(Decision.ALLOW);
            assertThat(s.decide(issue, "default", List.of("u1"), List.of("ROLE_USER")))
                .as("ROLE_USER-only must be denied at %s", issue)
                .isEqualTo(Decision.DENY);
        }

        // USAGE (ordinary client-server traffic) stays on the base ROLE_MATRIX.
        assertThat(s.decide("/_matrix/client/v3/sync", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_MATRIX")))
            .isEqualTo(Decision.ALLOW);
        // The Mastodon external-client role does NOT cross over to Matrix issuance.
        assertThat(s.decide("/_matrix/client/v3/login", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_MATRIX", "ROLE_MASTODON_EXTERNAL_CLIENT")))
            .isEqualTo(Decision.DENY);
    }

    @Test
    void canonicalSeed_beGateway_externalClientIssuanceRows_presentAndPaired() {
        // Seed-parity guard for the issuance rows: each external-client issuance
        // pattern must carry BOTH the platform external-client role AND ROLE_MOD as
        // allow rows (so a future edit that drops the mod-pairing, or swaps the
        // role for a base platform role, fails here rather than silently regressing
        // the issuance gate).
        var seed = CanonicalSeed.forGateway("hugmesh-be-gateway");
        record Expect(String pattern, String role) {}
        List<Expect> required = List.of(
                new Expect("/_matrix/client/*/login/**",    "ROLE_MATRIX_EXTERNAL_CLIENT"),
                new Expect("/_matrix/client/*/login/**",    "ROLE_MOD"),
                new Expect("/_matrix/client/*/register/**", "ROLE_MATRIX_EXTERNAL_CLIENT"),
                new Expect("/_matrix/client/*/register/**", "ROLE_MOD"),
                new Expect("/api/v1/apps",                  "ROLE_MASTODON_EXTERNAL_CLIENT"),
                new Expect("/api/v1/apps",                  "ROLE_MOD"),
                new Expect("/oauth/authorize/**",           "ROLE_MASTODON_EXTERNAL_CLIENT"),
                new Expect("/oauth/authorize/**",           "ROLE_MOD"),
                new Expect("/oauth/token",                  "ROLE_MASTODON_EXTERNAL_CLIENT"),
                new Expect("/oauth/token",                  "ROLE_MOD"));
        for (Expect e : required) {
            assertThat(seed)
                .as("issuance row %s -> %s (allow) must be present in the seed", e.pattern(), e.role())
                .anyMatch(r -> e.pattern().equals(r.urlPattern())
                        && e.role().equals(r.role()) && r.allow());
        }
        // And the issuance patterns must NOT be granted to the bare base platform
        // role (that would let base USAGE roles mint native tokens).
        for (var r : seed) {
            boolean isIssuancePattern =
                    "/_matrix/client/*/login/**".equals(r.urlPattern())
                    || "/_matrix/client/*/register/**".equals(r.urlPattern())
                    || "/api/v1/apps".equals(r.urlPattern())
                    || "/oauth/authorize/**".equals(r.urlPattern())
                    || "/oauth/token".equals(r.urlPattern());
            if (isIssuancePattern && r.allow()) {
                assertThat(r.role())
                    .as("issuance pattern %s must not be granted to a base platform/user role",
                            r.urlPattern())
                    .isNotIn("ROLE_USER", "ROLE_MATRIX", "ROLE_MASTODON");
            }
        }
    }

    @Test
    void canonicalSeed_feGateway_socialShellsGatedByPlatformRoles() {
        var seed = CanonicalSeed.forGateway("hugmesh-fe-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-fe-gateway", true, false, null);
        s.primeForTest(seed);
        assertThat(s.decide("/social/matrix/inbox", "default", List.of("u1"), List.of("ROLE_USER")))
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/social/matrix/inbox", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_MATRIX")))
            .isEqualTo(Decision.ALLOW);
        assertThat(s.decide("/social/mastodon/feed", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_MASTODON")))
            .isEqualTo(Decision.ALLOW);
        // mod paired on the social shells too
        assertThat(s.decide("/social/mastodon/feed", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_MOD")))
            .isEqualTo(Decision.ALLOW);
    }

    @Test
    void canonicalSeed_feGateway_fleetOwnerReachesPhoneFleetButPlainAdminFloorDoesNot() {
        // The baked FE floor (dual-DB-outage fail-safe) must let a pure ROLE_FLEET_ADMIN
        // (NOT ROLE_ADMIN) reach /bff/admin/phone-fleet/** — the longer pattern wins the
        // longest-match over the /bff/admin/** ROLE_ADMIN floor. This is the parity copy of
        // the Postgres seed row; without it a fleet owner is default-denied during an outage.
        var seed = CanonicalSeed.forGateway("hugmesh-fe-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-fe-gateway", true, false, null);
        s.primeForTest(seed);
        // Pure fleet owner (no ROLE_ADMIN) reaches the fleet surface.
        assertThat(s.decide("/bff/admin/phone-fleet/devices", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_FLEET_ADMIN")))
            .isEqualTo(Decision.ALLOW);
        // ADMIN + SUPERADMIN also reach it (paired rows).
        assertThat(s.decide("/bff/admin/phone-fleet/devices", "default", List.of("u1"),
                List.of("ROLE_ADMIN"))).isEqualTo(Decision.ALLOW);
        assertThat(s.decide("/bff/admin/phone-fleet/devices", "default", List.of("u1"),
                List.of("ROLE_SUPERADMIN"))).isEqualTo(Decision.ALLOW);
        // A plain USER (no fleet/admin role) is denied on the fleet path...
        assertThat(s.decide("/bff/admin/phone-fleet/devices", "default", List.of("u1"),
                List.of("ROLE_USER"))).isEqualTo(Decision.DENY);
        // ...and the FLEET_ADMIN capability does NOT leak into the generic /bff/admin/** floor.
        assertThat(s.decide("/bff/admin/announcements", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_FLEET_ADMIN"))).isEqualTo(Decision.DENY);
    }

    // ── #244 ACCEPT (decision 41): the superadmin platform console at the fe door ─

    @Test
    void canonicalSeed_feGateway_superadminPlatformDoor_isGovernedNotUngoverned() {
        // THE BEHAVIOUR THIS ROW EXISTS FOR, and the assertion that goes RED the
        // moment it is reverted. Before the row NO fe pattern matched
        // /bff/superadmin/… at all (measured on main @ 13f1651d: the class held
        // FOUR ROLE_SUPERADMIN rules — pki `/**`, be `/bff/image-builds/arch/**`,
        // be `/bff/superadmin/**`, fe `/bff/admin/phone-fleet/**` — and NONE of
        // them on the fe superadmin prefix), so decide() answered NO_RULE and the
        // filter FORWARDED on the coarse authenticated() floor. NO_RULE is not a
        // refusal; it is a forward with no X-Route-Denied header and nothing in the
        // gateway's denial log.
        //
        // DENY vs NO_RULE is the whole discriminator here: delete the row and the
        // first assertion below reads NO_RULE, not DENY.
        var seed = CanonicalSeed.forGateway("hugmesh-fe-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-fe-gateway", true, false, null);
        s.primeForTest(seed);

        // A logged-in principal that is not superadmin: governed-but-ungranted ⇒ DENY
        // AT THE DOOR (not a forward into admin-bff's own hasRole("SUPERADMIN")).
        for (String path : List.of("/bff/superadmin/service-store/catalog",
                                   "/bff/superadmin/workloads",
                                   "/bff/superadmin/games-services/catalog",
                                   "/bff/superadmin/fleet-entitlements/x",
                                   "/bff/superadmin/phone-devices/1/owner")) {
            assertThat(s.decide(path, "default", List.of("u1"), List.of("ROLE_USER")))
                .as("%s must be GOVERNED by the baked fe floor (DENY), never NO_RULE/forward", path)
                .isEqualTo(Decision.DENY);
        }

        // ROLE_SUPERADMIN is the granting role at this layer.
        assertThat(s.decide("/bff/superadmin/service-store/catalog", "default", List.of("u1"),
                List.of("ROLE_SUPERADMIN")))
            .as("ROLE_SUPERADMIN holds the granting row on the superadmin platform prefix")
            .isEqualTo(Decision.ALLOW);

        // A per-domain ROLE_ADMIN holds NO granting row here — the seed does NOT
        // pair ROLE_ADMIN on this prefix. (GatewayRouteAccessFilter short-circuits
        // admin/superadmin BEFORE decide() is consulted, so this layer's answer is
        // not what a live admin request experiences; that residual is documented on
        // the row and unchanged by it. This assertion pins the TABLE, so a later
        // "admins are a superset" pairing cannot be added here unnoticed.)
        assertThat(s.decide("/bff/superadmin/service-store/catalog", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_ADMIN")))
            .as("plain ROLE_ADMIN must NOT hold a granting row on /bff/superadmin/**")
            .isEqualTo(Decision.DENY);

        // The new row must not swallow its SIBLING prefixes: /bff/admin/** keeps its
        // ROLE_ADMIN floor and the fleet sub-path keeps its ROLE_FLEET_ADMIN grant.
        assertThat(s.decide("/bff/admin/announcements", "default", List.of("u1"),
                List.of("ROLE_ADMIN")))
            .as("/bff/admin/** must still be granted to ROLE_ADMIN")
            .isEqualTo(Decision.ALLOW);
        assertThat(s.decide("/bff/admin/phone-fleet/devices", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_FLEET_ADMIN")))
            .as("the fleet-owner sub-path must still be granted to ROLE_FLEET_ADMIN")
            .isEqualTo(Decision.ALLOW);
        // ...and a path that merely SHARES the prefix string is not captured: Ant
        // `/bff/superadmin/**` matches the prefix itself and its subpaths only.
        assertThat(s.decide("/bff/superadmins-club", "default", List.of("u1"), List.of("ROLE_USER")))
            .as("/bff/superadmin/** must not capture /bff/superadmins-club")
            .isEqualTo(Decision.NO_RULE);
    }

    @Test
    void canonicalSeed_feGateway_superadminRow_shapeMatchesTheClusterSeed_andCarriesNoGamesServicesRefinement() {
        // ROW-SHAPE PIN (the dual-write half). The cluster Postgres seed carries
        //   ('hugmesh-fe-gateway','/bff/superadmin/**','ROLE_SUPERADMIN',true)
        // in generator specs/cluster/manifests/route-access/initdb/20-schema.sql.
        // This asserts the baked copy is that row and nothing else, so a drift in
        // either direction is a red test rather than a silent divergence.
        var fe = CanonicalSeed.forGateway("hugmesh-fe-gateway");
        var superadminRows = fe.stream()
                .filter(r -> r.urlPattern().startsWith("/bff/superadmin"))
                .toList();
        assertThat(superadminRows)
            .as("the fe floor must carry EXACTLY one /bff/superadmin row — the platform-prefix grant")
            .hasSize(1);
        var row = superadminRows.get(0);
        assertThat(row.urlPattern()).isEqualTo("/bff/superadmin/**");
        assertThat(row.role()).isEqualTo("ROLE_SUPERADMIN");
        assertThat(row.allow()).as("the row is an ALLOW grant, not a deny row").isTrue();
        assertThat(row.domain()).as("baked rows are UNSCOPED (domain=null)").isNull();
        assertThat(row.casdoorUser()).as("baked rows pin no casdoor user").isNull();
        // TIER LABEL. forGateway() picks the tier LIST by application name and
        // decide() never reads Rule.gateway(), so writing r(BE, …) inside fe()
        // would leave every behavioural assertion in this class green while
        // mislabelling the row — and Rule.gateway() and Rule.id() are what the
        // denial log and the admin console print. Pinned so the mislabel is red.
        assertThat(row.gateway())
            .as("the row must be LABELLED fe — r(BE, …) inside fe() is behaviourally "
              + "null but mislabels every log line and the rule id")
            .isEqualTo("hugmesh-fe-gateway");
        assertThat(row.id())
            .as("seed rule ids are seed:<gateway>:<pattern>:<role>")
            .isEqualTo("seed:hugmesh-fe-gateway:/bff/superadmin/**:ROLE_SUPERADMIN");

        // NO games-services DENY refinement in the BAKED floor — a DELIBERATE
        // DIVERGENCE from the cluster seed, not a shared omission. The carrier
        // commit 63c8952f paired the allow row with ('hugmesh-fe-gateway',
        // '/bff/superadmin/games-services/**','ROLE_SUPERADMIN',false); #244's
        // ACCEPT is stated WITHOUT it, and decision 41 authorises exactly one row
        // here. The CLUSTER seed has carried that deny row again since 2026-09-17
        // (operator decision 28 = D, hugmesh-generator 4764ab4f) with mfa_required
        // pinned TRUE on the row itself. A baked copy could not reproduce that —
        // D8 forbids mfa_required=true on any baked row — so it would carry the
        // wall without the floor; what it WOULD change is decide()'s answer for a
        // ROLE_SUPERADMIN on the fallback (ALLOW here, explicit DENY with a copy),
        // which GatewayRouteAccessFilter never consults because it short-circuits
        // that role first. Whether to mirror it is not decided by 41 and is
        // recorded on #244. The hasSize(1) above fails if it appears here; the
        // divergence itself is asserted in hugmesh-generator's
        // fallback-floor-parity.feature, which reads BOTH files.
        assertThat(fe)
            .as("no /bff/superadmin/games-services/** refinement row (it would strip the MFA floor)")
            .noneMatch(r -> r.urlPattern().startsWith("/bff/superadmin/games-services"));

        // D8, NARROWED BY DECISION 56 (hugmesh-generator#347, operator answer
        // 2026-09-18: "a declared set of privileged rows"). This row is IN the
        // declared set (CanonicalSeed.MFA_REQUIRED_FALLBACK_ROWS) because its
        // cluster Postgres counterpart is mfa_required=true via the blanket flip
        //   SET mfa_required = true WHERE allow AND url_pattern LIKE '/bff/superadmin/%'
        // — reaching that row was decision 41's third, previously-undelivered gain
        // (#244 / hugmesh-gateway#35): isMfaRequiredSurface() returns false for an
        // UNGOVERNED path, so before this flip the privileged step-up floor had
        // nothing at the public browser door to attach to even after #33 landed.
        // Every OTHER baked row still carries mfa_required=false (D8's default,
        // unchanged for anything not in the declared set).
        assertThat(row.mfaRequired())
            .as("decision 56: this row is in the declared MFA-required set")
            .isTrue();
        // ...and the RESIDUAL THAT CLOSES: on the datastore-unreachable fallback
        // the superadmin platform console is now BOTH role-gated AND MFA-gated,
        // matching the cluster seed. If this row is ever removed from the declared
        // set this assertion goes red and the change has to be argued, not slipped
        // in.
        var s = new GatewayRouteAccessService(null, null, "hugmesh-fe-gateway", true, false, null);
        s.primeForTest(fe);
        assertThat(s.isMfaRequiredSurface("/bff/superadmin/service-store/catalog", "default"))
            .as("decision 56: the superadmin door is role-gated AND MFA-gated on the fallback")
            .isTrue();
    }

    @Test
    void canonicalSeed_feGateway_rootIsPublic() {
        var seed = CanonicalSeed.forGateway("hugmesh-fe-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-fe-gateway", true, false, null);
        s.primeForTest(seed);
        assertThat(s.decide("/", "default", List.of(), List.of())).isEqualTo(Decision.ALLOW);
        assertThat(s.decide("/admin/dashboard", "default", List.of("u1"), List.of("ROLE_USER")))
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/bff/me/profile", "default", List.of("u1"), List.of("ROLE_USER")))
            .isEqualTo(Decision.ALLOW);
    }

    @Test
    void canonicalSeed_feGateway_nativeLoginSurfacesAreAnonymous() {
        // NATIVE-LOGIN model: the login-ui SPA shell (/login/**) and the
        // credential-submit endpoint (/bff/login) are the ONLY authentication
        // entry points now that Casdoor's hosted page is never browser-exposed.
        // An anonymous visitor (no authorities) holds NO role yet, so both MUST
        // resolve to ALLOW — gating them on ROLE_USER was a chicken-and-egg
        // lock-out (a session would be required to reach the session-minting
        // endpoint). This is the route-access HALF of the two-layer congruence
        // with SecurityConfig (FE_SHELL_PUBLIC_GET_PATHS `/login/**` + PUBLIC_PATHS
        // `/bff/login`); both layers open the SAME surface.
        var seed = CanonicalSeed.forGateway("hugmesh-fe-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-fe-gateway", true, false, null);
        s.primeForTest(seed);
        // Anonymous ALLOW on the login page shell + its bundles and the submit.
        assertThat(s.decide("/login", "default", List.of(), List.of()))
            .isEqualTo(Decision.ALLOW);
        assertThat(s.decide("/login/main-ABCD1234.js", "default", List.of(), List.of()))
            .isEqualTo(Decision.ALLOW);
        assertThat(s.decide("/bff/login", "default", List.of(), List.of()))
            .isEqualTo(Decision.ALLOW);
        // Congruence guard: the seed row itself must be PUBLIC (not a role), so a
        // future edit that re-gates the login surface on a role fails HERE.
        assertThat(seed)
            .as("/login/** must be PUBLIC in the fe seed (native-login anonymous entry)")
            .anyMatch(r -> "/login/**".equals(r.urlPattern()) && "PUBLIC".equals(r.role()) && r.allow());
        assertThat(seed)
            .as("/bff/login must be PUBLIC in the fe seed (native-login credential submit)")
            .anyMatch(r -> "/bff/login".equals(r.urlPattern()) && "PUBLIC".equals(r.role()) && r.allow());
        // Registration/provision are NOT widened by this change — they stay gated
        // (provisioning is a post-login, session-bearing step, not an anonymous one).
        assertThat(s.decide("/bff/register/start", "default", List.of(), List.of()))
            .isEqualTo(Decision.DENY);
    }

    @Test
    void canonicalSeed_feGateway_publicAnnouncementsAreAnonymous() {
        // /bff/public/announcements/** is the UNAUTHENTICATED login-page banner
        // surface: anonymous (no authorities) must resolve to ALLOW, while the
        // sibling ROLE_ADMIN /bff/admin/** prefix (CRUD) stays admin-only.
        var seed = CanonicalSeed.forGateway("hugmesh-fe-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-fe-gateway", true, false, null);
        s.primeForTest(seed);
        assertThat(s.decide("/bff/public/announcements/login", "default", List.of(), List.of()))
            .isEqualTo(Decision.ALLOW);
        assertThat(s.decide("/bff/admin/announcements", "default", List.of("u1"), List.of("ROLE_USER")))
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/bff/admin/announcements", "default", List.of("u1"), List.of("ROLE_USER", "ROLE_ADMIN")))
            .isEqualTo(Decision.ALLOW);
    }

    @Test
    void canonicalSeed_feGateway_publicAppealContactIsAnonymous() {
        // /bff/public/appeal-contact is the UNAUTHENTICATED appeal-page contact
        // resolver (admin-bff permitAll, returns {"email":"..."}, no PII): a
        // banned/anonymous visitor (no authorities) must resolve to ALLOW so the
        // pre-auth login-ui appeal page can render the contact address. The
        // sibling ROLE_ADMIN /bff/admin/** prefix stays admin-only, and the route
        // is scoped to the exact path (NOT a blanket /bff/public/**) — an
        // unrelated /bff/public/** sub-path is NOT made anonymous by this row.
        var seed = CanonicalSeed.forGateway("hugmesh-fe-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-fe-gateway", true, false, null);
        s.primeForTest(seed);
        assertThat(s.decide("/bff/public/appeal-contact", "default", List.of(), List.of()))
            .isEqualTo(Decision.ALLOW);
        // exact-route scoping: a different /bff/public/** path is NOT made
        // anonymous by this row. It matches no rule in the fe() seed, so the
        // route-access layer reports NO_RULE (ungoverned) rather than PUBLIC —
        // i.e. appeal-contact did NOT widen into a blanket /bff/public/** allow.
        assertThat(s.decide("/bff/public/other-thing", "default", List.of(), List.of()))
            .isEqualTo(Decision.NO_RULE);
        // the sibling ROLE_ADMIN /bff/admin/** prefix stays admin-only.
        assertThat(s.decide("/bff/admin/appeals", "default", List.of("u1"), List.of("ROLE_USER")))
            .isEqualTo(Decision.DENY);
    }

    @Test
    void canonicalSeed_feGateway_characterForgeSurfacesFloorOnRoleUser() {
        // Character Forge (OPTIONAL slug `character-forge`): the UI shell
        // (/character-forge/**) and its BFF (/bff/character-forge/**) are gated
        // by the plain ROLE_USER capability floor (character-studio precedent).
        // Anonymous (no authorities) must be DENIED (governed-but-ungranted, NOT
        // NO_RULE — the baked floor keeps the surface governed on the
        // datastore-unreachable fallback), and a plain ROLE_USER reaches both.
        var seed = CanonicalSeed.forGateway("hugmesh-fe-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-fe-gateway", true, false, null);
        s.primeForTest(seed);
        // anonymous: governed and denied on both surfaces.
        assertThat(s.decide("/character-forge/studio", "default", List.of(), List.of()))
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/bff/character-forge/characters", "default", List.of(), List.of()))
            .isEqualTo(Decision.DENY);
        // plain ROLE_USER: allowed on the shell, its assets, and the BFF.
        assertThat(s.decide("/character-forge", "default", List.of("u1"), List.of("ROLE_USER")))
            .isEqualTo(Decision.ALLOW);
        assertThat(s.decide("/character-forge/assets/game/forge.wasm", "default",
                List.of("u1"), List.of("ROLE_USER")))
            .isEqualTo(Decision.ALLOW);
        assertThat(s.decide("/bff/character-forge/characters/active", "default",
                List.of("u1"), List.of("ROLE_USER")))
            .isEqualTo(Decision.ALLOW);
        // Congruence guard: the seed rows themselves must floor on ROLE_USER
        // (no ROLE_ADMIN pairing on a capability floor; admin-bypass covers
        // admins), so a future edit that widens/narrows the floor fails HERE.
        for (String pattern : List.of("/character-forge/**", "/bff/character-forge/**")) {
            assertThat(seed)
                .as("%s must be a ROLE_USER allow row in the fe seed", pattern)
                .anyMatch(r -> pattern.equals(r.urlPattern())
                        && "ROLE_USER".equals(r.role()) && r.allow());
            assertThat(seed)
                .as("%s must not carry any non-ROLE_USER rule (no admin pairing on a capability floor)", pattern)
                .noneMatch(r -> pattern.equals(r.urlPattern()) && !"ROLE_USER".equals(r.role()));
        }
        // A sibling first-segment (NOT under /character-forge/) is untouched by
        // these rows: no rule governs it, so the layer reports NO_RULE.
        assertThat(s.decide("/character-forgery/x", "default", List.of(), List.of()))
            .isEqualTo(Decision.NO_RULE);
    }

    @Test
    void canonicalSeed_feGateway_spaShellAssetsArePublic() {
        // The anonymous SPA shell the '/' PUBLIC row implies: the document, the
        // ROOT-level hashed bundles, the module-federation manifests, favicon and
        // /assets/** all resolve ALLOW for a no-authorities caller — congruent
        // with the SecurityConfig FE_SHELL_PUBLIC_GET_PATHS floor, so the coarse
        // layer and this table open the SAME surface (the front-page parity fix).
        var seed = CanonicalSeed.forGateway("hugmesh-fe-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-fe-gateway", true, false, null);
        s.primeForTest(seed);
        for (String path : List.of("/", "/index.html", "/favicon.ico",
                "/importmap.json", "/remoteEntry.json",
                "/main-PCXO4T2D.js", "/styles-76A67VRN.css", "/assets/logo.svg")) {
            assertThat(s.decide(path, "default", List.of(), List.of()))
                .as("anonymous SPA shell path %s must be ALLOWed by the fe seed", path)
                .isEqualTo(Decision.ALLOW);
        }
        // Ant '*' does not cross '/': the /*.js row must NOT widen onto nested
        // paths — a .js under a gated prefix keeps its own (ROLE_ADMIN) rule.
        assertThat(s.decide("/admin/evil.js", "default", List.of("u1"), List.of("ROLE_USER")))
            .as("the /*.js shell row must not widen into gated prefixes")
            .isEqualTo(Decision.DENY);
    }

    @Test
    void canonicalSeed_feGateway_publicFederationReadsAreAnonymous() {
        // GET /api/federation/vanity(/**) (the PUBLIC profile resolve — the
        // cluster fe spec's vanity-subdomain route documents this allowance as
        // the deferred missing piece) and GET /api/federation/capabilities (the
        // public install-state projection a LOGGED-OUT host shell reads) must
        // resolve ALLOW anonymously; every OTHER federation surface stays
        // ungoverned here (NO_RULE — the coarse authenticated() floor is the
        // authority), i.e. the rows did NOT widen into /api/federation/**.
        var seed = CanonicalSeed.forGateway("hugmesh-fe-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-fe-gateway", true, false, null);
        s.primeForTest(seed);
        for (String path : List.of("/api/federation/vanity",
                "/api/federation/vanity/somebody", "/api/federation/capabilities")) {
            assertThat(s.decide(path, "default", List.of(), List.of()))
                .as("anonymous public federation read %s must be ALLOWed", path)
                .isEqualTo(Decision.ALLOW);
        }
        assertThat(s.decide("/api/federation/manifest", "default", List.of(), List.of()))
            .as("the public reads must NOT widen into a blanket /api/federation/** allow")
            .isEqualTo(Decision.NO_RULE);
    }

    // ── SERVICE-only internal ingest surfaces (explicit DENY rows) ────────────
    // The cluster Postgres seed (generator route-access/initdb/20-schema.sql) gained
    // three `allow=false` rows for the service-to-service /…/internal/** receivers the
    // fe route table Ant-matches under its /bff/user/**, /bff/mesh/** and /bff/**
    // predicates. They were seeded into POSTGRES ONLY, so on the datastore-unreachable
    // path — where THIS class is the enforced authority — the surfaces matched no
    // pattern at all, decide() returned NO_RULE and the gateway FORWARDED on the coarse
    // authenticated() floor. The fallback was WEAKER than the steady state; these tests
    // pin the parity copy.

    /** The three SERVICE-only ingest prefixes and a concrete path under each. */
    private static final List<String> INTERNAL_INGEST_PATTERNS = List.of(
            "/bff/user/internal/**", "/bff/mesh/internal/**", "/bff/internal/**");
    private static final List<String> INTERNAL_INGEST_PROBES = List.of(
            "/bff/user/internal/mesh-devices",
            "/bff/user/internal/characters/parts/42/approve",
            "/bff/mesh/internal/bridge-sync",
            "/bff/internal/session/introspect",
            "/bff/internal/accounts/ensure");

    @Test
    void canonicalSeed_feGateway_serviceOnlyInternalIngestIsDeniedNotUngoverned() {
        // FAIL-FIRST: without the seed rows every probe below is NO_RULE (matched by no
        // fe pattern) and the filter forwards. With them the deciding longest match is
        // the allow=false row, so every carrier of every ordinary role is DENIED.
        var seed = CanonicalSeed.forGateway("hugmesh-fe-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-fe-gateway", true, false, null);
        s.primeForTest(seed);
        for (String probe : INTERNAL_INGEST_PROBES) {
            // The plain authenticated floor: HOLDS the deny row's ROLE_USER, so
            // explicit-deny wins.
            assertThat(s.decide(probe, "default", List.of("u1"), List.of("ROLE_USER")))
                .as("SERVICE-only ingest %s must be DENIED for a plain authenticated user", probe)
                .isEqualTo(Decision.DENY);
            // A tier capability holder does NOT get in either (mesh-access is not the
            // meshbridge daemon's identity).
            assertThat(s.decide(probe, "default", List.of("u1"), List.of("ROLE_USER", "ROLE_MESH")))
                .as("SERVICE-only ingest %s must be DENIED for a ROLE_MESH holder", probe)
                .isEqualTo(Decision.DENY);
            // Nor a mod, nor a fleet admin — none of these are ROLE_SERVICE.
            assertThat(s.decide(probe, "default", List.of("u1"), List.of("ROLE_USER", "ROLE_MOD")))
                .as("SERVICE-only ingest %s must be DENIED for a mod", probe)
                .isEqualTo(Decision.DENY);
            // Anonymous (no authorities at all) is governed-but-ungranted ⇒ DENY, NOT
            // the NO_RULE forward the surfaces used to get.
            assertThat(s.decide(probe, "default", List.of(), List.of()))
                .as("SERVICE-only ingest %s must be DENIED (never NO_RULE) for anonymous", probe)
                .isEqualTo(Decision.DENY);
        }
    }

    @Test
    void canonicalSeed_feGateway_internalDenyRowsAreDenyShapedAndCarryNoAllowSibling() {
        // Congruence guard on the ROWS themselves (not just the verdict), mirroring the
        // character-forge / native-login guards above: each pattern must exist, must be
        // allow=false, must carry the ROLE_USER role the Postgres seed uses, and must
        // NOT gain an allow sibling at the SAME pattern — an allow row at equal length
        // would satisfy `allowed` for its role holders while explicitDeny only fires for
        // holders of the deny row's role, so a mismatched pair could re-open the surface.
        var seed = CanonicalSeed.forGateway("hugmesh-fe-gateway");
        for (String pattern : INTERNAL_INGEST_PATTERNS) {
            assertThat(seed)
                .as("%s must be an explicit allow=false row in the fe seed", pattern)
                .anyMatch(r -> pattern.equals(r.urlPattern())
                        && "ROLE_USER".equals(r.role()) && !r.allow());
            assertThat(seed)
                .as("%s must carry NO allow=true row (an allow sibling would re-open it)", pattern)
                .noneMatch(r -> pattern.equals(r.urlPattern()) && r.allow());
            // The deny rows are unscoped + unpinned + non-MFA, exactly like every other
            // baked floor row (mfa_required lives only in the admin-managed Postgres rows).
            assertThat(seed)
                .as("%s must be unscoped/unpinned/non-MFA like the rest of the baked floor", pattern)
                .filteredOn(r -> pattern.equals(r.urlPattern()))
                .allMatch(r -> r.domain() == null && r.casdoorUser() == null && !r.mfaRequired());
        }
    }

    @Test
    void canonicalSeed_feGateway_internalDenyRowsDoNotSwallowTheirTiers() {
        // Non-over-broadening: the rows are scoped to the `internal` path SEGMENT. The
        // ordinary user/mesh tier surfaces sitting under the SAME fe route predicates
        // stay ungoverned by this baked floor (their tier floors live in the
        // admin-managed Postgres rows), and the pre-existing /bff allow rows are intact.
        var seed = CanonicalSeed.forGateway("hugmesh-fe-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-fe-gateway", true, false, null);
        s.primeForTest(seed);
        for (String sibling : List.of("/bff/user/profile", "/bff/mesh/rooms",
                "/bff/internal-ish/thing", "/bff/userinternal/x")) {
            assertThat(s.decide(sibling, "default", List.of("u1"), List.of("ROLE_USER")))
                .as("%s must NOT be swallowed by the internal-ingest deny rows", sibling)
                .isEqualTo(Decision.NO_RULE);
        }
        assertThat(s.decide("/bff/me/profile", "default", List.of("u1"), List.of("ROLE_USER")))
            .isEqualTo(Decision.ALLOW);
        assertThat(s.decide("/bff/character-forge/characters", "default",
                List.of("u1"), List.of("ROLE_USER")))
            .isEqualTo(Decision.ALLOW);
    }

    @Test
    void canonicalSeed_internalDenyRowsAreFeOnly_beAndPkiTiersAreUnchanged() {
        // The generator seeded these rows for hugmesh-fe-gateway ONLY (the be spec
        // declares no /bff/user|mesh|** route predicates, so no other tier routes the
        // surfaces). Guard against a copy-paste into the wrong tier, which would 403 a
        // legitimately-unrelated path on that gateway.
        for (String gateway : List.of("hugmesh-be-gateway", "hugmesh-pki-gateway")) {
            assertThat(CanonicalSeed.forGateway(gateway))
                .as("%s must not carry the fe-only internal-ingest deny rows", gateway)
                .noneMatch(r -> INTERNAL_INGEST_PATTERNS.contains(r.urlPattern()));
        }
    }

    @Test
    void canonicalSeed_feGateway_internalDenyRows_areMirroredInTheComposePostgresSeed() {
        // DUAL-WRITE PARITY. compose/route-access-seed.sql is the local-dev Postgres
        // SOURCE OF TRUTH; when it loads, its rows REPLACE this seed wholesale. If the
        // baked floor denies a surface the dev Postgres rows leave ungoverned, the dev
        // stack silently reproduces the very NO_RULE-forward hole the fix closes — so
        // the two must carry the same three rows. (The cluster copy lives in the
        // generator repo: specs/cluster/manifests/route-access/initdb/20-schema.sql.)
        Path seedSql = Path.of("compose", "route-access-seed.sql");
        assertThat(seedSql)
            .as("the compose Postgres seed must exist (test runs from the module basedir)")
            .exists();
        String sql;
        try {
            sql = Files.readString(seedSql, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("could not read " + seedSql, e);
        }
        for (String pattern : INTERNAL_INGEST_PATTERNS) {
            assertThat(sql)
                .as("compose seed must carry the fe-gateway DENY row for %s", pattern)
                .containsPattern("\\('hugmesh-fe-gateway',\\s*'" + Pattern.quote(pattern)
                        + "',\\s*'ROLE_USER',\\s*false\\)");
        }
    }

    // ── DECISION 61 — the platform must not ship a '/**' row its own admin API
    // refuses (hugmesh-admin-bff-api#57, hugmesh-generator#347, 2026-09-18);
    // tightened to ZERO exceptions by decision 79 = B (2026-09-23) ──────────────

    @Test
    void noSeed_shipsABareDoubleStarRow_zeroExceptions() {
        // hugmesh-admin-bff-api's AdminController.addRouteRule refuses a
        // url_pattern whose first path segment is a bare wildcard ('/**' has
        // none) — an operator who deletes such a row can never recreate it
        // through the admin API. Decision 61 = refuse: the API keeps refusing
        // it, so seeds must not SHIP one.
        //
        // Decision 61 left ONE named exception: pki's headscale catch-all
        // r(PKI, "/**", "ROLE_SUPERADMIN") (bug #15). Decision 79 = B
        // (hugmesh-admin-bff-api#57, 2026-09-23) moved headscale's floor out of
        // gateway_route_access into SecurityConfig — every request whose Host
        // matches the `headscale` route's own Host predicate needs
        // ROLE_SUPERADMIN, ahead of PUBLIC_PATHS — and dropped the row. So there
        // is no exception left, and this guard no longer names one.
        //
        // Scope: the three tier seeds, the per-brand suffix names that reuse
        // them, and the compose Postgres seed. NOT in scope: bySuffix()'s
        // unknown-name floor r(<name>, "/**", "ROLE_ADMIN"). That is a synthetic
        // fail-CLOSED floor for a misconfigured instance name — no Postgres seed
        // ships it and no admin ever manages it, so the admin API's refusal to
        // recreate '/**' cannot strand it. unknownGatewayName_getsClosedDenyAllFloor_notFailOpen
        // pins it separately.
        for (String gateway : List.of(CanonicalSeed.PKI, CanonicalSeed.BE, CanonicalSeed.FE,
                "brandx-pki-gateway", "brandx-be-gateway", "brandx-fe-gateway")) {
            List<Rule> seed = CanonicalSeed.forGateway(gateway);
            assertThat(seed)
                .as("guard sanity: %s must resolve to a real tier seed, not an empty list", gateway)
                .isNotEmpty();
            assertThat(seed.stream().filter(r -> "/**".equals(r.urlPattern())).map(Rule::id).toList())
                .as("CanonicalSeed for %s must ship NO bare /** row (decision 79 = B: zero exceptions)", gateway)
                .isEmpty();
        }

        Path seedSql = Path.of("compose", "route-access-seed.sql");
        assertThat(seedSql)
            .as("the compose Postgres seed must exist (test runs from the module basedir)")
            .exists();
        String sql;
        try {
            sql = Files.readString(seedSql, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("could not read " + seedSql, e);
        }
        String rows = sql.replaceAll("(?m)--[^\n]*", "");
        var m = Pattern.compile("\\('([^']+)',\\s*'([^']*)',\\s*'([^']+)',\\s*(true|false)\\)").matcher(rows);
        int parsed = 0;
        var bareDoubleStarInCompose = new ArrayList<String>();
        while (m.find()) {
            parsed++;
            if ("/**".equals(m.group(2))) {
                bareDoubleStarInCompose.add(m.group(1) + ":" + m.group(2) + ":" + m.group(3));
            }
        }
        assertThat(parsed)
            .as("parse sanity: a broken row regex would make the emptiness check below vacuous")
            .isGreaterThan(40);
        assertThat(bareDoubleStarInCompose)
            .as("compose/route-access-seed.sql must ship NO bare /** row (decision 79 = B: zero exceptions)")
            .isEmpty();
    }

    // ── The edge-AI /v1 space in the LOCAL-DEV Postgres seed (issue #4, TODO 1) ──

    /** Every {@code ('gw', 'pattern', 'ROLE_x', true|false)} tuple in the
     *  local-dev seed, as the Rules the gateway would hold once that Postgres
     *  loads. Parsing (rather than substring-matching) is what lets this test
     *  assert DECISIONS on the dev stack's own rows instead of merely asserting
     *  the text is present. */
    private static List<Rule> composeSeedRulesFor(String gateway) {
        Path seedSql = Path.of("compose", "route-access-seed.sql");
        assertThat(seedSql)
            .as("the compose Postgres seed must exist (test runs from the module basedir)")
            .exists();
        String sql;
        try {
            sql = Files.readString(seedSql, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("could not read " + seedSql, e);
        }
        // Strip `--` comments first: the file documents patterns like /v1/** in
        // prose, and a comment must never be mistaken for a row.
        String rows = sql.replaceAll("(?m)--[^\n]*", "");
        var out = new ArrayList<Rule>();
        var m = Pattern.compile("\\('([^']+)',\\s*'([^']*)',\\s*'([^']+)',\\s*(true|false)\\)")
                .matcher(rows);
        while (m.find()) {
            if (!gateway.equals(m.group(1))) continue;
            out.add(new Rule(null, m.group(1), m.group(2), m.group(3), null,
                    Boolean.parseBoolean(m.group(4)), null, false));
        }
        return out;
    }

    @Test
    void composeSeed_beGateway_edgeAiV1Space_resolvesAndIsFloorGated() {
        // THIRD LEG OF THE DUAL-WRITE (issue #4, TODO 1). The cluster Postgres seed
        // and the baked CanonicalSeed both carry the three be-gateway /v1 rows; the
        // local-dev seed compose.yaml mounts into docker-entrypoint-initdb.d carried
        // NONE. When that Postgres loads, its rows REPLACE the baked seed wholesale
        // (loadFromPostgres wins over CanonicalSeed), so the dev stack reproduced
        // exactly the hole the baked rows closed: /v1/** matched nothing, decide()
        // answered NO_RULE, and NO_RULE FORWARDS.
        //
        // POSTURE THE NEW ROWS CREATE (all three are ROLE_USER capability floors,
        // strictly closing — nothing reachable to a ROLE_USER stops being reachable):
        //   • no authorities                -> DENY (governed-but-ungranted, was NO_RULE->forward)
        //   • authenticated, no ROLE_USER   -> DENY (a ROLE_MATRIX-only account, was forwarded)
        //   • ROLE_USER                     -> ALLOW (unchanged outcome, now governed)
        //   • ROLE_ADMIN / ROLE_SUPERADMIN  -> unchanged: the FILTER's own bypasses
        //     short-circuit before decide() is ever called, which is why no
        //     ROLE_ADMIN row is paired onto a capability floor.
        var rules = composeSeedRulesFor("hugmesh-be-gateway");
        assertThat(rules)
            .as("parse sanity: the be-gateway block must yield a plausible row count "
                    + "(a broken regex would make every assertion below vacuous)")
            .hasSizeGreaterThan(20);
        var s = new GatewayRouteAccessService(null, null, "hugmesh-be-gateway", true, false, null);
        s.primeForTest(rules);

        List<String> v1Paths = List.of(
                "/v1",                          // the ai.<domain> catchall root
                "/v1/chat/completions",         // edge-ai (Ollama OpenAI-compatible API)
                "/v1/embeddings",
                "/v1/models",
                "/v1/analyze/image/classify",   // edge-ai-analysis
                "/v1/analyze/content/moderate",
                "/v1/synthesize",               // edge-ai-tts
                "/v1/synthesize/stream");
        for (String path : v1Paths) {
            assertThat(s.decide(path, "default", List.of(), List.of()))
                .as("%s must RESOLVE to a rule in the dev seed (never NO_RULE)", path)
                .isEqualTo(Decision.DENY);
            assertThat(s.decide(path, "default", List.of("u1"), List.of("ROLE_MATRIX")))
                .as("a ROLE_MATRIX-only account must not reach %s", path)
                .isEqualTo(Decision.DENY);
            assertThat(s.decide(path, "default", List.of("u1"), List.of("ROLE_USER")))
                .as("the ROLE_USER floor must still reach %s", path)
                .isEqualTo(Decision.ALLOW);
        }
        // The mastodon /api/v1/** rows live in a DIFFERENT path space and must not be
        // touched by the new base row (a /v1/** that also swallowed /api/v1 would
        // silently re-floor the homeserver API onto ROLE_USER).
        assertThat(s.decide("/api/v1/timelines/home", "default", List.of("u1"), List.of("ROLE_USER")))
            .as("/api/v1/** stays ROLE_MASTODON-gated; the /v1 base must not widen onto it")
            .isEqualTo(Decision.DENY);
    }

    @Test
    void composeSeed_beGatewayV1Rows_matchTheBakedCanonicalSeedExactly() {
        // DUAL-WRITE PARITY, both directions: the dev Postgres and the baked fallback
        // must agree on pattern, role AND allow for the whole /v1 space, or the dev
        // stack and a datastore-unreachable production enforce different postures.
        var composeV1 = composeSeedRulesFor("hugmesh-be-gateway").stream()
                .filter(r -> r.urlPattern().startsWith("/v1"))
                .map(r -> r.urlPattern() + "|" + r.role() + "|" + r.allow())
                .sorted().toList();
        var bakedV1 = CanonicalSeed.forGateway("hugmesh-be-gateway").stream()
                .filter(r -> r.urlPattern().startsWith("/v1"))
                .map(r -> r.urlPattern() + "|" + r.role() + "|" + r.allow())
                .sorted().toList();
        assertThat(bakedV1)
            .as("guard sanity: CanonicalSeed must still carry the three /v1 rows")
            .containsExactly("/v1/**|ROLE_USER|true",
                             "/v1/analyze/**|ROLE_USER|true",
                             "/v1/synthesize/**|ROLE_USER|true");
        assertThat(composeV1)
            .as("compose/route-access-seed.sql must mirror the baked /v1 floor exactly")
            .isEqualTo(bakedV1);
    }

    @Test
    void composeSeed_beGateway_wholeBlockMatchesTheBakedCanonicalSeedExactly() {
        // F2 (skeptic finding, round 3). The /v1 parity test above filters on
        // startsWith("/v1"), so it is BLIND to drift anywhere else in the file — and
        // there was some: after the /v1 rows landed, the compose be-gateway block was
        // still a strict SUBSET of the baked seed, missing all four /games rows
        // (/games/api/admin/** -> ROLE_GAMES_ADMIN, and the /games/** floor paired to
        // ROLE_GAMES + ROLE_ADMIN + ROLE_MOD). No be-gateway pattern in the file was
        // /games-prefixed, so by the very argument that motivated the /v1 fix —
        // loadFromPostgres REPLACES the baked seed wholesale — a stack pointed at this
        // seed left /games/api/admin/** at NO_RULE, and NO_RULE FORWARDS. An ADMIN
        // surface ungoverned by this layer is a strictly worse posture than the
        // ROLE_USER capability floor the /v1 gap cost.
        //
        // This guard is deliberately UNFILTERED: set equality over the entire
        // be-gateway block, both directions, on (pattern, role, allow). Any future row
        // added to CanonicalSeed.be() and not to the dev seed — or vice versa — fails
        // here rather than in a stack six months later. There is no allowlist because
        // there is currently nothing deliberately dev-only in the be block; if a row
        // ever needs to be one-sided, add it to an explicit exception set HERE, with
        // the reason, rather than re-narrowing the filter.
        var compose = composeSeedRulesFor("hugmesh-be-gateway").stream()
                .map(r -> r.urlPattern() + "|" + r.role() + "|" + r.allow())
                .distinct().sorted().toList();
        var baked = CanonicalSeed.forGateway("hugmesh-be-gateway").stream()
                .map(r -> r.urlPattern() + "|" + r.role() + "|" + r.allow())
                .distinct().sorted().toList();
        assertThat(baked)
            .as("guard sanity: a broken CanonicalSeed lookup would make this vacuous")
            .hasSizeGreaterThan(20);
        assertThat(compose)
            .as("compose/route-access-seed.sql and CanonicalSeed.be() are a DUAL WRITE: "
                    + "the whole be-gateway block must agree on pattern, role and allow")
            .isEqualTo(baked);
    }

    @Test
    void composeSeed_beGateway_gamesSurface_resolves_andTheAdminApiIsNotUngoverned() {
        // The behavioural half of F2, phrased the way the /v1 test is: it is not
        // enough that the rows are PRESENT, the dev seed must actually decide these
        // paths. Before the four rows landed every assertion below answered NO_RULE
        // (-> forward), including the namespace ADMIN API.
        var rules = composeSeedRulesFor("hugmesh-be-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-be-gateway", true, false, null);
        s.primeForTest(rules);

        // Portal floor: governed, and the capability + its two supersets reach it.
        for (String path : List.of("/games", "/games/", "/games/catalog", "/games/play/xyz")) {
            assertThat(s.decide(path, "default", List.of(), List.of()))
                .as("%s must RESOLVE to a rule in the dev seed (never NO_RULE)", path)
                .isEqualTo(Decision.DENY);
            assertThat(s.decide(path, "default", List.of("u1"), List.of("ROLE_USER")))
                .as("a plain ROLE_USER holds no games-access capability")
                .isEqualTo(Decision.DENY);
            assertThat(s.decide(path, "default", List.of("u1"), List.of("ROLE_GAMES")))
                .isEqualTo(Decision.ALLOW);
            assertThat(s.decide(path, "default", List.of("u1"), List.of("ROLE_ADMIN")))
                .isEqualTo(Decision.ALLOW);
            assertThat(s.decide(path, "default", List.of("u1"), List.of("ROLE_MOD")))
                .isEqualTo(Decision.ALLOW);
        }

        // Namespace admin API: LONGER pattern wins, so the portal floor must NOT
        // widen onto it. This is the row whose absence left an admin surface at
        // NO_RULE -> forward.
        String adminApi = "/games/api/admin/purge";
        assertThat(s.decide(adminApi, "default", List.of(), List.of()))
            .as("the games namespace admin API must be GOVERNED, not NO_RULE")
            .isEqualTo(Decision.DENY);
        for (String role : List.of("ROLE_USER", "ROLE_GAMES", "ROLE_ADMIN", "ROLE_MOD")) {
            assertThat(s.decide(adminApi, "default", List.of("u1"), List.of(role)))
                .as("%s must NOT reach the games namespace admin API by longest-match", role)
                .isEqualTo(Decision.DENY);
        }
        assertThat(s.decide(adminApi, "default", List.of("u1"), List.of("ROLE_GAMES_ADMIN")))
            .isEqualTo(Decision.ALLOW);

        // The /games rows must not leak onto the neighbouring /api/** floor.
        assertThat(s.decide("/api/reports/q3", "default", List.of("u1"), List.of("ROLE_GAMES")))
            .as("ROLE_GAMES alone must not reach the hugmesh-apis floor")
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/api/reports/q3", "default", List.of("u1"), List.of("ROLE_USER")))
            .isEqualTo(Decision.ALLOW);
    }

    // ── The fe-gateway block in the LOCAL-DEV Postgres seed (issue #34) ─────────

    @Test
    void composeSeed_feGateway_wholeBlockMatchesTheBakedCanonicalSeedExactly() {
        // ENUMERATIVE PARITY (issue #34), the fe-gateway sibling of
        // composeSeed_beGateway_wholeBlockMatchesTheBakedCanonicalSeedExactly above,
        // for the same reason F2 motivated that one: the hand-listed
        // canonicalSeed_feGateway_internalDenyRows_areMirroredInTheComposePostgresSeed
        // test only pins THREE rows by name, and the fe block had drifted on the
        // OTHER 16 without any test going red — measured on main @ 13f1651d:
        // baked fe() carried 33 rows, the compose seed carried 17, and the missing
        // 16 included the whole anonymous SPA shell (/index.html, /*.js, /*.css,
        // /assets/**, the federation-read PUBLIC rows), the public login-page
        // announcements/appeal-contact reads, the /bff/admin/phone-fleet/** trio
        // and /games/admin/**. Since compose/route-access-seed.sql REPLACES the
        // baked seed wholesale once Postgres loads, the missing PUBLIC rows left
        // the dev stack's anonymous shell 401-walled where the baked floor opens
        // it, and (in the opposite direction of harm) a developer running the
        // compose stack never saw the phone-fleet / games-admin gates enforced at
        // all — both silent, because nothing enumerated the full set.
        //
        // Deliberately UNFILTERED, both directions, on (pattern, role, allow): any
        // future row added to CanonicalSeed.fe() and not mirrored here — or vice
        // versa — fails this test instead of waiting for another skeptic to grep
        // both files by hand. There is currently nothing deliberately dev-only in
        // the fe block; if one is ever needed, name it in an explicit exception set
        // HERE, with the reason, rather than re-narrowing this assertion.
        var compose = composeSeedRulesFor("hugmesh-fe-gateway").stream()
                .map(r -> r.urlPattern() + "|" + r.role() + "|" + r.allow())
                .distinct().sorted().toList();
        var baked = CanonicalSeed.forGateway("hugmesh-fe-gateway").stream()
                .map(r -> r.urlPattern() + "|" + r.role() + "|" + r.allow())
                .distinct().sorted().toList();
        assertThat(baked)
            .as("guard sanity: a broken CanonicalSeed lookup would make this vacuous")
            .hasSizeGreaterThan(20);
        assertThat(compose)
            .as("compose/route-access-seed.sql and CanonicalSeed.fe() are a DUAL WRITE: "
                    + "the whole fe-gateway block must agree on pattern, role and allow")
            .isEqualTo(baked);
    }

    @Test
    void composeSeed_feGateway_spaShellAndPublicReads_resolveAnonymously() {
        // Behavioural half, phrased like composeSeed_beGateway_gamesSurface above:
        // presence in the file is not enough on its own, the dev seed must actually
        // decide these paths PUBLIC. Before the rows landed every assertion below
        // answered NO_RULE (which the coarse authenticated() floor then 401s) —
        // i.e. the anonymous SPA shell was UNGOVERNED-and-401ing on this dev seed
        // even though the baked floor opens it.
        var rules = composeSeedRulesFor("hugmesh-fe-gateway");
        assertThat(rules)
            .as("parse sanity: the fe-gateway block must yield a plausible row count "
                    + "(a broken regex would make every assertion below vacuous)")
            .hasSizeGreaterThan(20);
        var s = new GatewayRouteAccessService(null, null, "hugmesh-fe-gateway", true, false, null);
        s.primeForTest(rules);

        for (String path : List.of("/index.html", "/favicon.ico", "/importmap.json",
                "/remoteEntry.json", "/main.abc123.js", "/styles.abc123.css",
                "/assets/logo.png", "/api/federation/vanity", "/api/federation/vanity/acme",
                "/api/federation/capabilities", "/bff/public/announcements/login",
                "/bff/public/appeal-contact")) {
            assertThat(s.decide(path, "default", List.of(), List.of()))
                .as("%s must resolve PUBLIC-allow (anonymous) in the dev seed", path)
                .isEqualTo(Decision.ALLOW);
        }

        // Fleet-owner + games-admin rows: governed (never NO_RULE) and gated on
        // their granted capability, not on plain ROLE_ADMIN alone re-opening
        // /bff/admin/** at the shorter pattern.
        assertThat(s.decide("/bff/admin/phone-fleet/devices", "default", List.of(), List.of()))
            .as("phone-fleet must RESOLVE to a rule in the dev seed (never NO_RULE)")
            .isEqualTo(Decision.DENY);
        for (String role : List.of("ROLE_FLEET_ADMIN", "ROLE_ADMIN", "ROLE_SUPERADMIN")) {
            assertThat(s.decide("/bff/admin/phone-fleet/devices", "default", List.of("u1"), List.of(role)))
                .as("%s must reach the fleet-owner surface in the dev seed", role)
                .isEqualTo(Decision.ALLOW);
        }
        assertThat(s.decide("/games/admin/purge", "default", List.of(), List.of()))
            .as("games-admin must RESOLVE to a rule in the dev seed (never NO_RULE)")
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/games/admin/purge", "default", List.of("u1"), List.of("ROLE_GAMES_ADMIN")))
            .isEqualTo(Decision.ALLOW);
        assertThat(s.decide("/games/admin/purge", "default", List.of("u1"), List.of("ROLE_ADMIN")))
            .as("plain ROLE_ADMIN alone must NOT satisfy the composite games-admin row")
            .isEqualTo(Decision.DENY);
    }

    // ── Image-builder console split (build-distribution) ──────────────────────

    @Test
    void canonicalSeed_beGateway_imageBuilds_keyedOnGrantedCapability_notAdminDefault() {
        // USER-SITUATIONAL: /bff/image-builds/** is the mesh-WORKLOAD build surface,
        // gated on the GRANTED ROLE_IMAGE_BUILDER. A plain ADMIN (without the
        // capability) is DENIED — build is not an admin default (build≠run).
        var seed = CanonicalSeed.forGateway("hugmesh-be-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-be-gateway", true, false, null);
        s.primeForTest(seed);
        assertThat(s.decide("/bff/image-builds/foo", "default", List.of("u1"), List.of("ROLE_USER", "ROLE_ADMIN")))
            .as("plain admin must NOT build workload images")
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/bff/image-builds/foo", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_IMAGE_BUILDER")))
            .as("granted image-builder may build")
            .isEqualTo(Decision.ALLOW);
        // a plain user is denied
        assertThat(s.decide("/bff/image-builds/foo", "default", List.of("u1"), List.of("ROLE_USER")))
            .isEqualTo(Decision.DENY);
    }

    @Test
    void canonicalSeed_beGateway_archAndSuperadminBuilds_superadminOnly_byLongestMatch() {
        // CROSS-USER (negative): the arch/core build sub-surface is SUPERADMIN-only
        // and WINS over the broader image-builds floor by longest-pattern-match, so
        // an IMAGE_BUILDER (workload-only) is DENIED on arch/**.
        var seed = CanonicalSeed.forGateway("hugmesh-be-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-be-gateway", true, false, null);
        s.primeForTest(seed);
        assertThat(s.decide("/bff/image-builds/arch/x86", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_IMAGE_BUILDER")))
            .as("image-builder must NOT reach arch/core builds")
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/bff/image-builds/arch/x86", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_SUPERADMIN")))
            .isEqualTo(Decision.ALLOW);
        // superadmin infra console
        assertThat(s.decide("/bff/superadmin/domains", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_ADMIN")))
            .as("plain admin must NOT reach the superadmin console")
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/bff/superadmin/domains", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_SUPERADMIN")))
            .isEqualTo(Decision.ALLOW);
    }

    @Test
    void canonicalSeed_beGateway_imageBuildRows_notPairedWithAdmin() {
        // Seed-parity guard: /bff/image-builds/** must NOT carry a ROLE_ADMIN allow
        // row (that would let every per-domain admin build images). Only the granted
        // ROLE_IMAGE_BUILDER (workload) + ROLE_SUPERADMIN (arch sub-surface) appear.
        var seed = CanonicalSeed.forGateway("hugmesh-be-gateway");
        for (var r : seed) {
            if ("/bff/image-builds/**".equals(r.urlPattern()) && r.allow()) {
                assertThat(r.role())
                    .as("image-builds floor must be the granted capability, not an admin default")
                    .isEqualTo("ROLE_IMAGE_BUILDER");
            }
            if ("/bff/image-builds/arch/**".equals(r.urlPattern()) && r.allow()) {
                assertThat(r.role()).isEqualTo("ROLE_SUPERADMIN");
            }
        }
    }

    // ── hugmesh-games (OPTIONAL slug) floor — DB-seed parity ───────────────

    @Test
    void canonicalSeed_beGateway_gamesPortalFloor_gatedByGamesAccessRole() {
        // The games portal floor /games/** is gated by the network-wide ROLE_GAMES
        // access role (NOT the broad ROLE_USER floor): a plain ROLE_USER is DENIED,
        // a ROLE_GAMES holder is ALLOWED, and a games BAN (role removal) closes the
        // portal. ROLE_ADMIN + ROLE_MOD are paired (supersets) so they keep reaching
        // it. Without this baked floor the games surface would be UNGOVERNED on the
        // datastore-unreachable fallback.
        var seed = CanonicalSeed.forGateway("hugmesh-be-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-be-gateway", true, false, null);
        s.primeForTest(seed);
        // a plain authenticated user (no games access) is DENIED on the games surface
        assertThat(s.decide("/games/lobby", "default", List.of("u1"), List.of("ROLE_USER")))
            .as("plain ROLE_USER must NOT reach the games portal")
            .isEqualTo(Decision.DENY);
        // a games member is ALLOWED
        assertThat(s.decide("/games/lobby", "default", List.of("u1"), List.of("ROLE_USER", "ROLE_GAMES")))
            .as("ROLE_GAMES must reach the games portal")
            .isEqualTo(Decision.ALLOW);
        // admins + mods are paired supersets
        assertThat(s.decide("/games/lobby", "default", List.of("u1"), List.of("ROLE_USER", "ROLE_ADMIN")))
            .isEqualTo(Decision.ALLOW);
        assertThat(s.decide("/games/lobby", "default", List.of("u1"), List.of("ROLE_USER", "ROLE_MOD")))
            .isEqualTo(Decision.ALLOW);
    }

    @Test
    void canonicalSeed_beGateway_gamesAdminApi_isGamesAdminComposite_byLongestMatch() {
        // The games namespace admin API /games/api/admin/** is keyed on the DERIVED
        // composite ROLE_GAMES_ADMIN ONLY (= ROLE_GAMES intersect (ADMIN|MOD)), and
        // it is LONGER than the /games/** portal floor so longest-pattern-match makes
        // it the deciding rule. Neither ROLE_GAMES alone nor ROLE_ADMIN alone reaches
        // it — only the materialized composite authority.
        var seed = CanonicalSeed.forGateway("hugmesh-be-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-be-gateway", true, false, null);
        s.primeForTest(seed);
        // ROLE_GAMES alone (portal-floor role) is DENIED on the admin API (longest match wins)
        assertThat(s.decide("/games/api/admin/x", "default", List.of("u1"), List.of("ROLE_USER", "ROLE_GAMES")))
            .as("ROLE_GAMES alone must NOT reach the games admin API")
            .isEqualTo(Decision.DENY);
        // a plain ADMIN alone is DENIED (the composite is not collapsed to ADMIN)
        assertThat(s.decide("/games/api/admin/x", "default", List.of("u1"), List.of("ROLE_USER", "ROLE_ADMIN")))
            .as("plain ROLE_ADMIN must NOT satisfy the games admin composite")
            .isEqualTo(Decision.DENY);
        // the materialized composite authority is ALLOWED
        assertThat(s.decide("/games/api/admin/x", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_GAMES_ADMIN")))
            .as("ROLE_GAMES_ADMIN must reach the games admin API")
            .isEqualTo(Decision.ALLOW);
    }

    @Test
    void canonicalSeed_feGateway_gamesAdminUi_isGamesAdminComposite() {
        // fe-gateway carries ONLY the games namespace admin UI row
        // /games/admin/** -> ROLE_GAMES_ADMIN (the portal floor lives on be). A plain
        // ROLE_USER (and a plain ADMIN, and a plain GAMES) is DENIED; only the
        // composite ROLE_GAMES_ADMIN reaches it.
        var seed = CanonicalSeed.forGateway("hugmesh-fe-gateway");
        var s = new GatewayRouteAccessService(null, null, "hugmesh-fe-gateway", true, false, null);
        s.primeForTest(seed);
        assertThat(s.decide("/games/admin/dashboard", "default", List.of("u1"), List.of("ROLE_USER")))
            .as("plain ROLE_USER must NOT reach the games admin UI")
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/games/admin/dashboard", "default", List.of("u1"), List.of("ROLE_USER", "ROLE_ADMIN")))
            .as("plain ROLE_ADMIN must NOT satisfy the games admin composite")
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/games/admin/dashboard", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_GAMES_ADMIN")))
            .as("ROLE_GAMES_ADMIN must reach the games admin UI")
            .isEqualTo(Decision.ALLOW);
    }

    @Test
    void canonicalSeed_gamesRows_presentAndMatchDbSeed() {
        // Seed-parity guard: the baked floor must carry EXACTLY the games rows the
        // cluster Postgres seed (route-access/initdb/20-schema.sql) defines, so the
        // datastore-unreachable fallback governs the games surface identically:
        //   be-gateway: /games/api/admin/** -> ROLE_GAMES_ADMIN
        //               /games/** -> {ROLE_GAMES, ROLE_ADMIN, ROLE_MOD}
        //   fe-gateway: /games/admin/** -> ROLE_GAMES_ADMIN
        record Expect(String pattern, String role) {}
        var be = CanonicalSeed.forGateway("hugmesh-be-gateway");
        for (Expect e : List.of(
                new Expect("/games/api/admin/**", "ROLE_GAMES_ADMIN"),
                new Expect("/games/**",           "ROLE_GAMES"),
                new Expect("/games/**",           "ROLE_ADMIN"),
                new Expect("/games/**",           "ROLE_MOD"))) {
            assertThat(be)
                .as("be games row %s -> %s (allow) must be present in the seed", e.pattern(), e.role())
                .anyMatch(r -> e.pattern().equals(r.urlPattern())
                        && e.role().equals(r.role()) && r.allow());
        }
        var fe = CanonicalSeed.forGateway("hugmesh-fe-gateway");
        assertThat(fe)
            .as("fe games admin UI row /games/admin/** -> ROLE_GAMES_ADMIN (allow) must be present")
            .anyMatch(r -> "/games/admin/**".equals(r.urlPattern())
                    && "ROLE_GAMES_ADMIN".equals(r.role()) && r.allow());
        // and the games surface must NOT be granted to the broad ROLE_USER floor on
        // either tier (that would make a logged-in non-member reach games).
        for (var r : be) {
            if ((r.urlPattern().startsWith("/games/")) && r.allow()) {
                assertThat(r.role())
                    .as("be games pattern %s must not be granted to ROLE_USER", r.urlPattern())
                    .isNotEqualTo("ROLE_USER");
            }
        }
        for (var r : fe) {
            if ((r.urlPattern().startsWith("/games/")) && r.allow()) {
                assertThat(r.role())
                    .as("fe games pattern %s must not be granted to ROLE_USER", r.urlPattern())
                    .isNotEqualTo("ROLE_USER");
            }
        }
    }

    // ── Per-row domain scoping (multi-brand architecture tier) — BUG 1 keystone ─

    @Test
    void crossTenant_brandScopedAdminRow_doesNotGrantAcrossDomains() {
        // The cross-tenant escalation keystone at the SERVICE layer. A brand-Y
        // `/api/admin/** -> ROLE_ADMIN allow=true` row (domain="brandy") must apply
        // ONLY to the brandy surface. A query whose target domain is brandx is NOT
        // granted by it, even though the principal holds ROLE_ADMIN — so a brand-X
        // admin can never be re-granted by another brand's admin row. (The matching
        // filter-level hard-deny is GatewayRouteAccessFilterTest.)
        var s = svc(rule("/api/admin/**", "ROLE_ADMIN", null, true, "brandy"));

        // brandy admin row applies on the brandy surface -> ALLOW
        assertThat(s.decide("/api/admin/x", "brandy", List.of(), List.of("ROLE_USER", "ROLE_ADMIN")))
            .as("brand-Y-scoped admin row grants on the brand-Y surface")
            .isEqualTo(Decision.ALLOW);

        // SAME held authorities, but the request targets brandx: the brandy-scoped
        // row does NOT apply -> governed (longest match) but ungranted -> DENY.
        assertThat(s.decide("/api/admin/x", "brandx", List.of(), List.of("ROLE_USER", "ROLE_ADMIN")))
            .as("brand-Y-scoped admin row must NOT grant on the brand-X surface (cross-tenant)")
            .isEqualTo(Decision.DENY);
    }

    @Test
    void crossTenant_brandXAdminRow_doesNotGrantOnBrandYTarget() {
        // Mirror of the prompt's named case: a brand-X-scoped admin row, queried
        // with targetDomain="brandy" and the brand-X admin's held authorities,
        // DENIES — the brandx row does not reach the brandy surface.
        var s = svc(rule("/api/admin/**", "ROLE_ADMIN", null, true, "brandx"));
        assertThat(s.decide("/api/admin/x", "brandy", List.of(), List.of("ROLE_USER", "ROLE_ADMIN")))
            .as("brand-X-scoped admin row must NOT grant on the brand-Y surface")
            .isEqualTo(Decision.DENY);
        // ...and it still grants on its OWN (brandx) surface.
        assertThat(s.decide("/api/admin/x", "brandx", List.of(), List.of("ROLE_USER", "ROLE_ADMIN")))
            .isEqualTo(Decision.ALLOW);
    }

    @Test
    void unscopedRow_appliesToAnyDomain_backCompat() {
        // A NULL-domain (unscoped) row — the back-compat + canonical-seed shape —
        // applies regardless of target domain, so single-tenant ("default") and any
        // brand surface are all granted.
        var s = svc(rule("/api/admin/**", "ROLE_ADMIN", null, true));   // domain=null
        assertThat(s.decide("/api/admin/x", "default", List.of(), List.of("ROLE_USER", "ROLE_ADMIN")))
            .isEqualTo(Decision.ALLOW);
        assertThat(s.decide("/api/admin/x", "brandx", List.of(), List.of("ROLE_USER", "ROLE_ADMIN")))
            .isEqualTo(Decision.ALLOW);
        assertThat(s.decide("/api/admin/x", "brandy", List.of(), List.of("ROLE_USER", "ROLE_ADMIN")))
            .isEqualTo(Decision.ALLOW);
    }

    // ── AND-composite intersection roles are NOT collapsed (V2 keystone) ──────

    @Test
    void crossUser_andCompositeRows_notSatisfiedByPlainAdmin() {
        // CROSS-USER: ROLE_GAMES_ADMIN / ROLE_FORUM_MOD are AND-intersection
        // composites encoded as a SINGLE deciding row each. A plain ADMIN must NOT
        // satisfy them — the route-access table is role-string equality (no
        // hierarchy collapse), so only the exact composite authority allows.
        var s = svc(
            rule("/games/admin/**", "ROLE_GAMES_ADMIN", null, true),
            rule("/forum/mod/**",   "ROLE_FORUM_MOD",   null, true));
        // plain admin / mod do NOT satisfy the composite rows
        assertThat(s.decide("/games/admin/x", "default", List.of("u1"), List.of("ROLE_USER", "ROLE_ADMIN")))
            .as("plain ADMIN must NOT satisfy ROLE_GAMES_ADMIN")
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/forum/mod/x", "default", List.of("u1"), List.of("ROLE_USER", "ROLE_MOD")))
            .as("plain MOD must NOT satisfy ROLE_FORUM_MOD")
            .isEqualTo(Decision.DENY);
        // the materialised composite authority (minted by Casdoor) DOES satisfy
        assertThat(s.decide("/games/admin/x", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_GAMES_ADMIN")))
            .isEqualTo(Decision.ALLOW);
        assertThat(s.decide("/forum/mod/x", "default", List.of("u1"),
                List.of("ROLE_USER", "ROLE_FORUM_MOD")))
            .isEqualTo(Decision.ALLOW);
    }

    @Test
    void crossUser_modIsSiblingOfAdmin_adminDoesNotSatisfyModOnlyRow() {
        // ROLE_MOD is a documented SIBLING of ROLE_ADMIN. The route-access table
        // does NOT auto-grant a MOD-only row to an admin (that pairing, where
        // wanted, is an EXPLICIT extra row — not a hierarchy edge).
        var s = svc(rule("/mod/only/**", "ROLE_MOD", null, true));
        assertThat(s.decide("/mod/only/x", "default", List.of("u1"), List.of("ROLE_USER", "ROLE_ADMIN")))
            .as("a plain ADMIN must NOT satisfy a MOD-only row (siblings)")
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/mod/only/x", "default", List.of("u1"), List.of("ROLE_USER", "ROLE_MOD")))
            .isEqualTo(Decision.ALLOW);
    }

    // ── bySuffix: per-brand instances closed-by-default (V7) ──────────────────

    @Test
    void perBrandInstance_derivesTierBySuffix_closedByDefault() {
        // A runtime-added per-brand be-gateway derives the BE tier (closed-by-
        // default: /api/admin/** ADMIN-only) instead of fail-open List.of().
        var seed = CanonicalSeed.forGateway("brandx-be-gateway");
        assertThat(seed).as("per-brand be instance gets the BE tier floor").isNotEmpty();
        var s = new GatewayRouteAccessService(null, null, "brandx-be-gateway", true, false, null);
        s.primeForTest(seed);
        assertThat(s.decide("/api/admin/users", "default", List.of("u1"), List.of("ROLE_USER")))
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/api/admin/users", "default", List.of("u1"), List.of("ROLE_USER", "ROLE_ADMIN")))
            .isEqualTo(Decision.ALLOW);
        // fe + pki suffixes resolve to their tiers too
        assertThat(CanonicalSeed.forGateway("brandy-fe-gateway")).isNotEmpty();
        assertThat(CanonicalSeed.forGateway("brandz-pki-gateway")).isNotEmpty();
    }

    @Test
    void unknownGatewayName_getsClosedDenyAllFloor_notFailOpen() {
        // A truly unknown name (no known suffix) is CLOSED: only ADMIN reaches any
        // path; a ROLE_USER is DENIED everywhere (was fail-open List.of() before).
        var seed = CanonicalSeed.forGateway("totally-unknown-thing");
        assertThat(seed).as("unknown gateway must have a closed floor, not empty").isNotEmpty();
        var s = new GatewayRouteAccessService(null, null, "totally-unknown-thing", true, false, null);
        s.primeForTest(seed);
        assertThat(s.decide("/anything/at/all", "default", List.of("u1"), List.of("ROLE_USER")))
            .as("unknown gateway is closed-by-default for ROLE_USER")
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/anything/at/all", "default", List.of("u1"), List.of("ROLE_USER", "ROLE_ADMIN")))
            .isEqualTo(Decision.ALLOW);
    }

    @Test
    void nullOrBlankGatewayName_getsClosedDenyAllFloor_notFailOpen() {
        // The SHARPEST residual fail-open: a null/blank spring.application.name used
        // to return List.of() -> every path NO_RULE -> the filter FORWARDS = fail-OPEN.
        // It now falls through to the SAME closed deny-floor as an unknown name, so a
        // misconfigured/blank instance name can never leave the gate ungoverned.
        for (String name : new String[] {null, "", "   "}) {
            var seed = CanonicalSeed.forGateway(name);
            assertThat(seed)
                .as("null/blank gateway name must have a closed floor, not empty (was fail-open)")
                .isNotEmpty();
            var s = new GatewayRouteAccessService(null, null, name, true, false, null);
            s.primeForTest(seed);
            // ROLE_USER is DENIED on every path (closed-by-default), NOT NO_RULE/forward.
            assertThat(s.decide("/anything/at/all", "default", List.of("u1"), List.of("ROLE_USER")))
                .as("null/blank-named gateway is closed-by-default for ROLE_USER")
                .isEqualTo(Decision.DENY);
            // ADMIN still reaches the floor (the recovery seam mirrors the unknown floor).
            assertThat(s.decide("/anything/at/all", "default", List.of("u1"),
                    List.of("ROLE_USER", "ROLE_ADMIN")))
                .isEqualTo(Decision.ALLOW);
        }
    }

    @Test
    void refreshPath_isRoutedThroughRouteAccessBreaker() {
        // A pass-through breaker that records each guarded read, plus a factory that
        // hands the service its dedicated "routeAccess" instance.
        AtomicInteger runs = new AtomicInteger();
        ReactiveCircuitBreaker passthrough = new ReactiveCircuitBreaker() {
            @Override public <T> Mono<T> run(Mono<T> toRun, Function<Throwable, Mono<T>> fb) {
                runs.incrementAndGet();
                return toRun.onErrorResume(fb);
            }
            @Override public <T> Flux<T> run(Flux<T> toRun, Function<Throwable, Flux<T>> fb) {
                runs.incrementAndGet();
                return toRun.onErrorResume(fb);
            }
        };
        RecordingCbFactory factory = new RecordingCbFactory(passthrough);

        // No datastore wired: the refresh read completes empty, exercising the guard
        // without a live Postgres/Cassandra.
        var s = new GatewayRouteAccessService(null, null, "hugmesh-be-gateway", true, false, factory);
        // The service asks the factory for exactly its own breaker instance.
        assertThat(factory.created).containsExactly("routeAccess");

        // Drive a refresh tick; the datastore read is routed through the breaker.
        s.init();
        assertThat(runs.get()).isGreaterThanOrEqualTo(1);

        // Breaker-open/empty refresh must not fail open: the seed is still enforced.
        assertThat(s.decide("/api/admin/users", "default", List.of(), List.of("ROLE_USER")))
            .isEqualTo(Decision.DENY);
    }

    // ── D8 per-row mfa_required gate in decide() (behind app.mfa.enabled) ─────
    // The MFA_SATISFIED marker is a NON-role authority the converter adds from a
    // fresh stamp; in these unit tests we pass it directly in the authorities set.

    private static final String MFA = net.hugmesh.gateway.security.Roles.MFA_SATISFIED;

    @Test
    void mfaRequiredRoute_deniedWithoutMarker_allowedWith() {
        // app.mfa.enabled=true so the gate is LIVE. A mfa_required ROLE_USER row:
        // a plain ROLE_USER lacking the marker is DENIED; with MFA_SATISFIED ALLOWED.
        var s = svcMfaOn(mfaRule("/bff/sudo/**", "ROLE_USER"));
        assertThat(s.decide("/bff/sudo/exec", "default", List.of(), List.of("ROLE_USER")))
            .as("mfa_required route without MFA_SATISFIED -> DENY").isEqualTo(Decision.DENY);
        assertThat(s.decide("/bff/sudo/exec", "default", List.of(), List.of("ROLE_USER", MFA)))
            .as("mfa_required route WITH a fresh MFA_SATISFIED -> ALLOW").isEqualTo(Decision.ALLOW);
    }

    @Test
    void mfaRequiredRoute_darkDefault_markerIrrelevant_legacyBehaviour() {
        // app.mfa.enabled=false (dark default): the mfa_required column is INERT —
        // a ROLE_USER is ALLOWED on the same row WITHOUT any marker (byte-identical
        // to legacy). svc(...) builds the service with mfaEnabled=false.
        var s = svc(mfaRule("/bff/sudo/**", "ROLE_USER"));
        assertThat(s.decide("/bff/sudo/exec", "default", List.of(), List.of("ROLE_USER")))
            .as("dark default ignores mfa_required -> legacy ALLOW").isEqualTo(Decision.ALLOW);
    }

    @Test
    void mfaRequired_onlyGatesTheGrantingRule_notAnUnheldRow() {
        // Two rows at the SAME longest pattern: a non-mfa ROLE_USER allow AND an
        // mfa_required ROLE_ADMIN allow. A plain ROLE_USER (no MFA) is GRANTED by the
        // ROLE_USER row (which it satisfies and which does NOT require MFA) — the
        // ADMIN mfa_required row it does NOT satisfy can't pull the floor up on it.
        var s = svcMfaOn(
                rule("/api/x/**", "ROLE_USER", null, true),
                mfaRule("/api/x/**", "ROLE_ADMIN"));
        assertThat(s.decide("/api/x/go", "default", List.of(), List.of("ROLE_USER")))
            .as("the unheld ADMIN mfa_required row does not gate a USER granted elsewhere")
            .isEqualTo(Decision.ALLOW);
        // An ADMIN (who DOES satisfy the mfa_required ROLE_ADMIN row) without the
        // marker is DENIED on that grant.
        assertThat(s.decide("/api/x/go", "default", List.of(), List.of("ROLE_ADMIN")))
            .as("the granting ADMIN row's mfa_required gates the admin without a marker")
            .isEqualTo(Decision.DENY);
        // ...and the ADMIN WITH the marker is ALLOWED.
        assertThat(s.decide("/api/x/go", "default", List.of(), List.of("ROLE_ADMIN", MFA)))
            .isEqualTo(Decision.ALLOW);
    }

    @Test
    void isMfaRequiredSurface_reflectsTheDecidingRule() {
        var s = svcMfaOn(
                rule("/api/**", "ROLE_USER", null, true),
                mfaRule("/api/secure/**", "ROLE_USER"));
        // Longest pattern /api/secure/** is mfa_required; the broader /api/** is not.
        assertThat(s.isMfaRequiredSurface("/api/secure/op", "default")).isTrue();
        assertThat(s.isMfaRequiredSurface("/api/open/op", "default")).isFalse();
        // Ungoverned path -> no floor.
        assertThat(s.isMfaRequiredSurface("/nope/here", "default")).isFalse();
    }

    // ── DECISION 56 — the declared MFA-required set on the baked floor ──────────
    // hugmesh-generator#347, operator answer 2026-09-18: "a declared set of
    // privileged rows". See CanonicalSeed.MFA_REQUIRED_FALLBACK_ROWS for the full
    // derivation from the cluster Postgres seed's blanket flip UPDATE.

    @Test
    void canonicalSeed_mfaRequiredFallbackRows_everyEntryMatchesARealBakedRow() {
        // TYPO SAFETY. CanonicalSeed.r() looks entries up by Rule.id(); an id that
        // does not match any row CanonicalSeed actually emits would simply never be
        // found, silently declaring NOTHING rather than failing loud. This proves
        // the declared set is a SUBSET of the ids the three real tiers emit (plus
        // the generic per-brand/unknown floor, which cannot carry a declared row by
        // construction — it is always exactly one r(gateway, "/**", "ROLE_ADMIN")).
        var allIds = java.util.stream.Stream.of(
                        CanonicalSeed.forGateway(CanonicalSeed.PKI),
                        CanonicalSeed.forGateway(CanonicalSeed.BE),
                        CanonicalSeed.forGateway(CanonicalSeed.FE))
                .flatMap(List::stream)
                .map(Rule::id)
                .collect(java.util.stream.Collectors.toSet());
        assertThat(allIds)
            .as("every MFA_REQUIRED_FALLBACK_ROWS entry must be a real baked row id")
            .containsAll(CanonicalSeed.MFA_REQUIRED_FALLBACK_ROWS);
    }

    @Test
    void canonicalSeed_declaredMfaRows_isMfaRequiredSurfaceIsTrueOnTheFallback() {
        // Every row named in the declared set: isMfaRequiredSurface() must be TRUE
        // on the SEED-ONLY fallback (no datastore, no Postgres flip needed) for a
        // representative path under it.
        var be = new GatewayRouteAccessService(null, null, CanonicalSeed.BE, true, false, null);
        be.primeForTest(CanonicalSeed.forGateway(CanonicalSeed.BE));
        assertThat(be.isMfaRequiredSurface("/bff/superadmin/workloads", "default"))
            .as("be /bff/superadmin/** is in the declared set")
            .isTrue();
        // The be row also governs the games-services subtree (no more specific be
        // row exists), so the declared floor's MFA gain reaches it too.
        assertThat(be.isMfaRequiredSurface("/bff/superadmin/games-services/catalog", "default"))
            .as("be /bff/superadmin/** covers its own games-services subtree")
            .isTrue();

        var fe = new GatewayRouteAccessService(null, null, CanonicalSeed.FE, true, false, null);
        fe.primeForTest(CanonicalSeed.forGateway(CanonicalSeed.FE));
        assertThat(fe.isMfaRequiredSurface("/bff/superadmin/service-store/catalog", "default"))
            .as("fe /bff/superadmin/** is in the declared set (decision 41's row)")
            .isTrue();
        assertThat(fe.isMfaRequiredSurface("/bff/admin/phone-fleet/devices", "default"))
            .as("fe /bff/admin/phone-fleet/** is in the declared set (all three paired roles)")
            .isTrue();
        assertThat(fe.isMfaRequiredSurface("/bff/admin/announcements", "default"))
            .as("fe /bff/admin/** is in the declared set")
            .isTrue();
    }

    @Test
    void canonicalSeed_undeclaredPrivilegedRows_isMfaRequiredSurfaceStaysFalse() {
        // D8's default is UNCHANGED for every baked row NOT in the declared set,
        // even other SUPERADMIN-only surfaces — narrowing is deliberate, not a
        // side effect of "every privileged row gained it".
        var pki = new GatewayRouteAccessService(null, null, CanonicalSeed.PKI, true, false, null);
        pki.primeForTest(CanonicalSeed.forGateway(CanonicalSeed.PKI));
        // pki bakes no /** headscale row any more (decision 79 = B moved headscale's
        // floor to SecurityConfig's Host gate), so /key is NO_RULE on the pki seed
        // and can never be an mfa_required surface there; none of pki's remaining
        // rows is in the declared set either.
        assertThat(pki.isMfaRequiredSurface("/key", "default"))
            .as("no pki row is in the declared set, and /key matches none of them")
            .isFalse();

        var be = new GatewayRouteAccessService(null, null, CanonicalSeed.BE, true, false, null);
        be.primeForTest(CanonicalSeed.forGateway(CanonicalSeed.BE));
        assertThat(be.isMfaRequiredSurface("/bff/image-builds/arch/x86", "default"))
            .as("be's /bff/image-builds/arch/** is SUPERADMIN-only but NOT in the "
              + "declared set (not under /bff/admin or /bff/superadmin)")
            .isFalse();
    }

    // ── DECISION 80a = B — all three wiki rows on the fe baked floor ────────────
    // hugmesh-generator#329, operator answer 2026-09-23 (against the "add only the
    // superadmin row" recommendation). Mirrors generator
    // specs/cluster/manifests/route-access/initdb/20-schema.sql:1068-1070.

    /** An fe gateway with BOTH datastores unreachable (no Cassandra template, no
     *  Postgres repository): init() seeds CanonicalSeed.fe() and nothing ever
     *  supersedes it — the exact startup-window / dead-datastore state 80a is about. */
    private static GatewayRouteAccessService feSeedOnly(boolean mfaEnabled) {
        var s = new GatewayRouteAccessService(null, null, CanonicalSeed.FE, true, mfaEnabled, null);
        s.init();
        return s;
    }

    @Test
    void canonicalSeed_feWikiFloor_roleUserWithoutWiki_isRefusedOnTheWikiBff() {
        var s = feSeedOnly(false);
        // RED on origin/main 22663fe: fe() had no wiki row, so this was NO_RULE (forward).
        assertThat(s.decide("/bff/wiki/x", "default", List.of("u1"), List.of("ROLE_USER")))
            .as("/bff/wiki/** is ROLE_WIKI on the baked floor; ROLE_USER alone is refused")
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/bff/wiki/pages/home", "default", List.of("u1"), List.of("ROLE_USER", "ROLE_WIKI")))
            .as("the wiki-access capability reaches the wiki floor")
            .isEqualTo(Decision.ALLOW);
    }

    @Test
    void canonicalSeed_feWikiAdminFloor_isAdminOnly() {
        var s = feSeedOnly(false);
        // RED on origin/main 22663fe: NO_RULE.
        assertThat(s.decide("/bff/wiki/admin/config", "default", List.of("u1"), List.of("ROLE_USER", "ROLE_WIKI")))
            .as("/bff/wiki/admin/** is ROLE_ADMIN; the wiki floor must not widen onto it")
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/bff/wiki/admin/config", "default", List.of("u1"), List.of("ROLE_ADMIN")))
            .isEqualTo(Decision.ALLOW);
    }

    @Test
    void canonicalSeed_feWikiSuperadminFloor_plainAdminIsRefused() {
        var s = feSeedOnly(false);
        // RED on origin/main 22663fe: NO_RULE.
        assertThat(s.decide("/bff/wiki/superadmin/x", "default", List.of("u1"), List.of("ROLE_ADMIN")))
            .as("/bff/wiki/superadmin/** is ROLE_SUPERADMIN; a plain ADMIN is refused by decide()")
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/bff/wiki/superadmin/x", "default", List.of("u1"), List.of("ROLE_USER", "ROLE_WIKI")))
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/bff/wiki/superadmin/x", "default", List.of("u1"), List.of("ROLE_SUPERADMIN")))
            .isEqualTo(Decision.ALLOW);
    }

    @Test
    void canonicalSeed_feWikiRows_mirrorTheClusterSeedRoleStrings() {
        // Byte-level pin of the three rows (pattern, role, allow) so a role-string
        // typo on either side is caught here rather than on a live mesh.
        var wiki = CanonicalSeed.forGateway(CanonicalSeed.FE).stream()
                .filter(r -> r.urlPattern().startsWith("/bff/wiki"))
                .map(r -> r.urlPattern() + "|" + r.role() + "|" + r.allow())
                .sorted().toList();
        assertThat(wiki).containsExactly(
                "/bff/wiki/**|ROLE_WIKI|true",
                "/bff/wiki/admin/**|ROLE_ADMIN|true",
                "/bff/wiki/superadmin/**|ROLE_SUPERADMIN|true");
    }

    // ── DECISION 80b = B — per-service admin + superadmin rows carry MFA ────────
    // hugmesh-generator#329, operator answer 2026-09-23. The two wiki console rows
    // join MFA_REQUIRED_FALLBACK_ROWS; the /bff/wiki/** floor stays false.

    @Test
    void canonicalSeed_feWikiConsoleRows_raiseMfaRequiredOnGrant() {
        var s = feSeedOnly(true);
        String mfa = net.hugmesh.gateway.security.Roles.MFA_SATISFIED;
        // RED on origin/main 22663fe: NO_RULE for every line below.
        assertThat(s.decide("/bff/wiki/admin/config", "default", List.of("u1"), List.of("ROLE_ADMIN")))
            .as("the wiki admin-console grant demands a fresh second factor")
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/bff/wiki/admin/config", "default", List.of("u1"), List.of("ROLE_ADMIN", mfa)))
            .isEqualTo(Decision.ALLOW);
        assertThat(s.decide("/bff/wiki/superadmin/x", "default", List.of("u1"), List.of("ROLE_SUPERADMIN")))
            .as("the wiki superadmin-console grant demands a fresh second factor")
            .isEqualTo(Decision.DENY);
        assertThat(s.decide("/bff/wiki/superadmin/x", "default", List.of("u1"), List.of("ROLE_SUPERADMIN", mfa)))
            .isEqualTo(Decision.ALLOW);
        // The wiki-access floor is NOT an MFA surface.
        assertThat(s.decide("/bff/wiki/pages/home", "default", List.of("u1"), List.of("ROLE_USER", "ROLE_WIKI")))
            .as("/bff/wiki/** stays mfa_required=false")
            .isEqualTo(Decision.ALLOW);

        // The privileged-floor view GatewayRouteAccessFilter consults for the
        // ADMIN/SUPERADMIN bypasses (which never reach decide()).
        assertThat(s.isMfaRequiredSurface("/bff/wiki/admin/config", "default")).isTrue();
        assertThat(s.isMfaRequiredSurface("/bff/wiki/superadmin/x", "default")).isTrue();
        assertThat(s.isMfaRequiredSurface("/bff/wiki/pages/home", "default")).isFalse();
    }

    @Test
    void isPrimed_seedOnly_isTrue_noDatastore() {
        // No Postgres + no Cassandra wired: the seed IS authoritative — since
        // decision 56 it DOES carry some mfa_required=true rows (be()'s
        // /bff/superadmin/** among them), but nothing ever supersedes the seed in
        // this mode, so there is no discovery lag for isPrimed() to guard against.
        // isPrimed() is TRUE and the floor is never a 503.
        var s = new GatewayRouteAccessService(null, null, "hugmesh-be-gateway", true, true, null);
        s.init();
        assertThat(s.isPrimed()).isTrue();
    }

    /** Minimal {@link ReactiveCircuitBreakerFactory} that records the breaker ids it
     *  is asked to create and returns a caller-supplied instance. */
    @SuppressWarnings({"rawtypes", "unchecked"})
    private static final class RecordingCbFactory extends ReactiveCircuitBreakerFactory {
        final List<String> created = new ArrayList<>();
        private final ReactiveCircuitBreaker breaker;
        RecordingCbFactory(ReactiveCircuitBreaker breaker) { this.breaker = breaker; }
        @Override public ReactiveCircuitBreaker create(String id) {
            created.add(id);
            return breaker;
        }
        @Override protected ConfigBuilder configBuilder(String id) { return null; }
        @Override public void configureDefault(Function defaultConfiguration) { }
    }
}
