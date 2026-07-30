package systems.hugmesh.gateway.cache;

import org.junit.jupiter.api.Test;
import org.springframework.cloud.client.circuitbreaker.ConfigBuilder;
import org.springframework.cloud.client.circuitbreaker.ReactiveCircuitBreaker;
import org.springframework.cloud.client.circuitbreaker.ReactiveCircuitBreakerFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.gateway.cache.GatewayRouteAccessService.Decision;
import systems.hugmesh.gateway.cache.GatewayRouteAccessService.Rule;

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
 * {@link systems.hugmesh.gateway.filter.GatewayRouteAccessFilter} relies on.
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

    private static final String MFA = systems.hugmesh.gateway.security.Roles.MFA_SATISFIED;

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

    @Test
    void isPrimed_seedOnly_isTrue_noDatastore() {
        // No Postgres + no Cassandra wired: the seed IS authoritative (it carries no
        // mfa_required rows), so isPrimed() is TRUE and the floor is never a 503.
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
