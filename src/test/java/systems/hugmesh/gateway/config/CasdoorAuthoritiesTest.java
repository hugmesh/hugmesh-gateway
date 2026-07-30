package systems.hugmesh.gateway.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import systems.hugmesh.gateway.security.DomainRegistry;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link CasdoorAuthorities} — the SHARED JWT-&gt;authorities converter both the
 * single-issuer and the multi-issuer decoder paths use. Proves the new
 * issuer-derived {@code DOMAIN_<x>} authority is emitted correctly AND that the
 * existing authority set (ROLE_USER floor, ROLE_&lt;UPPER&gt;, permissions,
 * legacy isAdmin) is unchanged.
 *
 * <ul>
 *   <li>USER-SITUATIONAL — a single token's full authority set per claim shape.</li>
 *   <li>CROSS-USER — the issuer (NOT a user-settable claim) decides DOMAIN_;
 *       a forged {@code owner}/{@code org} claim cannot move the domain.</li>
 * </ul>
 */
class CasdoorAuthoritiesTest {

    private static Jwt jwt(String issuer, Map<String, Object> claims) {
        return Jwt.withTokenValue("test")
            .header("alg", "none")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(60))
            .subject("u1")
            .issuer(issuer)
            .claims(c -> c.putAll(claims))
            .build();
    }

    private static List<String> names(List<GrantedAuthority> a) {
        return a.stream().map(GrantedAuthority::getAuthority).toList();
    }

    // ── USER-SITUATIONAL ──────────────────────────────────────────────────────

    @Test
    void singleIssuer_emitsRoleUserFloor_rolesUpper_andDomainDefault() {
        DomainRegistry reg = new DomainRegistry("http://casdoor:8000", "", "");
        var auth = CasdoorAuthorities.authorities(
                jwt("http://casdoor:8000", Map.of("roles", List.of("admin", "player"))), reg);
        assertThat(names(auth)).containsExactlyInAnyOrder(
                "ROLE_USER", "ROLE_ADMIN", "ROLE_PLAYER", "DOMAIN_default");
    }

    @Test
    void permissionsVerbatim_andLegacyIsAdmin_stillWork_plusDomain() {
        DomainRegistry reg = new DomainRegistry("http://casdoor:8000", "", "");
        var auth = CasdoorAuthorities.authorities(
                jwt("http://casdoor:8000", Map.of(
                        "permissions", List.of("read:reports", "write:reports"),
                        "isAdmin", true)), reg);
        assertThat(names(auth)).containsExactlyInAnyOrder(
                "ROLE_USER", "read:reports", "write:reports", "ROLE_ADMIN", "DOMAIN_default");
    }

    @Test
    void noConfig_anyIssuer_stillDomainDefault() {
        DomainRegistry reg = new DomainRegistry("", "", "");
        var auth = CasdoorAuthorities.authorities(jwt("http://whatever:8000", Map.of()), reg);
        assertThat(names(auth)).contains("ROLE_USER", "DOMAIN_default");
    }

    @Test
    void domainAuthority_isNonRole_cannotSatisfyHasRole() {
        // DOMAIN_<x> must never carry the ROLE_ prefix (so route-access / hasRole
        // can never match it as a role).
        DomainRegistry reg = new DomainRegistry("https://id.brandx.tld",
                "https://id.brandx.tld=brandx", "");
        var auth = CasdoorAuthorities.authorities(jwt("https://id.brandx.tld", Map.of()), reg);
        assertThat(names(auth)).contains("DOMAIN_brandx");
        assertThat(names(auth)).noneMatch(s -> s.startsWith("ROLE_BRANDX"));
        assertThat(names(auth)).noneMatch(s -> s.startsWith("ROLE_DOMAIN"));
    }

    // ── CROSS-USER — issuer is the ONLY domain source ─────────────────────────

    @Test
    void multiBrand_domainFromIssuer_perBrand() {
        DomainRegistry reg = new DomainRegistry("https://id.brandx.tld",
                "https://id.brandx.tld=brandx,https://id.brandy.tld=brandy", "");
        assertThat(names(CasdoorAuthorities.authorities(jwt("https://id.brandx.tld", Map.of()), reg)))
                .contains("DOMAIN_brandx").doesNotContain("DOMAIN_brandy");
        assertThat(names(CasdoorAuthorities.authorities(jwt("https://id.brandy.tld", Map.of()), reg)))
                .contains("DOMAIN_brandy").doesNotContain("DOMAIN_brandx");
    }

    @Test
    void forgedUserSettableClaim_cannotMoveTheDomain() {
        // A user controlling owner/org/aud cannot escape its issuer's domain: the
        // converter reads ONLY jwt.getIssuer(), never these claims.
        DomainRegistry reg = new DomainRegistry("https://id.brandx.tld",
                "https://id.brandx.tld=brandx,https://id.brandy.tld=brandy", "");
        Jwt forged = jwt("https://id.brandx.tld", Map.of(
                "owner", "brandy", "org", "brandy", "aud", "brandy", "domain", "brandy"));
        assertThat(names(CasdoorAuthorities.authorities(forged, reg)))
                .contains("DOMAIN_brandx").doesNotContain("DOMAIN_brandy");
    }

    @Test
    void unknownIssuer_defensivelyMapsToDefault_neverDomainNull() {
        // The decoder rejects an untrusted iss before conversion, but if a null
        // ever reached here the converter must emit DOMAIN_default, not DOMAIN_null.
        DomainRegistry reg = new DomainRegistry("https://id.brandx.tld",
                "https://id.brandx.tld=brandx", "");
        var auth = CasdoorAuthorities.authorities(jwt("https://evil.tld", Map.of()), reg);
        assertThat(names(auth)).contains("DOMAIN_default");
        assertThat(names(auth)).doesNotContain("DOMAIN_null");
    }

    // ── AUTHORITY-INJECTION DEFENSE — reserved-prefix guard ───────────────────

    @Test
    void injectedDomainPermission_isDropped_issuerDomainWins() {
        // ESCALATION REGRESSION: a brand-X token (validated iss=brandx) carrying
        // permissions:["DOMAIN_brandy"] must NOT gain a forged DOMAIN_brandy. The
        // reserved-prefix guard drops the verbatim entry; the ONLY DOMAIN_ left is
        // the genuine issuer-derived DOMAIN_brandx.
        DomainRegistry reg = new DomainRegistry("https://id.brandx.tld",
                "https://id.brandx.tld=brandx,https://id.brandy.tld=brandy", "");
        var auth = CasdoorAuthorities.authorities(
                jwt("https://id.brandx.tld", Map.of(
                        "roles", List.of("admin"),
                        "permissions", List.of("DOMAIN_brandy"))), reg);
        assertThat(names(auth)).contains("DOMAIN_brandx");
        assertThat(names(auth)).doesNotContain("DOMAIN_brandy");
        // Exactly one DOMAIN_ authority survives (the issuer's), so the hardened
        // Roles.domainOf(authorities) resolves the genuine tenant (not null).
        assertThat(names(auth)).filteredOn(s -> s.startsWith("DOMAIN_")).hasSize(1);
    }

    @Test
    void injectedRoleSuperadminPermission_isDropped() {
        // ESCALATION REGRESSION: permissions:["ROLE_SUPERADMIN"] must NOT forge the
        // cross-domain super-role. The reserved-prefix guard drops it; ROLE_ comes
        // ONLY from the roles claim / legacy isAdmin.
        DomainRegistry reg = new DomainRegistry("https://id.brandx.tld",
                "https://id.brandx.tld=brandx", "");
        var auth = CasdoorAuthorities.authorities(
                jwt("https://id.brandx.tld", Map.of(
                        "permissions", List.of("ROLE_SUPERADMIN", "ROLE_ADMIN"))), reg);
        assertThat(names(auth)).doesNotContain("ROLE_SUPERADMIN");
        // The verbatim ROLE_ADMIN permission is ALSO dropped (ROLE_ is reserved);
        // a genuine admin must come from the roles claim or legacy isAdmin.
        assertThat(names(auth)).containsExactlyInAnyOrder("ROLE_USER", "DOMAIN_brandx");
    }

    @Test
    void caseAndWhitespaceVariants_ofReservedPrefix_alsoDropped() {
        // The guard trims + upper-cases before the prefix check, so " role_x ",
        // "domain_y", mixed-case spellings are all dropped — no bypass via casing.
        DomainRegistry reg = new DomainRegistry("https://id.brandx.tld",
                "https://id.brandx.tld=brandx", "");
        var auth = CasdoorAuthorities.authorities(
                jwt("https://id.brandx.tld", Map.of(
                        "permissions", List.of("  role_superadmin ", "Domain_brandy",
                                "RoLe_admin", "read:reports"))), reg);
        // Only the genuine non-reserved permission survives.
        assertThat(names(auth)).contains("read:reports");
        assertThat(names(auth)).noneMatch(s -> s.toUpperCase().contains("SUPERADMIN"));
        assertThat(names(auth)).doesNotContain("DOMAIN_brandy");
        assertThat(names(auth)).filteredOn(s -> s.startsWith("DOMAIN_")).hasSize(1);
    }

    // ── D8 MFA marker derivation — MFA_SATISFIED ──────────────────────────────
    // Emitted ONLY from the validated `mfa_satisfied_at` claim, behind
    // app.mfa.enabled, NON-role, never from roles/permissions; an explicit `now`
    // makes the freshness window deterministic.

    private static final long WINDOW = 600_000L;   // 10 min
    private static final long NOW = 1_750_000_000_000L;

    private static Jwt mfaJwt(String issuer, String satisfiedAt) {
        return jwt(issuer, java.util.Map.of("mfa_satisfied_at", satisfiedAt));
    }

    @Test
    void mfaEnabled_freshStamp_emitsMfaSatisfiedMarker_nonRole() {
        DomainRegistry reg = new DomainRegistry("http://casdoor:8000", "", "");
        var on = new CasdoorAuthorities.MfaConfig(true, WINDOW);
        var auth = CasdoorAuthorities.authorities(
                mfaJwt("http://casdoor:8000", Long.toString(NOW - 60_000L)), reg, on, NOW);
        assertThat(names(auth)).contains("MFA_SATISFIED");
        // It is a NON-role authority — no ROLE_ prefix, so it can never satisfy a
        // hasRole()/route-access role check by accident.
        assertThat(names(auth)).doesNotContain("ROLE_MFA_SATISFIED");
    }

    @Test
    void mfaEnabled_staleOrFutureStamp_noMarker() {
        DomainRegistry reg = new DomainRegistry("http://casdoor:8000", "", "");
        var on = new CasdoorAuthorities.MfaConfig(true, WINDOW);
        // Stale (past the window).
        assertThat(names(CasdoorAuthorities.authorities(
                mfaJwt("http://casdoor:8000", Long.toString(NOW - WINDOW - 1)), reg, on, NOW)))
                .doesNotContain("MFA_SATISFIED");
        // Future (forged-future / skew) — rejected.
        assertThat(names(CasdoorAuthorities.authorities(
                mfaJwt("http://casdoor:8000", Long.toString(NOW + 60_000L)), reg, on, NOW)))
                .doesNotContain("MFA_SATISFIED");
    }

    @Test
    void mfaDisabled_darkDefault_neverEmitsMarker_evenWithFreshStamp() {
        // app.mfa.enabled=false (the dark default) => byte-identical legacy authority
        // set; the marker is NEVER produced even with a perfectly fresh stamp.
        DomainRegistry reg = new DomainRegistry("http://casdoor:8000", "", "");
        var auth = CasdoorAuthorities.authorities(
                mfaJwt("http://casdoor:8000", Long.toString(NOW)), reg,
                CasdoorAuthorities.MfaConfig.DISABLED, NOW);
        assertThat(names(auth)).doesNotContain("MFA_SATISFIED");
        // And the convenience overload (legacy, no MfaConfig) is also dark.
        assertThat(names(CasdoorAuthorities.authorities(
                mfaJwt("http://casdoor:8000", Long.toString(NOW)), reg)))
                .doesNotContain("MFA_SATISFIED");
    }

    @Test
    void forgedMfaSatisfiedPermission_isDropped_evenWhenMfaEnabled() {
        // A forged permissions:["MFA_SATISFIED"] must NEVER inject the marker — the
        // reserved-prefix guard drops it; the marker comes ONLY from the validated
        // claim. Here there is NO valid mfa_satisfied_at claim, so the only way
        // MFA_SATISFIED could appear is via the forged permission (it must not).
        DomainRegistry reg = new DomainRegistry("http://casdoor:8000", "", "");
        var on = new CasdoorAuthorities.MfaConfig(true, WINDOW);
        var auth = CasdoorAuthorities.authorities(
                jwt("http://casdoor:8000", java.util.Map.of(
                        "permissions", List.of("MFA_SATISFIED", "mfa_satisfied", " MFA_SATISFIED "))),
                reg, on, NOW);
        assertThat(names(auth)).doesNotContain("MFA_SATISFIED");
        assertThat(names(auth)).noneMatch(s -> s.toUpperCase().contains("MFA_SATISFIED"));
    }

    @Test
    void forgedMfaSatisfiedPermission_doesNotSurvive_butValidClaimDoes() {
        // Both at once: a forged permission AND a genuine fresh claim. Exactly ONE
        // MFA_SATISFIED authority survives — the converter's, from the claim; the
        // permission entry is dropped (not double-added, not the source).
        DomainRegistry reg = new DomainRegistry("http://casdoor:8000", "", "");
        var on = new CasdoorAuthorities.MfaConfig(true, WINDOW);
        var auth = CasdoorAuthorities.authorities(
                jwt("http://casdoor:8000", java.util.Map.of(
                        "mfa_satisfied_at", Long.toString(NOW),
                        "permissions", List.of("MFA_SATISFIED"))),
                reg, on, NOW);
        assertThat(names(auth)).filteredOn(s -> s.equals("MFA_SATISFIED")).hasSize(1);
    }

    @Test
    void rolesClaim_namedLikeDomain_cannotInjectTenant() {
        // A roles entry "DOMAIN_brandy" gains the ROLE_ prefix -> "ROLE_DOMAIN_BRANDY",
        // an inert non-tenant authority; it can never become a DOMAIN_ scope.
        DomainRegistry reg = new DomainRegistry("https://id.brandx.tld",
                "https://id.brandx.tld=brandx,https://id.brandy.tld=brandy", "");
        var auth = CasdoorAuthorities.authorities(
                jwt("https://id.brandx.tld", Map.of(
                        "roles", List.of("DOMAIN_brandy"))), reg);
        assertThat(names(auth)).contains("ROLE_DOMAIN_BRANDY", "DOMAIN_brandx");
        assertThat(names(auth)).doesNotContain("DOMAIN_brandy");
        assertThat(names(auth)).filteredOn(s -> s.startsWith("DOMAIN_")).hasSize(1);
    }

    // ── ROLE_-prefixed Casdoor seed shape (the hugmesh.systems convention) ──────

    @Test
    void rolesClaim_alreadyRolePrefixed_doesNotDoublePrefix() {
        // The hugmesh.systems Casdoor seed names roles ROLE_ADMIN/ROLE_MOD (the name
        // doubles as the cross-service group id sync jobs look up). The converter must
        // canonicalize these to ROLE_ADMIN/ROLE_MOD — NOT ROLE_ROLE_ADMIN, which would
        // fail every hasRole()/route-access check (regression for the double-prefix bug).
        DomainRegistry reg = new DomainRegistry("http://casdoor:8000", "", "");
        var auth = CasdoorAuthorities.authorities(
                jwt("http://casdoor:8000", Map.of(
                        "roles", List.of("ROLE_ADMIN", "ROLE_MOD"))), reg);
        assertThat(names(auth)).containsExactlyInAnyOrder(
                "ROLE_USER", "ROLE_ADMIN", "ROLE_MOD", "DOMAIN_default");
        assertThat(names(auth)).doesNotContain("ROLE_ROLE_ADMIN", "ROLE_ROLE_MOD");
    }

    @Test
    void rolesClaim_mixedBareAndPrefixed_bothCanonicalizeIdentically() {
        // Bare (games) and ROLE_-prefixed (systems) names collapse to the same authority,
        // so a single converter serves both Casdoor conventions.
        DomainRegistry reg = new DomainRegistry("http://casdoor:8000", "", "");
        var auth = CasdoorAuthorities.authorities(
                jwt("http://casdoor:8000", Map.of(
                        "roles", List.of("admin", "ROLE_SUPERADMIN", "role_mod"))), reg);
        assertThat(names(auth)).containsExactlyInAnyOrder(
                "ROLE_USER", "ROLE_ADMIN", "ROLE_SUPERADMIN", "ROLE_MOD", "DOMAIN_default");
    }
}
