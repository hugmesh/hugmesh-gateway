package net.hugmesh.gateway.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Roles.fromJwt + {has, isAdmin, isGameMaster} contract. Same shapes
 * the Casdoor token template can emit ({@code roles} as list-of-strings
 * OR list-of-objects) plus the legacy {@code isAdmin} boolean.
 */
class RolesTest {

    private static Jwt jwtWith(Map<String, Object> claims) {
        return Jwt.withTokenValue("test")
            .header("alg", "none")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(60))
            .subject("user-id-123")
            .claims(c -> c.putAll(claims))
            .build();
    }

    @Test
    void fromJwt_listOfStrings() {
        Jwt jwt = jwtWith(Map.of("roles", List.of("admin", "player")));
        assertThat(Roles.fromJwt(jwt)).containsExactlyInAnyOrder("ADMIN", "PLAYER");
    }

    @Test
    void fromJwt_listOfObjects_default_casdoor_shape() {
        Jwt jwt = jwtWith(Map.of("roles", List.of(
                Map.of("name", "admin", "displayName", "Admin"),
                Map.of("name", "game-master"))));
        assertThat(Roles.fromJwt(jwt))
            .containsExactlyInAnyOrder("ADMIN", "GAME-MASTER");
    }

    @Test
    void fromJwt_dropsBlankEntries() {
        Jwt jwt = jwtWith(Map.of("roles", List.of(
                Map.of("name", ""),
                Map.of("displayName", "no name field"),
                "valid")));
        assertThat(Roles.fromJwt(jwt)).containsExactly("VALID");
    }

    @Test
    void has_caseInsensitive() {
        Jwt jwt = jwtWith(Map.of("roles", List.of("Admin")));
        assertThat(Roles.has(jwt, "admin")).isTrue();
        assertThat(Roles.has(jwt, "ADMIN")).isTrue();
        assertThat(Roles.has(jwt, "player")).isFalse();
    }

    @Test
    void isAdmin_legacy_boolean_only() {
        Jwt jwt = jwtWith(Map.of("isAdmin", true));
        assertThat(Roles.isAdmin(jwt)).isTrue();
    }

    @Test
    void isAdmin_role_only() {
        Jwt jwt = jwtWith(Map.of("roles", List.of("admin")));
        assertThat(Roles.isAdmin(jwt)).isTrue();
    }

    @Test
    void fromJwt_stripsLeadingRolePrefix_systemsSeedShape() {
        // hugmesh.net Casdoor names roles ROLE_ADMIN/ROLE_MOD; fromJwt must
        // canonicalize to the bare token so has()/isAdmin()/route-access match, instead
        // of the raw "ROLE_ADMIN" that never equals the compared "ADMIN".
        Jwt jwt = jwtWith(Map.of("roles", List.of("ROLE_ADMIN", "ROLE_MOD", "role_superadmin")));
        assertThat(Roles.fromJwt(jwt)).containsExactlyInAnyOrder("ADMIN", "MOD", "SUPERADMIN");
    }

    @Test
    void rolePredicates_workForRolePrefixedNames() {
        Jwt admin = jwtWith(Map.of("roles", List.of("ROLE_ADMIN")));
        assertThat(Roles.isAdmin(admin)).isTrue();
        assertThat(Roles.has(admin, "admin")).isTrue();
        Jwt superadmin = jwtWith(Map.of("roles", List.of("ROLE_SUPERADMIN")));
        assertThat(Roles.isSuperadmin(superadmin)).isTrue();
    }

    @Test
    void canonicalRoleName_stripsOneLeadingRolePrefix_caseInsensitive() {
        assertThat(Roles.canonicalRoleName("ROLE_ADMIN")).isEqualTo("ADMIN");
        assertThat(Roles.canonicalRoleName("role_mod")).isEqualTo("MOD");
        assertThat(Roles.canonicalRoleName("admin")).isEqualTo("ADMIN");
        assertThat(Roles.canonicalRoleName("  ROLE_Superadmin ")).isEqualTo("SUPERADMIN");
        assertThat(Roles.canonicalRoleName("ROLE_")).isEmpty();   // prefix-only -> skipped by callers
        assertThat(Roles.canonicalRoleName(null)).isEmpty();
    }

    @Test
    void isGameMaster_either_hyphen_or_underscore() {
        assertThat(Roles.isGameMaster(jwtWith(Map.of("roles", List.of("game-master"))))).isTrue();
        assertThat(Roles.isGameMaster(jwtWith(Map.of("roles", List.of("game_master"))))).isTrue();
        assertThat(Roles.isGameMaster(jwtWith(Map.of("roles", List.of("admin"))))).isFalse();
    }

    @Test
    void usernameOf_pullsNameClaim() {
        Jwt jwt = jwtWith(Map.of("name", "alice"));
        assertThat(Roles.usernameOf(jwt)).isEqualTo("alice");
    }

    @Test
    void casdoorIdOf_subjectFirst_idFallback() {
        Jwt jwt = jwtWith(Map.of("id", "fallback-id"));
        assertThat(Roles.casdoorIdOf(jwt)).isEqualTo("user-id-123"); // subject wins
        Jwt noSub = Jwt.withTokenValue("t").header("alg", "none")
            .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60))
            .subject(" ") // blank subject — fall through to claim
            .claim("id", "fallback-id").build();
        // Jwt.subject() returns the literal value passed; the helper
        // treats blank as missing.
        assertThat(Roles.casdoorIdOf(noSub)).isEqualTo("fallback-id");
    }

    // ── NEW super-role / capability helpers (USER-SITUATIONAL) ────────────────

    private static Jwt jwtWithIssuer(String issuer, Map<String, Object> claims) {
        return Jwt.withTokenValue("test")
            .header("alg", "none")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(60))
            .subject("user-id-123")
            .issuer(issuer)
            .claims(c -> c.putAll(claims))
            .build();
    }

    @Test
    void isSuperadmin_matchesEitherSpelling_andOnlySuperadmin() {
        assertThat(Roles.isSuperadmin(jwtWith(Map.of("roles", List.of("superadmin"))))).isTrue();
        assertThat(Roles.isSuperadmin(jwtWith(Map.of("roles", List.of("super-admin"))))).isTrue();
        assertThat(Roles.isSuperadmin(jwtWith(Map.of("roles", List.of("super_admin"))))).isTrue();
        // a plain admin is NOT a superadmin (the cross-domain bypass must not leak)
        assertThat(Roles.isSuperadmin(jwtWith(Map.of("roles", List.of("admin"))))).isFalse();
        assertThat(Roles.isSuperadmin(jwtWith(Map.of("isAdmin", true)))).isFalse();
    }

    @Test
    void isSuperadmin_false_whenSuperadminIsOnlyAnInjectedPermission() {
        // AUTHORITY-INJECTION REGRESSION: superadmin is derived from the ROLES
        // claim, never from `permissions`. A token whose only "superadmin" signal
        // is a forged permissions entry is NOT treated as superadmin, so it can
        // never claim the cross-domain bypass. (The converter additionally drops
        // the reserved-prefix permission entirely — see CasdoorAuthoritiesTest.)
        Jwt injected = jwtWith(Map.of(
                "roles", List.of("user"),
                "permissions", List.of("ROLE_SUPERADMIN", "SUPERADMIN")));
        assertThat(Roles.isSuperadmin(injected)).isFalse();
    }

    @Test
    void isImageBuilder_matchesEitherSpelling_notAdminDefault() {
        assertThat(Roles.isImageBuilder(jwtWith(Map.of("roles", List.of("image_builder"))))).isTrue();
        assertThat(Roles.isImageBuilder(jwtWith(Map.of("roles", List.of("image-builder"))))).isTrue();
        // image-builder is a GRANTED capability — a plain admin does NOT hold it.
        assertThat(Roles.isImageBuilder(jwtWith(Map.of("roles", List.of("admin"))))).isFalse();
        assertThat(Roles.isImageBuilder(jwtWith(Map.of("isAdmin", true)))).isFalse();
    }

    @Test
    void domainOf_jwt_viaRegistry_singleIssuerIsDefault() {
        DomainRegistry reg = new DomainRegistry("http://casdoor:8000", "", "");
        Jwt jwt = jwtWithIssuer("http://casdoor:8000", Map.of("roles", List.of("admin")));
        assertThat(Roles.domainOf(jwt, reg)).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
        // defensive null inputs
        assertThat(Roles.domainOf((Jwt) null, reg)).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
        assertThat(Roles.domainOf(jwt, null)).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
    }

    @Test
    void domainOf_jwt_viaRegistry_multiBrand_perIssuer_andFailClosed() {
        DomainRegistry reg = new DomainRegistry("https://id.brandx.tld",
                "https://id.brandx.tld=brandx,https://id.brandy.tld=brandy", "");
        assertThat(Roles.domainOf(jwtWithIssuer("https://id.brandx.tld", Map.of()), reg))
            .isEqualTo("brandx");
        assertThat(Roles.domainOf(jwtWithIssuer("https://id.brandy.tld", Map.of()), reg))
            .isEqualTo("brandy");
        // untrusted issuer -> null (caller fails closed)
        assertThat(Roles.domainOf(jwtWithIssuer("https://evil.tld", Map.of()), reg)).isNull();
    }

    @Test
    void domainOf_authorities_exactlyOneDomain_isReturned() {
        // The canonical converter stamps EXACTLY ONE DOMAIN_ authority; that is
        // the only well-formed shape, and it reads back its tenant.
        assertThat(Roles.domainOf(List.of(
                new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("ROLE_ADMIN"),
                new SimpleGrantedAuthority("DOMAIN_brandx"))))
            .isEqualTo("brandx");
    }

    @Test
    void domainOf_authorities_failsClosed_onZeroOrMultipleDomain() {
        // FAIL-CLOSED hardening (authority-injection defense). The overload refuses
        // to be a spoofable side channel:
        //  - ZERO DOMAIN_ (hand-built / pre-converter token) -> null (deny), NOT
        //    a silent "default".
        assertThat(Roles.domainOf(List.of(
                new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("ROLE_ADMIN"))))
            .isNull();
        //  - MORE THAN ONE DOMAIN_ (INJECTION signature: a forged DOMAIN_brandy
        //    alongside the genuine issuer DOMAIN_brandx) -> null (deny); never the
        //    first one wins.
        assertThat(Roles.domainOf(List.of(
                new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("DOMAIN_brandy"),   // injected first
                new SimpleGrantedAuthority("DOMAIN_brandx")))) // genuine issuer
            .isNull();
        // null input -> null (deny).
        assertThat(Roles.domainOf((java.util.Collection<org.springframework.security.core.GrantedAuthority>) null))
            .isNull();
    }

    // ── D8 MFA freshness — Roles.isMfaSatisfied(jwt, now, window) ─────────────
    // The claim is the BFF-written flat top-level snake_case `mfa_satisfied_at`,
    // a numeric epoch-MILLIS carried as a STRING (Casdoor User.properties is a Go
    // map[string]string — a JSON number is rejected at write time). Window default
    // is 10m (600000ms); `now` is injected for deterministic freshness assertions.

    private static final long WINDOW = 600_000L;   // 10 min

    private static Jwt mfaJwt(Object satisfiedAt) {
        return jwtWith(Map.of(Roles.MFA_SATISFIED_AT_CLAIM, satisfiedAt));
    }

    @Test
    void isMfaSatisfied_freshStampString_withinWindow_true() {
        long now = 1_750_000_000_000L;
        // 1 minute ago — well inside the 10m window. STRING value (the Casdoor shape).
        assertThat(Roles.isMfaSatisfied(mfaJwt(Long.toString(now - 60_000L)), now, WINDOW)).isTrue();
        // Exactly at the boundary (age == window) is still fresh.
        assertThat(Roles.isMfaSatisfied(mfaJwt(Long.toString(now - WINDOW)), now, WINDOW)).isTrue();
        // age == 0 (stamped right now) is fresh.
        assertThat(Roles.isMfaSatisfied(mfaJwt(Long.toString(now)), now, WINDOW)).isTrue();
    }

    @Test
    void isMfaSatisfied_staleStamp_pastWindow_false() {
        long now = 1_750_000_000_000L;
        // One millisecond past the window — STALE, rejected.
        assertThat(Roles.isMfaSatisfied(mfaJwt(Long.toString(now - WINDOW - 1)), now, WINDOW)).isFalse();
        // Way old.
        assertThat(Roles.isMfaSatisfied(mfaJwt(Long.toString(now - 3_600_000L)), now, WINDOW)).isFalse();
    }

    @Test
    void isMfaSatisfied_futureStamp_rejected() {
        long now = 1_750_000_000_000L;
        // A timestamp in the FUTURE (now - ts < 0) must be REJECTED — a far-future
        // stamp would otherwise never go stale (clock-skew / forged-future defense).
        assertThat(Roles.isMfaSatisfied(mfaJwt(Long.toString(now + 1)), now, WINDOW)).isFalse();
        assertThat(Roles.isMfaSatisfied(mfaJwt(Long.toString(now + 3_600_000L)), now, WINDOW)).isFalse();
    }

    @Test
    void isMfaSatisfied_missingOrMalformed_failsClosed() {
        long now = 1_750_000_000_000L;
        // No claim at all.
        assertThat(Roles.isMfaSatisfied(jwtWith(Map.of("roles", List.of("admin"))), now, WINDOW)).isFalse();
        // Blank / non-numeric / non-positive string.
        assertThat(Roles.isMfaSatisfied(mfaJwt("   "), now, WINDOW)).isFalse();
        assertThat(Roles.isMfaSatisfied(mfaJwt("not-a-number"), now, WINDOW)).isFalse();
        assertThat(Roles.isMfaSatisfied(mfaJwt("0"), now, WINDOW)).isFalse();
        assertThat(Roles.isMfaSatisfied(mfaJwt("-1"), now, WINDOW)).isFalse();
        // null jwt.
        assertThat(Roles.isMfaSatisfied(null, now, WINDOW)).isFalse();
    }

    @Test
    void isMfaSatisfied_numericClaim_alsoTolerated() {
        long now = 1_750_000_000_000L;
        // Defensive: a JSON Number (should not happen with Casdoor, but parsing it
        // costs nothing) within the window is accepted.
        assertThat(Roles.isMfaSatisfied(mfaJwt(now - 60_000L), now, WINDOW)).isTrue();
        assertThat(Roles.isMfaSatisfied(mfaJwt(now + 1L), now, WINDOW)).isFalse();   // future number rejected
    }
}
