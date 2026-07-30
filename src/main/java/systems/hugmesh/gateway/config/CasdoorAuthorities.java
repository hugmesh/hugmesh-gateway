package systems.hugmesh.gateway.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Flux;
import systems.hugmesh.gateway.security.DomainRegistry;
import systems.hugmesh.gateway.security.Roles;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Single source of truth for the gateway's Casdoor JWT -&gt; Spring authorities
 * mapping, so the single-issuer ({@link SecurityConfig}) and the optional
 * multi-issuer ({@link TenancyResourceServerConfig}) decoder paths emit
 * BYTE-IDENTICAL authorities. Keeping one converter avoids the half-migration
 * pitfall where one path silently drops the {@code DOMAIN_<x>} authority.
 *
 * <p>Three claim sources, in precedence:
 * <ol>
 *   <li>{@code roles} array (strings OR objects with a {@code name} field —
 *       Casdoor's default token shape) -&gt; {@code ROLE_<UPPER>}.</li>
 *   <li>{@code permissions} array -&gt; verbatim (non-prefixed) authorities,
 *       EXCEPT any entry whose value starts with a RESERVED prefix
 *       ({@code ROLE_} / {@code DOMAIN_}) is dropped — those authorities come
 *       ONLY from controlled logic, never from a user-influenced permission
 *       string (authority-injection defense; see {@code RESERVED_PREFIXES}).</li>
 *   <li>{@code isAdmin} boolean (legacy) -&gt; {@code ROLE_ADMIN}.</li>
 * </ol>
 * Every authenticated principal floors to {@code ROLE_USER} and is stamped with
 * exactly one issuer-derived {@code DOMAIN_<x>} authority.
 */
final class CasdoorAuthorities {

    private CasdoorAuthorities() {}

    /**
     * MFA derivation config for the converter (D8 gateway MFA floor). Carried so
     * the single-issuer ({@link SecurityConfig}) and multi-issuer
     * ({@link TenancyResourceServerConfig}) paths derive the {@code MFA_SATISFIED}
     * marker BYTE-IDENTICALLY. {@code enabled} is {@code app.mfa.enabled} (default
     * {@code false} — ships dark: when off, the converter emits the legacy
     * authority set verbatim and {@code MFA_SATISFIED} is NEVER produced).
     * {@code freshnessWindowMillis} is {@code app.mfa.freshness-window} (default
     * 10m).
     *
     * @param enabled               whether the {@code MFA_SATISFIED} marker is derived at all
     * @param freshnessWindowMillis the {@code 0 <= now - ts <= window} freshness window
     */
    record MfaConfig(boolean enabled, long freshnessWindowMillis) {
        /** The dark default — MFA derivation OFF, byte-identical legacy behaviour. */
        static final MfaConfig DISABLED = new MfaConfig(false, 0L);
    }

    /**
     * Authority prefixes RESERVED for the converter's own controlled logic and
     * therefore NEVER allowed to originate from a user-influenced claim string:
     * <ul>
     *   <li>{@code ROLE_} — emitted ONLY from the {@code roles} claim (each role
     *       name upper-cased and prefixed here) and the legacy {@code isAdmin}
     *       boolean. A verbatim {@code permissions} entry must never become a
     *       {@code ROLE_*} authority.</li>
     *   <li>{@code DOMAIN_} — emitted ONLY from the cryptographically-validated
     *       issuer (exactly one, added last). A verbatim {@code permissions}
     *       entry must never forge a {@code DOMAIN_*} tenant scope, and a
     *       {@code roles} entry cannot either (it always gains the {@code ROLE_}
     *       prefix first, so {@code "DOMAIN_x" -> "ROLE_DOMAIN_X"}, which is an
     *       inert non-tenant authority).</li>
     *   <li>{@code MFA_SATISFIED} (D8) — the second-factor marker, emitted ONLY
     *       from the BFF-written, freshness-validated {@code mfa_satisfied_at}
     *       claim (see {@link #authorities}), NEVER from a roles/permissions
     *       entry. A forged {@code permissions:["MFA_SATISFIED"]} must be dropped
     *       so a step-up gate can't be satisfied without an actual recent MFA.
     *       Listed as a full prefix (not just an exact value) so casing /
     *       whitespace variants are caught by the same trim+upper guard.</li>
     * </ul>
     * SECURITY: without this filter a brand-X token carrying
     * {@code permissions:["DOMAIN_brandy"]} or {@code permissions:["ROLE_SUPERADMIN"]}
     * would inject a forged tenant scope / super-role and escalate cross-domain;
     * a {@code permissions:["MFA_SATISFIED"]} would forge a second factor.
     */
    private static final String[] RESERVED_PREFIXES = {"ROLE_", "DOMAIN_", "MFA_SATISFIED"};

    private static boolean isReserved(String authority) {
        String upper = authority.trim().toUpperCase();
        for (String prefix : RESERVED_PREFIXES) {
            if (upper.startsWith(prefix)) return true;
        }
        return false;
    }

    /** Build the converter bound to the given {@link DomainRegistry} (used to
     *  resolve the issuer -&gt; {@code DOMAIN_<x>} authority). MFA derivation OFF —
     *  the legacy byte-identical authority set (no {@code MFA_SATISFIED}). */
    static Converter<Jwt, Flux<GrantedAuthority>> converter(DomainRegistry domainRegistry) {
        return converter(domainRegistry, MfaConfig.DISABLED);
    }

    /** Build the converter bound to the given {@link DomainRegistry} with the D8
     *  {@link MfaConfig}. When {@code mfa.enabled()} is {@code false} (the dark
     *  default) the emitted authorities are byte-identical to the legacy set;
     *  when {@code true} a FRESH BFF-written {@code mfa_satisfied_at} claim adds
     *  the {@code MFA_SATISFIED} marker. Production clock is
     *  {@link System#currentTimeMillis()}. */
    static Converter<Jwt, Flux<GrantedAuthority>> converter(DomainRegistry domainRegistry,
                                                            MfaConfig mfa) {
        return jwt -> Flux.fromIterable(
                authorities(jwt, domainRegistry, mfa, System.currentTimeMillis()));
    }

    /** Compute the authority list for a token (the pure mapping, exposed for
     *  reuse + unit testing). MFA derivation OFF — legacy authority set. */
    static List<GrantedAuthority> authorities(Jwt jwt, DomainRegistry domainRegistry) {
        return authorities(jwt, domainRegistry, MfaConfig.DISABLED, System.currentTimeMillis());
    }

    /** Compute the authority list for a token with the D8 {@link MfaConfig} and an
     *  explicit {@code now} (epoch-millis) so the freshness window is
     *  deterministically unit-testable. */
    static List<GrantedAuthority> authorities(Jwt jwt, DomainRegistry domainRegistry,
                                              MfaConfig mfa, long now) {
        var authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER")); // floor — UNCHANGED

        Object rolesClaim = jwt.getClaim("roles");
        if (rolesClaim instanceof Collection<?> list) {
            for (Object r : list) {
                // Canonicalize FIRST (strip one leading ROLE_ so a Casdoor role named
                // "ROLE_ADMIN" doesn't double-prefix to ROLE_ROLE_ADMIN and miss every
                // hasRole()/route-access check), THEN re-add the single Spring ROLE_.
                // Still always ROLE_-prefixed, so a roles entry can NEVER inject a
                // DOMAIN_ authority: "DOMAIN_x" -> "ROLE_DOMAIN_X" (inert, non-tenant).
                // See RESERVED_PREFIXES + Roles.canonicalRoleName.
                String name = Roles.canonicalRoleName(roleNameOf(r));
                if (!name.isBlank()) {
                    authorities.add(new SimpleGrantedAuthority("ROLE_" + name));
                }
            }
        }

        Object permsClaim = jwt.getClaim("permissions");
        if (permsClaim instanceof Collection<?> list) {
            for (Object p : list) {
                if (p == null) continue;
                String perm = p.toString().trim();
                if (perm.isEmpty()) continue;
                // RESERVED-PREFIX GUARD (authority-injection defense). A verbatim
                // permission string MUST NOT carry the ROLE_ or DOMAIN_ prefix —
                // those authorities come ONLY from the converter's controlled logic
                // (roles-claim -> ROLE_<UPPER>; validated issuer -> DOMAIN_<x>).
                // Skipping such entries stops a brand-X token carrying
                // permissions:["DOMAIN_brandy"] (forged tenant scope) or
                // permissions:["ROLE_SUPERADMIN"] (forged super-role) from
                // escalating cross-domain. See RESERVED_PREFIXES.
                if (isReserved(perm)) continue;
                authorities.add(new SimpleGrantedAuthority(perm));
            }
        }

        if (Boolean.TRUE.equals(jwt.getClaim("isAdmin"))) {
            authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        }

        // MFA_SATISFIED marker (D8 gateway MFA floor) — ships DARK (app.mfa.enabled,
        // default false). Derived ONLY from the BFF-written, freshness-validated
        // `mfa_satisfied_at` JWT-Custom claim (Roles.isMfaSatisfied), NEVER from a
        // roles/permissions entry (those carrying MFA_SATISFIED were already dropped
        // by the reserved-prefix guard above). A NON-role SimpleGrantedAuthority
        // (no ROLE_ prefix) so it can never satisfy a hasRole()/route-access role
        // check by accident — it is a distinct second-factor proof consumed only by
        // the mfa_required route gate + the privileged floor. When the flag is off
        // the marker is never produced => byte-identical legacy authority set.
        if (mfa.enabled() && Roles.isMfaSatisfied(jwt, now, mfa.freshnessWindowMillis())) {
            authorities.add(new SimpleGrantedAuthority(Roles.MFA_SATISFIED));
        }

        // Domain authority — keyed on the cryptographically-validated ISSUER
        // (per-brand Casdoor => distinct iss). NEVER a user-settable claim.
        // DOMAIN_<x> is a NON-role authority (no ROLE_ prefix) so it can never
        // satisfy a hasRole()/route-access role check by accident. A null from
        // the registry (unknown issuer) defensively maps to "default" rather than
        // emitting "DOMAIN_null".
        String issuer = jwt.getIssuer() == null ? null : jwt.getIssuer().toString();
        String domain = domainRegistry.domainOf(issuer);
        if (domain == null) domain = DomainRegistry.DEFAULT_DOMAIN;
        authorities.add(new SimpleGrantedAuthority("DOMAIN_" + domain));

        return authorities;
    }

    private static String roleNameOf(Object item) {
        if (item instanceof String s) return s;
        if (item instanceof Map<?, ?> m) {
            Object name = m.get("name");
            if (name instanceof String s && !s.isBlank()) return s;
        }
        return "";
    }
}
