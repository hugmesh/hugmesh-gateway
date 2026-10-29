package net.hugmesh.gateway.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * JWT role extraction utility — aligned with the hugmesh.games BFF's
 * {@code games.hugmesh.bff.security.Roles}.
 *
 * <p>Casdoor's token template can emit the {@code roles} claim in two
 * shapes:
 *
 * <ol>
 *   <li>List of strings:  {@code "roles": ["admin", "player"]}</li>
 *   <li>List of role objects (default):
 *       {@code "roles": [{"name": "admin", ...}, {"name": "player", ...}]}</li>
 * </ol>
 *
 * <p>Both shapes are handled. Empty / blank entries are skipped silently
 * so a partially-populated role object doesn't introduce a phantom
 * {@code ROLE_} authority.
 *
 * <p>Static helpers below answer the common "does this principal have
 * role X" question from controller code without copying the claim-walk.
 */
public final class Roles {

    private Roles() {}

    /**
     * Non-role marker authority asserting THIS session completed a second factor
     * recently (D8 MFA floor). NOT a Casdoor role and NOT a permission — it is
     * derived ONLY by {@link #isMfaSatisfied(Jwt, long, long)} from the
     * BFF-written, freshness-validated {@code mfa_satisfied_at} JWT-Custom claim,
     * and is added to the converter's RESERVED prefixes so a forged
     * {@code permissions:["MFA_SATISFIED"]} can never inject it. See
     * {@code CasdoorAuthorities}.
     */
    public static final String MFA_SATISFIED = "MFA_SATISFIED";

    /**
     * Flat top-level JWT-Custom claim the admin-bff stamps on a successful
     * BFF-driven MFA challenge: a numeric epoch-MILLIS timestamp carried as a
     * STRING. Casdoor stores {@code User.properties} as a Go {@code map[string]string}
     * (a JSON number is rejected at write time), so the value persists and emits
     * VERBATIM as a string (e.g. {@code "1750233600000"}) — top-level snake_case,
     * NOT camel-cased (Casdoor's SnakeToCamel does not rewrite the
     * {@code Properties.<key>} branch; empirically pinned, workflow wfza2mi09).
     */
    public static final String MFA_SATISFIED_AT_CLAIM = "mfa_satisfied_at";

    /**
     * True iff the JWT carries a FRESH MFA stamp: the BFF-written
     * {@link #MFA_SATISFIED_AT_CLAIM} epoch-millis string parses to a {@code long}
     * {@code ts} satisfying {@code 0 <= now - ts <= freshnessWindowMillis}. A
     * timestamp in the FUTURE ({@code now - ts < 0}) is REJECTED (clock-skew /
     * forged-future defense — a far-future stamp would otherwise never go stale),
     * a STALE one ({@code now - ts > window}) is rejected, and any
     * missing / blank / non-numeric / non-positive value is rejected. Fail-closed
     * throughout — this NEVER throws, it returns {@code false} on every malformed
     * input.
     *
     * <p>The claim is the SOLE source of {@code MFA_SATISFIED}; it is never derived
     * from roles/permissions. {@code now} is passed in (caller supplies
     * {@link System#currentTimeMillis()} in production) so the freshness window is
     * deterministically unit-testable.
     */
    public static boolean isMfaSatisfied(Jwt jwt, long now, long freshnessWindowMillis) {
        if (jwt == null) return false;
        Long ts = mfaSatisfiedAtMillis(jwt);
        if (ts == null) return false;
        long age = now - ts;
        if (age < 0) return false;                    // future timestamp -> reject
        return age <= freshnessWindowMillis;          // within the freshness window
    }

    /**
     * Parse the {@link #MFA_SATISFIED_AT_CLAIM} claim to epoch-millis, or
     * {@code null} when absent / blank / non-numeric / non-positive. Tolerant of
     * the claim arriving as a String (the Casdoor JWT-Custom shape) OR a JSON
     * Number (defensive — should not happen, but parsing it costs nothing). Never
     * throws.
     */
    private static Long mfaSatisfiedAtMillis(Jwt jwt) {
        Object raw = jwt.getClaim(MFA_SATISFIED_AT_CLAIM);
        if (raw == null) return null;
        long ts;
        if (raw instanceof Number n) {
            ts = n.longValue();
        } else {
            String s = raw.toString().trim();
            if (s.isEmpty()) return null;
            try {
                ts = Long.parseLong(s);
            } catch (NumberFormatException e) {
                return null;                          // non-numeric -> fail-closed
            }
        }
        return ts > 0 ? ts : null;                    // non-positive -> fail-closed
    }

    /**
     * Returns every role name carried by the JWT, upper-cased and
     * trimmed. Empty list if the claim is missing.
     */
    public static List<String> fromJwt(Jwt jwt) {
        var out = new ArrayList<String>();
        if (jwt == null) return out;
        Object claim = jwt.getClaim("roles");
        if (claim instanceof Collection<?> list) {
            for (Object item : list) {
                String name = canonicalRoleName(roleNameOf(item));
                if (!name.isBlank()) out.add(name);
            }
        }
        return out;
    }

    /**
     * Canonicalize a raw Casdoor role NAME to the bare, upper-cased role token the
     * gateway compares against (and which {@code CasdoorAuthorities} re-prefixes with
     * the single Spring {@code ROLE_}).
     *
     * <p>Casdoor deployments name roles in two conventions: bare ({@code admin} — the
     * hugmesh.games shape) and {@code ROLE_}-prefixed ({@code ROLE_ADMIN} — the
     * hugmesh.net seed shape, where the role name doubles as the cross-service
     * group id the akkoma/tuwunel/games sync jobs look up by
     * {@code get-role?id=<org>/ROLE_MOD}). Both MUST collapse to the same token, or a
     * {@code ROLE_ADMIN} Casdoor role double-prefixes to the authority
     * {@code ROLE_ROLE_ADMIN} and every {@code hasRole()} / route-access / filter-bypass
     * check misses (only the {@code ROLE_USER} floor survives). We strip ONE leading,
     * case-insensitive {@code ROLE_} so {@code admin} and {@code ROLE_ADMIN} both
     * canonicalize to {@code ADMIN}.
     *
     * <p>SECURITY: this never weakens the converter's reserved-prefix defenses — the
     * result is always re-{@code ROLE_}-prefixed by {@code CasdoorAuthorities}, so a
     * role named {@code DOMAIN_x} still yields the inert {@code ROLE_DOMAIN_X}. Returns
     * {@code ""} for null/blank/prefix-only input so the caller skips it.
     */
    public static String canonicalRoleName(String raw) {
        if (raw == null) return "";
        String s = raw.trim();
        if (s.length() >= 5 && s.regionMatches(true, 0, "ROLE_", 0, 5)) {
            s = s.substring(5).trim();
        }
        return s.toUpperCase();
    }

    /** True iff {@code roleName} (case-insensitive) is present in the
     *  JWT's roles claim. */
    public static boolean has(Jwt jwt, String roleName) {
        if (jwt == null || roleName == null) return false;
        String want = roleName.trim().toUpperCase();
        for (String r : fromJwt(jwt)) if (r.equals(want)) return true;
        return false;
    }

    public static boolean isAdmin(Jwt jwt) {
        if (jwt == null) return false;
        if (Boolean.TRUE.equals(jwt.getClaim("isAdmin"))) return true;
        return has(jwt, "ADMIN");
    }

    /** True iff the principal carries the {@code game-master} role
     *  (hugmesh.net platform admin). Gates infra/health URLs. */
    public static boolean isGameMaster(Jwt jwt) {
        return has(jwt, "GAME-MASTER") || has(jwt, "GAME_MASTER");
    }

    /** True iff the principal carries the network-wide games-access role
     *  {@code ROLE_GAMES} (the hugmesh.net seed spelling) or bare {@code games}
     *  — {@link #has} strips one leading {@code ROLE_} so both match. The
     *  DERIVED composite {@code ROLE_GAMES_ADMIN} canonicalizes to
     *  {@code GAMES_ADMIN} and does NOT match on its own; that is fine, because
     *  the composite is only ever materialized for a principal that already
     *  holds {@code ROLE_GAMES}. Distinct from {@link #isGameMaster}, the
     *  platform-admin role. Gates the {@code game} resource-type floor in
     *  {@code ResourceAccessFilter}. */
    public static boolean isGames(Jwt jwt) {
        return has(jwt, "GAMES");
    }

    /** True iff the principal carries the infra super-role {@code SUPERADMIN}.
     *  The ONLY role exempt from the gateway's per-domain bypass scoping —
     *  SUPERADMIN reaches every surface in every brand (the infra control plane).
     *  Both hyphen and underscore spellings of the Casdoor role name match. */
    public static boolean isSuperadmin(Jwt jwt) {
        return has(jwt, "SUPERADMIN") || has(jwt, "SUPER-ADMIN") || has(jwt, "SUPER_ADMIN");
    }

    /** True iff the principal may build mesh-WORKLOAD images. Granted to trusted
     *  per-domain admins as a separate capability (NOT an admin default);
     *  SUPERADMIN reaches the build surface via the gateway cross-domain bypass.
     *  Both hyphen and underscore spellings match (the converter upper-cases the
     *  raw Casdoor role name without stripping its separator). */
    public static boolean isImageBuilder(Jwt jwt) {
        return has(jwt, "IMAGE-BUILDER") || has(jwt, "IMAGE_BUILDER");
    }

    /** The brand/domain this principal is scoped to, derived from the token
     *  ISSUER (per-brand Casdoor =&gt; distinct {@code iss}) through the SAME
     *  registry the converter uses. Returns {@code "default"} for the
     *  single-issuer fallback so single-issuer clusters keep one domain, and
     *  (defensively) when {@code jwt}/{@code registry} is null. A {@code null}
     *  from the registry (unknown issuer in multi-brand mode) is surfaced as-is
     *  so the caller can fail closed. */
    public static String domainOf(Jwt jwt, DomainRegistry registry) {
        if (jwt == null || registry == null) return DomainRegistry.DEFAULT_DOMAIN;
        return registry.domainOf(jwt.getIssuer() == null ? null : jwt.getIssuer().toString());
    }

    /** Domain carried on the already-converted authorities ({@code DOMAIN_<x>}) —
     *  the form a caller holding only Spring authorities (no registry) can read.
     *
     *  <p>FAIL-CLOSED on an ambiguous authority set: the canonical converter
     *  ({@code CasdoorAuthorities}) stamps EXACTLY ONE issuer-derived
     *  {@code DOMAIN_<x>}, so any other count is anomalous —
     *  <ul>
     *    <li>ZERO {@code DOMAIN_} authorities (a hand-built / pre-converter token)
     *        — we can't prove a tenant, so return {@code null}.</li>
     *    <li>MORE THAN ONE {@code DOMAIN_} authority — an INJECTION signature (e.g.
     *        a forged {@code permissions:["DOMAIN_brandy"]} alongside the genuine
     *        issuer {@code DOMAIN_brandx}); never pick the first, return
     *        {@code null}.</li>
     *  </ul>
     *  Returning {@code null} makes the gateway's {@code domainMatches(null, …)}
     *  treat it as a non-match (deny). Belt-and-suspenders: the converter's
     *  reserved-prefix guard already prevents the injected DOMAIN_ from ever
     *  appearing, and the gateway filter derives the principal domain from the
     *  validated issuer (not this list) — this overload simply refuses to be a
     *  spoofable side channel. Prefer {@link #domainOf(Jwt, DomainRegistry)}
     *  (issuer-keyed) where a {@link Jwt} is in hand. */
    public static String domainOf(Collection<? extends GrantedAuthority> authorities) {
        if (authorities == null) return null;                       // fail-closed
        String found = null;
        for (GrantedAuthority a : authorities) {
            String s = a.getAuthority();
            if (s != null && s.startsWith("DOMAIN_")) {
                if (found != null) return null;                     // >1 DOMAIN_ -> injection, fail-closed
                found = s.substring("DOMAIN_".length());
            }
        }
        return found;                                               // null when ZERO DOMAIN_ -> fail-closed
    }

    // ── authorities-based privileged checks (bff_ session / non-JWT principals) ──
    // A native-login bff_ session is bridged by BffSessionAuthFilter to a
    // UsernamePasswordAuthenticationToken carrying ROLE_<UPPER> (+ MFA_SATISFIED)
    // SimpleGrantedAuthorities — NOT a Jwt. These overloads answer the SAME privileged
    // questions the Jwt overloads answer, off that authority set, so the gateway's
    // route-access privileged bypasses (SUPERADMIN / ADMIN / GAME-MASTER, and the
    // MFA floor) apply to native-login callers exactly as they do to Casdoor JWTs.
    // The authority set is trustworthy here: it is set by the gateway itself from
    // admin-bff's introspect response, never from user-supplied claims.

    /** True iff the authority set carries {@code ROLE_ADMIN}. */
    public static boolean isAdmin(Collection<? extends GrantedAuthority> authorities) {
        return hasRoleAuthority(authorities, "ADMIN");
    }

    /** True iff the authority set carries the {@code game-master} role (either
     *  hyphen or underscore spelling, matching {@link #isGameMaster(Jwt)}). */
    public static boolean isGameMaster(Collection<? extends GrantedAuthority> authorities) {
        return hasRoleAuthority(authorities, "GAME-MASTER") || hasRoleAuthority(authorities, "GAME_MASTER");
    }

    /** True iff the authority set carries the infra super-role {@code SUPERADMIN}
     *  (hyphen/underscore spellings tolerated, matching {@link #isSuperadmin(Jwt)}). */
    public static boolean isSuperadmin(Collection<? extends GrantedAuthority> authorities) {
        return hasRoleAuthority(authorities, "SUPERADMIN")
                || hasRoleAuthority(authorities, "SUPER-ADMIN")
                || hasRoleAuthority(authorities, "SUPER_ADMIN");
    }

    /** True iff the authority set carries the {@code MFA_SATISFIED} marker. Unlike the
     *  Jwt overload (which re-checks a freshness-windowed timestamp claim), the marker's
     *  PRESENCE is authoritative here: the gateway's {@code BffSessionAuthFilter} adds it
     *  ONLY when admin-bff's introspect reports the session's MFA as satisfied, and
     *  admin-bff applies the freshness window server-side before answering. */
    public static boolean isMfaSatisfied(Collection<? extends GrantedAuthority> authorities) {
        if (authorities == null) return false;
        for (GrantedAuthority a : authorities) {
            if ("MFA_SATISFIED".equals(a.getAuthority())) return true;
        }
        return false;
    }

    private static boolean hasRoleAuthority(Collection<? extends GrantedAuthority> authorities, String roleToken) {
        if (authorities == null) return false;
        String target = "ROLE_" + roleToken;
        for (GrantedAuthority a : authorities) {
            if (target.equals(a.getAuthority())) return true;
        }
        return false;
    }

    private static String roleNameOf(Object item) {
        if (item == null) return "";
        if (item instanceof String s) return s.trim();
        if (item instanceof Map<?, ?> m) {
            Object name = m.get("name");
            if (name instanceof String s && !s.isBlank()) return s.trim();
        }
        return "";
    }

    /** Casdoor user id (subject) accessor — the single place we choose
     *  between {@code sub} and {@code id} so a Casdoor schema flip
     *  doesn't ripple through controller code. */
    public static String casdoorIdOf(Jwt jwt) {
        if (jwt == null) return null;
        String sub = jwt.getSubject();
        if (sub != null && !sub.isBlank()) return sub;
        Object id = jwt.getClaim("id");
        return id == null ? null : id.toString();
    }

    /** Lowercase username from the {@code name} claim — used by the
     *  revocation list to key on user-friendly identifiers when the
     *  Casdoor id rotates. */
    public static String usernameOf(Jwt jwt) {
        if (jwt == null) return null;
        Object n = jwt.getClaim("name");
        return n == null ? null : n.toString();
    }

    /** Convert {@code List<GrantedAuthority>} → role-name list (strips
     *  the {@code ROLE_} prefix). Useful for log lines / debug. */
    public static List<String> namesOf(Collection<? extends GrantedAuthority> authorities) {
        var out = new ArrayList<String>();
        if (authorities == null) return out;
        for (GrantedAuthority a : authorities) {
            String s = a.getAuthority();
            if (s == null) continue;
            out.add(s.startsWith("ROLE_") ? s.substring(5) : s);
        }
        return out;
    }
}
