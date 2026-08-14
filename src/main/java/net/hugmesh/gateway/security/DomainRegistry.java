package net.hugmesh.gateway.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Issuer-URI -&gt; brand/domain map — the single source of truth the converter,
 * the {@code Roles} helpers and the gateway filter all consult to derive the
 * brand a token belongs to.
 *
 * <p><b>Why the issuer.</b> The platform's fork decision (V) is one Casdoor per
 * brand, so the token's cryptographically-validated {@code iss} claim is the
 * trustworthy tenant discriminator. Never key the domain off a user-settable
 * claim ({@code owner}/{@code org}/{@code aud}) — a user could forge cross-tenant
 * scope. The resource server validates {@code iss} against the configured
 * issuer(s) before any authority is emitted, so an issuer reaching this registry
 * is already trusted.
 *
 * <p><b>Single-issuer back-compat.</b> Given only the existing
 * {@code spring.security.oauth2.resourceserver.jwt.issuer-uri} and an empty
 * {@code app.tenancy.issuers}, the registry seeds exactly one entry
 * {@code {thatIssuer -> "default"}}; with NO issuer-uri at all the map stays
 * empty and {@link #domainOf(String)} returns {@code "default"} unconditionally.
 * So a single-issuer cluster emits {@code DOMAIN_default} for every token and
 * nothing else changes.
 *
 * <p><b>Multi-brand fail-closed.</b> When {@code app.tenancy.issuers} is
 * populated, ONLY the listed issuers are trusted; an issuer not in the map yields
 * {@code null} from {@link #domainOf(String)} so callers fail closed (and the
 * multi-issuer decoder, built from {@link #trustedIssuers()}, 401s an unknown
 * {@code iss} before authorities are emitted).
 */
@Component
public class DomainRegistry {

    /** The single-tenant / legacy domain every token maps to when no per-brand
     *  registry is configured. */
    public static final String DEFAULT_DOMAIN = "default";

    private final Map<String, String> issuerToDomain = new LinkedHashMap<>();
    private final Map<String, String> hostToDomain = new LinkedHashMap<>();
    private final String singleIssuer;

    public DomainRegistry(
            @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri:}") String singleIssuer,
            @Value("${app.tenancy.issuers:}") String issuersCsv,
            @Value("${app.tenancy.hosts:}") String hostsCsv) {
        this.singleIssuer = trimSlash(singleIssuer);
        if (issuersCsv != null && !issuersCsv.isBlank()) {
            for (String pair : issuersCsv.split(",")) {
                int eq = pair.indexOf('=');
                if (eq <= 0) continue;
                String iss = trimSlash(pair.substring(0, eq).trim());
                String dom = sanitize(pair.substring(eq + 1).trim());
                if (!iss.isEmpty() && !dom.isEmpty()) issuerToDomain.put(iss, dom);
            }
        }
        // Backward-compat: with NO multi-issuer config, the lone configured
        // issuer maps to DEFAULT_DOMAIN so a single-issuer cluster is unchanged.
        if (issuerToDomain.isEmpty() && !this.singleIssuer.isEmpty()) {
            issuerToDomain.put(this.singleIssuer, DEFAULT_DOMAIN);
        }
        // OPTIONAL host-suffix -> domain map (defense-in-depth for the gateway's
        // Host-vs-DOMAIN check). Empty on single-brand clusters so the Host check
        // is a no-op (every host resolves to DEFAULT_DOMAIN).
        if (hostsCsv != null && !hostsCsv.isBlank()) {
            for (String pair : hostsCsv.split(",")) {
                int eq = pair.indexOf('=');
                if (eq <= 0) continue;
                String host = normalizeHost(pair.substring(0, eq).trim());
                String dom = sanitize(pair.substring(eq + 1).trim());
                if (!host.isEmpty() && !dom.isEmpty()) hostToDomain.put(host, dom);
            }
        }
    }

    /**
     * Domain for an issuer. {@code "default"} when the registry is in
     * single-issuer mode (the lone configured issuer OR no config at all);
     * {@code null} when multi-issuer mode is active and the issuer is NOT trusted
     * (fail-closed — the caller must reject).
     */
    public String domainOf(String issuer) {
        String iss = trimSlash(issuer);
        if (issuerToDomain.isEmpty()) return DEFAULT_DOMAIN;          // no config -> legacy single-tenant
        String d = issuerToDomain.get(iss);
        if (d != null) return d;
        // Multi-brand mode with an unknown issuer: fail closed. The decoder,
        // built from trustedIssuers(), rejects this iss upstream; defensively
        // return null so any in-process caller also fails closed.
        return null;
    }

    /**
     * Domain for a request {@code Host} (defense-in-depth for the gateway's
     * cross-domain bypass scoping). Returns {@code "default"} when no host map is
     * configured (single-tenant: the Host check is a no-op) OR when the host is
     * not mapped — so a single-brand cluster always matches and an unmapped host
     * on a multi-brand cluster falls back to the route-access default-deny rather
     * than silently granting another brand's bypass. Matches by exact host first,
     * then by registered suffix (e.g. {@code api.brandx.tld} resolves through a
     * {@code brandx.tld} suffix entry).
     */
    public String domainForHost(String host) {
        if (host == null || hostToDomain.isEmpty()) return DEFAULT_DOMAIN;
        String h = normalizeHost(host);
        String exact = hostToDomain.get(h);
        if (exact != null) return exact;
        for (var e : hostToDomain.entrySet()) {
            String suffix = e.getKey();
            if (h.equals(suffix) || h.endsWith("." + suffix)) return e.getValue();
        }
        return DEFAULT_DOMAIN;
    }

    /** True iff this issuer is trusted (resolves to a non-null domain). */
    public boolean isTrusted(String issuer) {
        return domainOf(issuer) != null;
    }

    /** The trusted issuer set — the allowlist the multi-issuer decoder is built
     *  from (an {@code iss} outside this set 401s). */
    public java.util.Set<String> trustedIssuers() {
        return issuerToDomain.keySet();
    }

    /** True iff a per-brand multi-issuer registry was configured (more than the
     *  single back-compat entry). Gates whether the multi-issuer decoder swaps in. */
    public boolean isMultiIssuer() {
        return issuerToDomain.size() > 1;
    }

    private static String trimSlash(String s) {
        if (s == null) return "";
        String t = s.trim();
        return t.endsWith("/") ? t.substring(0, t.length() - 1) : t;
    }

    private static String normalizeHost(String s) {
        if (s == null) return "";
        String t = s.trim().toLowerCase();
        int c = t.indexOf(':');
        if (c >= 0) t = t.substring(0, c);   // strip port
        return t;
    }

    private static String sanitize(String s) {
        return s == null ? "" : s.trim().toLowerCase().replaceAll("[^a-z0-9-]", "-");
    }
}
