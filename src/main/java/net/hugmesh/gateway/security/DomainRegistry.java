package net.hugmesh.gateway.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.Collections;
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
 *
 * <p><b>Onion hosts (hugmesh-gateway#38).</b> A Tor v3 onion name is minted on the
 * node at first boot, so it can never be a config-time literal in
 * {@code app.tenancy.hosts}. {@code app.tenancy.hosts-file} names a RUNTIME
 * host-map file (a plain file or a mounted ConfigMap key) of {@code
 * <hash>.onion=<slug>} lines that the node reconcile / admin-bff appends after a
 * mint; {@link #reloadHostsFile()} re-reads it on a fixed delay and swaps the
 * effective map atomically. Only {@code .onion} keys are accepted from the file
 * (it is written by a node process, not by the operator), and a file line never
 * overrides a key the operator set in {@code app.tenancy.hosts}. Once onion
 * tenancy is configured (the file path is set, or the literal maps a named
 * onion), an UNMAPPED {@code .onion} Host resolves to {@code null} — fail CLOSED, so a
 * mis-registered onion can never be served as another brand — instead of
 * collapsing to {@link #DEFAULT_DOMAIN} like an unmapped HTTPS host does.
 */
@Component
public class DomainRegistry {

    /** The single-tenant / legacy domain every token maps to when no per-brand
     *  registry is configured. */
    public static final String DEFAULT_DOMAIN = "default";

    private static final Logger log = LoggerFactory.getLogger(DomainRegistry.class);

    /** The DNS suffix of a Tor onion service name (RFC 7686). */
    static final String ONION_SUFFIX = ".onion";

    /** Upper bound on the runtime host-map file. A v3 onion entry is ~70 bytes, so
     *  this is thousands of entries; anything larger is treated as a read failure
     *  (last-known-good kept) rather than parsed. */
    static final long MAX_HOSTS_FILE_BYTES = 1L << 20;

    private final Map<String, String> issuerToDomain = new LinkedHashMap<>();
    /** Operator-set {@code app.tenancy.hosts} literal — immutable after construction. */
    private final Map<String, String> literalHosts;
    /** EFFECTIVE host map (literal + file), an immutable snapshot swapped atomically
     *  by {@link #reloadHostsFile()}; never mutated in place, so a concurrent
     *  {@link #domainForHost} iterates a stable map. */
    private volatile Map<String, String> hostToDomain;
    private final String singleIssuer;
    /** {@code app.tenancy.hosts-file}; {@code null} when not configured. */
    private final Path hostsFile;
    /** True iff ONION tenancy is configured: the runtime file path is set (onions
     *  are registrable) OR the operator's literal already maps a named onion (onions
     *  are registered). Deliberately NOT {@code !hostToDomain.isEmpty()}: with the
     *  file configured but nothing appended yet the map IS empty, and an onion must
     *  still fail closed. Deliberately NOT "any host map / multi-issuer" either:
     *  the compose BRAND_B=1 lane and Studio's own-Casdoor domains already set
     *  APP_TENANCY_HOSTS/ISSUERS on hugmesh-fe-gateway, and their ONE onion door
     *  (TOR=1) is the mesh's default-brand door; failing it closed before anything
     *  can register an onion would turn a working door into a permanent 403. */
    private final boolean onionTenancyConfigured;
    /** Raw content of the last successful file read ({@code null} = absent/never
     *  read), so an unchanged poll re-parses nothing and swaps nothing. */
    private String lastFileContent;
    private boolean fileMissingLogged;

    public DomainRegistry(String singleIssuer, String issuersCsv, String hostsCsv) {
        this(singleIssuer, issuersCsv, hostsCsv, "");
    }

    @Autowired
    public DomainRegistry(
            @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri:}") String singleIssuer,
            @Value("${app.tenancy.issuers:}") String issuersCsv,
            @Value("${app.tenancy.hosts:}") String hostsCsv,
            @Value("${app.tenancy.hosts-file:}") String hostsFile) {
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
        Map<String, String> literal = new LinkedHashMap<>();
        if (hostsCsv != null && !hostsCsv.isBlank()) {
            for (String pair : hostsCsv.split(",")) putHostPair(literal, pair, false);
        }
        this.literalHosts = Collections.unmodifiableMap(literal);
        this.hostToDomain = this.literalHosts;
        this.hostsFile = (hostsFile == null || hostsFile.isBlank()) ? null : Path.of(hostsFile.trim());
        this.onionTenancyConfigured = this.hostsFile != null
                || literal.keySet().stream().anyMatch(DomainRegistry::isNamedOnion);
        // Prime synchronously so the first request after startup already sees the
        // file's entries (the scheduled poll only keeps it current afterwards).
        reloadHostsFile();
    }

    /**
     * Re-read {@code app.tenancy.hosts-file} and, when its content changed, swap
     * the effective host map atomically. Runs on a fixed delay
     * ({@code app.tenancy.hosts-file-refresh-ms}, default 5 s) — off the request
     * path, like the route-access / revocation refreshes — and once at
     * construction. Reads CONTENT rather than trusting mtime or a WatchService: a
     * ConfigMap mount is a symlink swap under {@code ..data/} that inotify on the
     * key path does not see.
     *
     * <p>A missing file means "no runtime entries" (onions not yet registered, so
     * they fail closed); any other read failure keeps the last-known-good map, so a
     * transient I/O error neither drops registered onions nor admits new ones.
     */
    @Scheduled(fixedDelayString = "${app.tenancy.hosts-file-refresh-ms:5000}")
    public synchronized void reloadHostsFile() {
        if (hostsFile == null) return;
        String content;
        try {
            if (Files.size(hostsFile) > MAX_HOSTS_FILE_BYTES) {
                log.warn("[tenancy] host-map file {} exceeds {} bytes — keeping the previous map",
                        hostsFile, MAX_HOSTS_FILE_BYTES);
                return;
            }
            content = Files.readString(hostsFile, StandardCharsets.UTF_8);
            fileMissingLogged = false;
        } catch (NoSuchFileException e) {
            if (!fileMissingLogged) {
                log.info("[tenancy] host-map file {} is absent — no runtime host entries "
                        + "(unregistered .onion hosts fail closed)", hostsFile);
                fileMissingLogged = true;
            }
            content = null;
        } catch (IOException | RuntimeException e) {
            log.warn("[tenancy] host-map file {} unreadable ({}) — keeping the previous map",
                    hostsFile, e.toString());
            return;
        }
        if (java.util.Objects.equals(content, lastFileContent)) return;
        Map<String, String> merged = new LinkedHashMap<>(literalHosts);
        if (content != null) {
            Map<String, String> fromFile = new LinkedHashMap<>();
            for (String line : content.split("\\R")) {
                String l = line.strip();
                if (l.isEmpty() || l.startsWith("#")) continue;
                // A line may also carry a CSV run, matching the env literal's shape.
                for (String pair : l.split(",")) putHostPair(fromFile, pair, true);
            }
            // The operator's literal is config-time authority: a runtime line can
            // ADD an onion, never re-point a host the operator already mapped.
            for (var e : fromFile.entrySet()) merged.putIfAbsent(e.getKey(), e.getValue());
        }
        this.hostToDomain = Collections.unmodifiableMap(merged);
        this.lastFileContent = content;
    }

    /** Parse one {@code host=slug} pair into {@code into}. File-sourced pairs
     *  ({@code onionOnly}) must name a {@code <label>.onion} host; anything else
     *  is logged and dropped, so a node process cannot map an HTTPS host. */
    private static void putHostPair(Map<String, String> into, String pair, boolean onionOnly) {
        int eq = pair.indexOf('=');
        if (eq <= 0) return;
        String host = normalizeHost(pair.substring(0, eq).trim());
        String dom = sanitize(pair.substring(eq + 1).trim());
        if (host.isEmpty() || dom.isEmpty()) return;
        if (onionOnly && !isNamedOnion(host)) {
            log.warn("[tenancy] host-map file entry '{}' ignored — the runtime file only "
                    + "registers <hash>.onion hosts", host);
            return;
        }
        into.put(host, dom);
    }

    /** {@code <at-least-one-label>.onion} — a bare {@code onion} key would match
     *  every onion by suffix and defeat the fail-closed default. */
    private static boolean isNamedOnion(String normalizedHost) {
        return normalizedHost.endsWith(ONION_SUFFIX)
                && normalizedHost.length() > ONION_SUFFIX.length();
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
     * configured (single-tenant: the Host check is a no-op) OR when an ordinary
     * host is not mapped — so a single-brand cluster always matches and an
     * unmapped host on a multi-brand cluster falls back to the route-access
     * default-deny rather than silently granting another brand's bypass. Matches
     * by exact host first, then by registered suffix (e.g. {@code api.brandx.tld}
     * resolves through a {@code brandx.tld} suffix entry).
     *
     * <p><b>Unmapped onion → {@code null} (fail CLOSED).</b> When onion tenancy is
     * configured — {@code app.tenancy.hosts-file} is set, or the literal
     * {@code app.tenancy.hosts} maps at least one named onion — a Host ending in
     * {@code .onion} that no entry maps returns {@code null}, never
     * {@code "default"}: once onions are per-brand doors, collapsing an
     * unregistered one to the default brand would serve brand A over brand B's
     * onion. The caller must reject. Without onion tenancy there is at most ONE
     * onion (the mesh's own door, which is the default brand's), so an onion keeps
     * resolving like any unmapped host — {@code "default"} — and the compose lane's
     * door keeps working with or without BRAND_B / own-Casdoor domains.
     */
    public String domainForHost(String host) {
        Map<String, String> map = hostToDomain;   // one snapshot for the whole lookup
        if (host == null) return DEFAULT_DOMAIN;
        String h = normalizeHost(host);
        boolean onion = h.endsWith(ONION_SUFFIX) || h.equals(ONION_SUFFIX.substring(1));
        if (map.isEmpty() && !(onion && onionFailsClosed())) return DEFAULT_DOMAIN;
        String exact = map.get(h);
        if (exact != null) return exact;
        for (var e : map.entrySet()) {
            String suffix = e.getKey();
            if (h.equals(suffix) || h.endsWith("." + suffix)) return e.getValue();
        }
        if (onion && onionFailsClosed()) return null;
        return DEFAULT_DOMAIN;
    }

    /** Whether an unmapped onion must fail closed — see {@link #onionTenancyConfigured}. */
    private boolean onionFailsClosed() {
        return onionTenancyConfigured;
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
        // A fully-qualified name may carry the root label's trailing dot
        // ("x.onion.", "api.brandx.tld."); it names the SAME host, so it must not
        // slip past the suffix match and collapse to "default".
        while (t.endsWith(".")) t = t.substring(0, t.length() - 1);
        return t;
    }

    private static String sanitize(String s) {
        return s == null ? "" : s.trim().toLowerCase().replaceAll("[^a-z0-9-]", "-");
    }
}
