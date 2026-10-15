package net.hugmesh.gateway.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.cloud.gateway.config.GatewayProperties;
import org.springframework.cloud.gateway.handler.predicate.PredicateDefinition;
import org.springframework.cloud.gateway.route.RouteDefinition;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import net.hugmesh.gateway.security.DomainRegistry;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

/**
 * Casdoor-aware OAuth2 resource-server config for the gateway. Mirrors
 * the {@code games.hugmesh.bff.config.SecurityConfig} pattern from
 * hugmesh.games so a JWT issued by either Casdoor instance maps to
 * the same Spring authorities regardless of which gateway / API pod
 * sees it first.
 *
 * <p>Gateway-specific path policy:
 *
 * <ul>
 *   <li>{@code /actuator/**} (health, info, metrics) — restricted to
 *       {@code ROLE_GAME-MASTER} or {@code ROLE_ADMIN}. Health endpoints leak
 *       topology / pod counts / cassandra reachability and should never be
 *       public; gating on GAME-MASTER alone (a role not seeded in every
 *       deployment) left them unreachable even by admins, so ROLE_ADMIN is
 *       included. ROLE_MOD/ROLE_USER stay excluded (infra-isolation invariant).</li>
 *   <li>{@code /api/auth/**} — public (the BFF's Casdoor-grant proxy
 *       lives here; users need to be able to authenticate to anything).</li>
 *   <li>{@code /api/registration/**} — public (external-OAuth signup
 *       must work for unauthenticated visitors).</li>
 *   <li>{@code /api/login/**} — public (federated login remote).</li>
 *   <li>PKI tier only: EVERY request on the headscale route's Host —
 *       {@code ROLE_SUPERADMIN}, checked FIRST, so nothing above is public there
 *       (decision 79; see {@link #headscaleHostPatterns}).</li>
 *   <li>everything else — authenticated.</li>
 * </ul>
 *
 * <p>The same JWT-to-authority conversion as the BFF: Casdoor's
 * {@code roles}/{@code permissions}/{@code isAdmin} claims become
 * Spring authorities. Every authenticated principal also gets
 * {@code ROLE_USER}.
 *
 * <p><b>Admin works on the internal token alone.</b> The
 * External-Authorization header path (see
 * {@link net.hugmesh.gateway.filter.ExternalAuthHeaderFilter})
 * is additive — it appends headers when an external OAuth token is
 * present but never <em>requires</em> one. A request carrying a valid
 * Casdoor JWT with {@code ROLE_ADMIN} sails through every authz layer
 * (this filter chain, the revocation check, the resource-access
 * filter) regardless of whether External-Authorization is also set.
 * The contract: external OAuth is for proving "you're this GitHub
 * user"; internal Casdoor admin is for proving "you have admin
 * rights here" — orthogonal and the latter never depends on the former.
 */
@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {

    /** Issuer-&gt;domain source of truth. Injected so the converter can stamp the
     *  cryptographically-validated {@code iss} as a {@code DOMAIN_<x>} authority.
     *  Single-issuer clusters get a registry that maps the lone issuer (or no
     *  issuer at all) to {@code DOMAIN_default}, so behaviour is unchanged. */
    private final DomainRegistry domainRegistry;

    /** OPTIONAL per-brand multi-issuer resolver. Present (non-null provider
     *  value) ONLY when {@code app.tenancy.issuers} is configured, via
     *  {@link TenancyResourceServerConfig}. When absent the resource server stays
     *  on the single {@code o.jwt(...)} issuer-uri wiring — byte-for-byte the
     *  current single-issuer path. */
    private final ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>>
            tenantAuthManagerResolver;

    /** FE-tier marker — {@code spring.application.name} is (or suffixes to)
     *  {@code *-fe-gateway}, mirroring {@code CanonicalSeed.bySuffix}. ONLY the
     *  front-door tier serves the anonymous SPA shell + the public federation
     *  reads ({@link #FE_SHELL_PUBLIC_GET_PATHS}); on the pki/be tiers (and on an
     *  unknown/blank name) those paths stay on the {@code authenticated()} floor —
     *  fail-closed. This tier-scoping is load-bearing: the route-access filter
     *  forwards ANONYMOUS requests untouched (SecurityConfig is the only anonymous
     *  gate), and the pki tier fronts the headscale control plane with a
     *  Host-but-no-Path route — a tier-blind {@code "/"} permitAll would hand
     *  anonymous traffic straight to it. */
    private final boolean feTier;

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    /** The id of the route that fronts the headscale control plane — hugmesh-pki-gateway
     *  {@code application-pki.yml} (and the generator's {@code apps/20-gateway-pki.yaml},
     *  which rebrand rewrites) both declare it as {@code id: headscale} with a
     *  {@code Host} predicate and NO {@code Path} predicate. */
    static final String HEADSCALE_ROUTE_ID = "headscale";

    /**
     * PKI-TIER HEADSCALE HOST GATE (decision 79 = B, hugmesh-admin-bff-api#57,
     * operator answer 2026-09-23). The {@code Host} patterns of the {@code headscale}
     * route, lower-cased; EMPTY (gate off) on every other tier and on a pki instance
     * with no headscale route. Every request whose Host matches one of them needs
     * {@code ROLE_SUPERADMIN}, as the FIRST {@code authorizeExchange} rule — ahead of
     * {@link #PUBLIC_PATHS}, so no path on that Host is public (anonymous 401,
     * everyone else 403).
     *
     * <p><b>Why here and not a route-access row.</b> headscale is routed by Host alone,
     * so its old floor was a bare {@code /** -> ROLE_SUPERADMIN} row in
     * {@code CanonicalSeed.pki()} — which (a) the admin API can never recreate
     * (decision 61) and (b) never stopped a same-brand {@code ROLE_ADMIN} /
     * {@code ROLE_GAME-MASTER}, because {@code GatewayRouteAccessFilter} forwards both
     * in their own domain before it reads any rule. This layer runs before that
     * filter and before its bypasses, so it stops them. The row is dropped.
     *
     * <p><b>Where the host comes from.</b> NOT a hand-kept copy of
     * {@code scale.hugmesh.net}: it is read from the {@code headscale} route's own
     * {@code Host} predicate in the bound {@link GatewayProperties} route list (the
     * {@code spring.cloud.gateway.server.webflux.routes} the image serves) — the one
     * place the rebrand rewrites. (hugmesh-pki-gateway's Liquibase
     * {@code gateway_routes} seed is NOT read: nothing in this gateway loads that
     * table.) A pki instance that HAS a headscale route whose Host cannot be derived
     * fails startup rather than serving headscale ungated.
     */
    private final List<String> headscaleHostPatterns;

    /** D8 MFA marker derivation — {@code app.mfa.enabled} (default {@code false},
     *  ships dark). When off the converter emits the byte-identical legacy
     *  authority set and {@code MFA_SATISFIED} is never produced. */
    private final boolean mfaEnabled;

    /** D8 MFA freshness window in millis — {@code app.mfa.freshness-window}
     *  (default 10m). A {@code mfa_satisfied_at} stamp older than this (or in the
     *  future) does NOT yield {@code MFA_SATISFIED}. */
    private final long mfaFreshnessWindowMillis;

    @Autowired
    public SecurityConfig(DomainRegistry domainRegistry,
                          ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>>
                                  tenantAuthManagerResolver,
                          @Value("${spring.application.name:}") String applicationName,
                          @Value("${app.mfa.enabled:false}") boolean mfaEnabled,
                          @Value("${app.mfa.freshness-window:600000}") long mfaFreshnessWindowMillis,
                          ObjectProvider<GatewayProperties> gatewayProperties) {
        this(domainRegistry, tenantAuthManagerResolver, applicationName, mfaEnabled,
                mfaFreshnessWindowMillis, routesOf(gatewayProperties.getIfAvailable()));
    }

    /** Route-list form of the production constructor — the seam the headscale-gate
     *  unit tests drive with hand-built {@link RouteDefinition}s. */
    SecurityConfig(DomainRegistry domainRegistry,
                   ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>>
                           tenantAuthManagerResolver,
                   String applicationName,
                   boolean mfaEnabled,
                   long mfaFreshnessWindowMillis,
                   List<RouteDefinition> routes) {
        this.domainRegistry = domainRegistry;
        this.tenantAuthManagerResolver = tenantAuthManagerResolver;
        this.feTier = isFeTier(applicationName);
        this.mfaEnabled = mfaEnabled;
        this.mfaFreshnessWindowMillis = mfaFreshnessWindowMillis;
        this.headscaleHostPatterns = deriveHeadscaleHostPatterns(applicationName, routes);
        if (!headscaleHostPatterns.isEmpty()) {
            log.info("[security] pki tier: every request on headscale Host {} requires ROLE_SUPERADMIN",
                    headscaleHostPatterns);
        }
    }

    /** Pre-decision-79 signature (no route definitions ⇒ the headscale host gate is
     *  OFF). Kept so the existing slice tests compile unchanged; production uses the
     *  {@code @Autowired} constructor above. */
    public SecurityConfig(DomainRegistry domainRegistry,
                          ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>>
                                  tenantAuthManagerResolver,
                          String applicationName,
                          boolean mfaEnabled,
                          long mfaFreshnessWindowMillis) {
        this(domainRegistry, tenantAuthManagerResolver, applicationName, mfaEnabled,
                mfaFreshnessWindowMillis, List.of());
    }

    /** Legacy convenience (MFA derivation OFF, default 10m window, NO tier —
     *  the FE shell paths stay gated, no headscale host gate). Keeps the pre-D8 slice
     *  tests compiling and proves the dark/unknown-tier default emits the
     *  byte-identical legacy policy. Production uses the {@code @Autowired}
     *  constructor above. */
    public SecurityConfig(DomainRegistry domainRegistry,
                          ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>>
                                  tenantAuthManagerResolver) {
        this(domainRegistry, tenantAuthManagerResolver, "", false, 600_000L);
    }

    private static List<RouteDefinition> routesOf(GatewayProperties props) {
        return props == null || props.getRoutes() == null ? List.of() : props.getRoutes();
    }

    /** PKI-tier detection by instance-name suffix — the SAME derivation
     *  {@code CanonicalSeed.bySuffix} uses ({@code hugmesh-pki-gateway} and every
     *  {@code ${BRAND}-pki-gateway}). */
    static boolean isPkiTier(String applicationName) {
        return applicationName != null && applicationName.endsWith("-pki-gateway");
    }

    /**
     * The headscale route's {@code Host} patterns, lower-cased, for the pki tier;
     * empty on every other tier and when no route has id {@value #HEADSCALE_ROUTE_ID}.
     * Reads every argument of every {@code Host} predicate on that route: the
     * shortcut form {@code Host=a,b} binds as {@code _genkey_0}/{@code _genkey_1}, the
     * long form as {@code patterns} (a comma list, or {@code patterns[0]}…).
     *
     * @throws IllegalStateException on the pki tier when a headscale route exists but
     *         no non-blank Host pattern can be read from it — startup fails rather
     *         than serving headscale with no host gate.
     */
    static List<String> deriveHeadscaleHostPatterns(String applicationName,
                                                    List<RouteDefinition> routes) {
        if (!isPkiTier(applicationName) || routes == null) return List.of();
        LinkedHashSet<String> patterns = new LinkedHashSet<>();
        boolean headscaleRoutePresent = false;
        for (RouteDefinition route : routes) {
            if (route == null || !HEADSCALE_ROUTE_ID.equals(route.getId())) continue;
            headscaleRoutePresent = true;
            for (PredicateDefinition p : route.getPredicates()) {
                if (p == null || !"Host".equalsIgnoreCase(p.getName()) || p.getArgs() == null) continue;
                for (String arg : p.getArgs().values()) {
                    if (arg == null) continue;
                    for (String one : arg.split(",")) {
                        String t = one.trim().toLowerCase(Locale.ROOT);
                        if (!t.isEmpty()) patterns.add(t);
                    }
                }
            }
        }
        if (headscaleRoutePresent && patterns.isEmpty()) {
            throw new IllegalStateException("pki tier '" + applicationName + "': route '"
                    + HEADSCALE_ROUTE_ID + "' exists but no Host pattern can be derived from it; "
                    + "refusing to start with the headscale control plane ungated "
                    + "(decision 79, hugmesh-admin-bff-api#57)");
        }
        return List.copyOf(new ArrayList<>(patterns));
    }

    /** The derived headscale Host patterns (empty = gate off). Read-only view for
     *  tests and diagnostics. */
    public List<String> headscaleHostPatterns() {
        return headscaleHostPatterns;
    }

    /** Same matcher shape Spring Cloud Gateway's {@code HostRoutePredicateFactory}
     *  uses ({@code AntPathMatcher} with {@code .} as the separator), made
     *  case-insensitive. */
    private static final AntPathMatcher HOST_MATCHER = hostMatcher();

    private static AntPathMatcher hostMatcher() {
        AntPathMatcher m = new AntPathMatcher(".");
        m.setCaseSensitive(false);
        return m;
    }

    /**
     * True iff {@code hostHeader} is on the headscale Host. A SUPERSET of the route
     * predicate on purpose (this gate may deny more than headscale serves, never
     * less): SCG's default {@code HostRoutePredicateFactory} matches the RAW
     * {@code Host} header (port included, case-sensitive); this also tries the
     * port-stripped form and ignores case and a trailing root dot.
     */
    static boolean isHeadscaleHost(List<String> patterns, String hostHeader) {
        if (patterns == null || patterns.isEmpty() || hostHeader == null) return false;
        List<String> candidates = new ArrayList<>(2);
        String raw = hostHeader.trim();
        candidates.add(raw);
        candidates.add(stripPortAndRootDot(raw));
        for (String pattern : patterns) {
            for (String candidate : candidates) {
                if (!candidate.isEmpty() && HOST_MATCHER.match(pattern, candidate)) return true;
            }
        }
        return false;
    }

    private static String stripPortAndRootDot(String host) {
        String h = host;
        if (h.startsWith("[")) {                       // IPv6 literal: [::1]:8080
            int close = h.indexOf(']');
            h = close > 0 ? h.substring(0, close + 1) : h;
        } else {
            int colon = h.lastIndexOf(':');
            if (colon >= 0 && h.indexOf(':') == colon) h = h.substring(0, colon);
        }
        while (h.endsWith(".")) h = h.substring(0, h.length() - 1);
        return h;
    }

    private ServerWebExchangeMatcher headscaleHostMatcher() {
        return exchange -> {
            Collection<String> hosts = exchange.getRequest().getHeaders().get("Host");
            if (hosts != null) {
                for (String host : hosts) {
                    if (isHeadscaleHost(headscaleHostPatterns, host)) {
                        return ServerWebExchangeMatcher.MatchResult.match();
                    }
                }
            }
            // Also the request URI's host (the server derives it from Host, so this
            // only ever widens the match — never narrows it).
            String uriHost = exchange.getRequest().getURI().getHost();
            return isHeadscaleHost(headscaleHostPatterns, uriHost)
                    ? ServerWebExchangeMatcher.MatchResult.match()
                    : ServerWebExchangeMatcher.MatchResult.notMatch();
        };
    }

    /** FE-tier detection by instance-name suffix — the SAME derivation
     *  {@code CanonicalSeed.bySuffix} uses for the seed tiers, so the coarse floor
     *  and the route-access seed can never disagree about which instance is the
     *  front door. Blank/unknown names are NOT fe (fail-closed). */
    static boolean isFeTier(String applicationName) {
        return applicationName != null && applicationName.endsWith("-fe-gateway");
    }

    /** Paths that anonymous traffic must reach (login, registration).
     *  Aligned with the front-end remote modules that exist. There is deliberately
     *  NO {@code /_remotes/banned/**}: no remote is served there (the banned-user
     *  flow is the login-ui appeal page, fed by {@code /bff/public/appeal-contact}),
     *  so a permit would silently expose anything later mounted at that prefix. */
    private static final String[] PUBLIC_PATHS = {
            "/api/auth/**",
            "/api/registration/**",
            "/api/login/**",
            "/_remotes/login/**",
            "/_remotes/registration/**",
            // Public login-page announcements: the admin-bff exposes
            // GET /bff/public/announcements/login UNAUTHENTICATED so the
            // pre-auth LOGIN page can render published login-target banners.
            // The fe-gateway proxies /bff/public/announcements/** to the
            // admin-bff (via the /bff/** catch-all); without this allowance the
            // coarse anyExchange().authenticated() floor would 401 the anonymous
            // visitor before the route-access PUBLIC rule (CanonicalSeed.fe())
            // is ever consulted. The authed /bff/announcements/** (home + forum)
            // and ROLE_ADMIN /bff/admin/announcements/** stay gated as before.
            "/bff/public/announcements/**",
            // Public appeal-contact resolver: the admin-bff exposes
            // GET /bff/public/appeal-contact UNAUTHENTICATED (permitAll, returns
            // {"email":"..."}, no PII) so the pre-auth login-ui appeal page can
            // render the contact address a banned/anonymous visitor should reach.
            // The fe-gateway proxies it to the admin-bff (via the /bff/** catch-all);
            // without this allowance the coarse anyExchange().authenticated() floor
            // would 401 the anonymous visitor before the route-access PUBLIC rule
            // (CanonicalSeed.fe()) is ever consulted. Scoped to the exact route (NOT
            // a blanket /bff/public/**), mirroring the announcements precedent.
            "/bff/public/appeal-contact",
            // Per-domain theme, both representations: the admin-bff exposes
            // GET /bff/public/theme?domain=… (JSON) and GET /bff/public/theme.css
            // (a stylesheet a page <link>s directly) UNAUTHENTICATED. They have to
            // be: the surfaces that consume them include the PRE-AUTH login page and
            // every anonymous visitor, and a theme that only authenticated users can
            // fetch means the login page renders unbranded — the one page a visitor
            // sees before they have any session at all. The 401 was invisible to the
            // Studio and the admin UI, which are authenticated and so always saw a
            // correctly-themed mesh.
            // Serving these anonymously leaks nothing: PublicTheme is a projection
            // that deliberately drops updatedBy (an administrator's JWT subject —
            // here an email address) precisely so this endpoint can be public.
            // Scoped to the exact routes, NOT a blanket /bff/public/**, mirroring the
            // announcements and appeal-contact precedents above.
            "/bff/public/theme",
            "/bff/public/theme.css",
            // Native login credential submit (the NATIVE-LOGIN model). The
            // anonymous browser POSTs {username,password(,mfaPasscode)} to
            // /bff/login on OUR login-ui form BEFORE it holds any session or role
            // — the fe-gateway proxies it to the user-bff (via the /bff/**
            // catch-all), which drives the Casdoor /api/login leg SERVER-SIDE and
            // mints the opaque bff_ session. Casdoor is never browser-exposed, so
            // /bff/login is the ONLY anonymous entry point to authentication.
            // Without this allowance the coarse anyExchange().authenticated() floor
            // would 401 the credential POST before the route-access PUBLIC rule
            // (CanonicalSeed.fe()) is ever consulted — the two layers must open the
            // SAME surface (the front-page-parity invariant). Scoped to the EXACT
            // path (NOT /bff/login/**), mirroring the announcements/appeal-contact
            // precedent above (the earlier /bff/auth/callback allowance this used
            // to mirror was retired with the browser-PKCE redirect model — #80).
            // ANONYMOUS PASSWORD RESET. user-bff permitAll's exactly
            // /bff/password-reset/request and /bff/password-reset/confirm — the
            // forgot-password legs, which by definition run with NO session. The
            // fe-gateway now routes both to user-bff by exact path, but this coarse
            // anyExchange().authenticated() floor 401s the anonymous visitor before
            // the route ever runs and before the route-access PUBLIC rule
            // (CanonicalSeed.fe()) is consulted — the same shape as the announcements,
            // appeal-contact and theme entries above, and the reason each of them is
            // here. Without this, a correctly-routed reset is still unreachable.
            //
            // EXACT PATHS, not /bff/password-reset/**: this mirrors user-bff's own
            // SecurityConfig, which permits the two by exact path so that a future
            // sibling under this prefix has to be opened deliberately rather than
            // inheriting anonymous access. This is a credential-WRITING surface; the
            // subtree form would be the wrong default here more than anywhere else.
            //
            // Opening the FLOOR is not the same as turning the feature on. user-bff
            // answers 503 while casdoor.password-reset.enabled is false (its default),
            // so the effect of this entry on a mesh that has not enabled reset is that
            // the anonymous caller reaches the owning service and is told, truthfully,
            // that it is not enabled — instead of a 401 that implies the wrong thing.
            "/bff/password-reset/request",
            "/bff/password-reset/confirm",
            "/bff/login",
    };

    /**
     * FE-TIER-ONLY anonymous GET surface — the SPA shell an anonymous visitor
     * must be able to load, plus the two public federation reads. Applied ONLY
     * when {@link #feTier} (instance name suffixes {@code -fe-gateway}) and ONLY
     * for {@code GET} — every other method/tier stays on the
     * {@code authenticated()} floor (fail-closed).
     *
     * <ul>
     *   <li><b>The SPA shell</b> — the route-access seed has carried
     *       {@code '/' -> PUBLIC} ({@code CanonicalSeed.fe()}) since day one, but
     *       the coarse {@code anyExchange().authenticated()} floor here 401'd the
     *       anonymous request BEFORE that rule was ever consulted (verified live:
     *       anonymous {@code GET /} through the compose front door returned 401
     *       despite the PUBLIC row). The fe catch-all proxies to the
     *       host-shell nginx (Angular browser build at the webroot +
     *       {@code try_files ... /index.html}), so the anonymous front page needs
     *       the document ({@code /}, {@code /index.html}), the root-level hashed
     *       bundles ({@code /*.js}, {@code /*.css} — Ant {@code *} does not cross
     *       {@code /}, so ONLY webroot files match), the module-federation
     *       manifests ({@code /importmap.json}, {@code /remoteEntry.json}), the
     *       favicon and {@code /assets/**}. This also unblocks the vanity-host
     *       flow ({@code alice.<domain>/} arrives as path {@code /}).</li>
     *   <li><b>{@code /api/federation/vanity(/**)}</b> — the PUBLIC profile
     *       resolve (federation-api permitAll's it app-side; the cluster fe spec's
     *       vanity-subdomain route documents this exact PUBLIC_PATHS entry as the
     *       deferred missing piece). Includes the bare collection path — the
     *       Host-derived resolve ({@code VanityController.resolveByHost}).</li>
     *   <li><b>{@code /api/federation/capabilities}</b> — the public install-state
     *       projection a LOGGED-OUT host shell reads to grey-out optional
     *       services (federation-api permitAll, no PII).</li>
     * </ul>
     *
     * <p>Deliberately NOT a blanket {@code /**} or {@code /api/federation/**}:
     * the manifest / module-registry / username surfaces keep their auth, and the
     * pki/be tiers (headscale control plane, homeserver APIs) never see any of
     * these permits.
     */
    private static final String[] FE_SHELL_PUBLIC_GET_PATHS = {
            "/",
            "/index.html",
            "/favicon.ico",
            "/importmap.json",
            "/remoteEntry.json",
            "/*.js",
            "/*.css",
            "/assets/**",
            "/api/federation/vanity",
            "/api/federation/vanity/**",
            "/api/federation/capabilities",
            // The NATIVE login page — OUR login-ui SPA shell, the ONLY login
            // surface in the native-login model (Casdoor's hosted page is never
            // browser-exposed). A hard navigation to /login (deep-link or a 401
            // redirect target) arrives at the fe front door as GET /login and is
            // proxied to the login-ui remote (fe route `login-ui` Path=/login/**);
            // the anonymous visitor MUST be able to load the document + its hashed
            // bundles to see the username/password form. GET-only + fe-tier-scoped
            // (like the rest of this shell floor): the credential SUBMIT is the
            // separate anonymous POST /bff/login in PUBLIC_PATHS, so a non-GET to
            // /login/** stays on the authenticated() floor. Mirrors the route-access
            // PUBLIC row (CanonicalSeed.fe() `/login/** -> PUBLIC`) so the coarse
            // floor and the route-access layer open the SAME surface.
            "/login/**",
    };

    /**
     * Homeserver-token passthrough surface (account-states PREREQ). Native
     * clients (Element / Tusky / Ivory) and our own social UIs hit these paths
     * with an opaque Matrix {@code access_token} / Mastodon OAuth token in the
     * {@code Authorization} header — NOT a Casdoor JWT. If the resource-server
     * layer required a valid JWT it would 401 every homeserver request before the
     * gate ever sees it. So these are permitAll at the OAuth2 resource-server
     * layer; authorization is done downstream by:
     * <ul>
     *   <li>{@link net.hugmesh.gateway.filter.HomeserverTokenRevocationFilter}
     *       — resolves the bearer and denies revoked tokens (ban / per-credential /
     *       external-client), fail-closed once {@code app.hs-revocation.enabled};</li>
     *   <li>the {@code gateway_route_access} base-role rows
     *       ({@code ROLE_MATRIX → /_matrix/**}, {@code ROLE_MASTODON → /api/v1/**}
     *       + {@code /oauth/**}) for principals that DO present a Casdoor JWT (our
     *       UIs proxied with the user's session).</li>
     * </ul>
     * {@code GET /_matrix/client/versions} and {@code /.well-known/**} stay public
     * here so first-run client discovery is never blocked by the issuance gate.
     */
    private static final String[] HOMESERVER_PASSTHROUGH_PATHS = {
            "/_matrix/**",
            "/api/v1/**",
            "/api/v2/**",
            "/oauth/**",
            "/.well-known/**",
    };

    /** Infrastructure / observability paths — GAME-MASTER / ADMIN / SUPERADMIN
     *  (coarse role gate; domain-scoping of admin's infra reach is enforced by
     *  {@link net.hugmesh.gateway.filter.GatewayRouteAccessFilter}). */
    private static final String[] INFRA_PATHS = {
            "/actuator/**",
            "/api/admin/health/**",
            "/api/admin/cassandra/**",
            "/api/admin/cluster/**",
    };

    @Bean
    SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        return http
                .authorizeExchange(ex -> {
                    // PKI tier: the headscale control plane's Host needs
                    // ROLE_SUPERADMIN for EVERY path (decision 79). FIRST, because
                    // authorizeExchange is first-match-wins: below PUBLIC_PATHS an
                    // anonymous /api/auth/** on that Host would be permitted. Off on
                    // every other tier (empty pattern list). See headscaleHostPatterns.
                    if (!headscaleHostPatterns.isEmpty()) {
                        ex.matchers(headscaleHostMatcher()).hasRole("SUPERADMIN");
                    }
                    ex.pathMatchers(PUBLIC_PATHS).permitAll();
                    // FE front door ONLY: the anonymous SPA shell + the public
                    // federation reads, GET-only. Other tiers (pki/be) and other
                    // methods stay on the authenticated() floor — see
                    // FE_SHELL_PUBLIC_GET_PATHS for why this is tier-scoped.
                    if (feTier) {
                        ex.pathMatchers(org.springframework.http.HttpMethod.GET,
                                FE_SHELL_PUBLIC_GET_PATHS).permitAll();
                    }
                    // Homeserver-token traffic carries an opaque Matrix/Mastodon
                    // bearer, not a Casdoor JWT — permit it at the resource-server
                    // layer so it isn't 401'd before the HomeserverTokenRevocation
                    // filter + the ROLE_MATRIX/ROLE_MASTODON route-access rows do
                    // the actual authz. See HOMESERVER_PASSTHROUGH_PATHS.
                    ex.pathMatchers(HOMESERVER_PASSTHROUGH_PATHS).permitAll();
                    // Infra/health endpoints: the platform super-role GAME-MASTER
                    // OR ROLE_ADMIN. GAME-MASTER is not seeded in every deployment,
                    // so gating on it alone left these endpoints unreachable even by
                    // admins; ROLE_ADMIN (which admins always hold) restores access
                    // while still excluding ROLE_MOD/ROLE_USER (the isolation
                    // invariant: mods never reach infra/logs/server-admin).
                    // SUPERADMIN added so the cross-domain infra role reaches the
                    // coarse infra gate. This gate stays ROLE-only (the
                    // authorizeExchange layer can't cheaply see Host); the
                    // DOMAIN-scoping of admin's infra reach is enforced
                    // downstream by GatewayRouteAccessFilter, which DOES see Host.
                    ex.pathMatchers(INFRA_PATHS).hasAnyRole("GAME-MASTER", "ADMIN", "SUPERADMIN");
                    ex.anyExchange().authenticated();
                })
                // OWASP / NIST 800-228 browser-policy hardening — emitted ONCE at
                // the hugmesh-gateway front door (the single TLS-terminating PEP)
                // so all brands/BFFs inherit it and the 12 per-service configs can't
                // drift. ADDITIVE: this only adds response headers and KEEPS Spring's
                // reactive secure defaults (X-Content-Type-Options: nosniff,
                // X-Frame-Options: DENY, Cache-Control) — those are NOT disabled.
                // It changes NO authz rule, issuer validation, or the CSRF posture.
                .headers(h -> h
                        // CSP — the UI-shell value. frame-ancestors 'none' defends
                        // against framing on modern UAs alongside the kept
                        // X-Frame-Options: DENY for legacy UAs. Tighten script-src to
                        // nonces/hashes once the Angular build emits them.
                        .contentSecurityPolicy(csp -> csp.policyDirectives(
                                "default-src 'self'; script-src 'self'; style-src 'self'; "
                                + "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
                                + "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; "
                                + "object-src 'none'; upgrade-insecure-requests"))
                        // HSTS — emitted ONLY here at the TLS edge (never from a
                        // plaintext intra-mesh BFF hop). 63072000s = 730d, >=1yr per
                        // OWASP secure-headers.
                        .hsts(hsts -> hsts
                                .includeSubdomains(true)
                                .preload(true)
                                .maxAge(java.time.Duration.ofDays(730)))
                        // Referrer-Policy — keep Spring's default explicit.
                        .referrerPolicy(rp -> rp.policy(
                                org.springframework.security.web.server.header
                                        .ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy.NO_REFERRER))
                        // Permissions-Policy — deny powerful features by default, with
                        // the THREE exceptions the platform's own features require.
                        // publickey-credentials-get is left unset here and granted only
                        // on the host serving WebAuthn/MFA enrollment.
                        //
                        // camera/microphone/autoplay are (self), NOT (). An EMPTY
                        // allowlist `camera=()` denies EVERY origin INCLUDING self, which
                        // makes the shipped Matrix video/voice call feature impossible:
                        // getUserMedia rejects with NotAllowedError ("Permissions policy
                        // violation: camera is not allowed in this document"), matrix-ui
                        // never acquires a local stream, never builds an offer and never
                        // sends m.call.invite — the caller sits in 'calling' while the
                        // callee stays 'idle' forever. The failure is invisible at the
                        // network layer (the request is never made at all), which is why
                        // it reads as a WebRTC/ICE problem rather than a header problem.
                        // (self) still denies every OTHER origin, so an embedded
                        // third-party iframe gets nothing. autoplay=(self) is needed on
                        // the receiving side so the remote <video> can start without a
                        // user gesture. display-capture stays () — screen sharing is not
                        // a shipped feature and gets no grant.
                        .permissionsPolicy(pp -> pp.policy(
                                "geolocation=(), camera=(self), microphone=(self), payment=(), usb=(), "
                                + "accelerometer=(), gyroscope=(), magnetometer=(), autoplay=(self), "
                                + "display-capture=(), fullscreen=(self)"))
                        // COOP/CORP — same-origin isolation. COEP: require-corp is
                        // DELIBERATELY NOT enabled (would break module-federation
                        // remote loading until the remotes are CORP-tagged).
                        .crossOriginOpenerPolicy(coop -> coop.policy(
                                org.springframework.security.web.server.header
                                        .CrossOriginOpenerPolicyServerHttpHeadersWriter
                                        .CrossOriginOpenerPolicy.SAME_ORIGIN))
                        .crossOriginResourcePolicy(corp -> corp.policy(
                                org.springframework.security.web.server.header
                                        .CrossOriginResourcePolicyServerHttpHeadersWriter
                                        .CrossOriginResourcePolicy.SAME_ORIGIN))
                        // X-Frame-Options: DENY + X-Content-Type-Options: nosniff +
                        // Cache-Control are Spring reactive defaults — left implicit
                        // (NOT disabled).
                )
                .oauth2ResourceServer(o -> {
                    // Multi-issuer is OPT-IN: swap to the per-issuer
                    // authentication-manager resolver ONLY when BOTH a resolver was
                    // contributed by TenancyResourceServerConfig AND the registry is
                    // genuinely multi-issuer (more than the single back-compat
                    // entry). Gating on isMultiIssuer() — not merely resolver !=
                    // null — keeps a single-issuer cluster on the EXISTING
                    // jwk-set-uri o.jwt(...) decoder path (no OIDC discovery, the
                    // explicit jwk-set-uri honoured) even if the tenancy conditional
                    // ever activates with just the lone back-compat issuer. In true
                    // multi-brand mode each trusted per-brand Casdoor validates its
                    // own tokens (unknown iss -> 401, fail-closed).
                    ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                            tenantAuthManagerResolver.getIfAvailable();
                    if (resolver != null && domainRegistry.isMultiIssuer()) {
                        o.authenticationManagerResolver(resolver);
                    } else {
                        o.jwt(j -> j.jwtAuthenticationConverter(jwtConverter()));
                    }
                })
                // CSRF stays DISABLED at the gateway — DO NOT re-enable (D6/D8).
                // CSRF defense lives at the COOKIE-TERMINATING admin-bff (the
                // double-submit cookie + X-CSRF header on the httpOnly bff_session
                // is enforced there, where the session cookie is actually minted and
                // read). The gateway is a stateless reverse proxy that authenticates
                // a BEARER token (Authorization header, immune to CSRF by construction
                // — a cross-site form/img can't set it) and brokers long-lived SSE +
                // WebSocket streams (Matrix/Mastodon). Spring's reactive CSRF filter
                // would (1) reject every bearer POST lacking a CSRF token it never
                // issued and (2) break the SSE/WS upgrade handshakes. Re-enabling here
                // therefore breaks bearer auth AND the homeserver streams while adding
                // zero protection the BFF doesn't already provide.
                .csrf(csrf -> csrf.disable())
                .build();
    }

    /**
     * Method-security role hierarchy — SUPERADMIN-only edges. Deliberately
     * MINIMAL: SUPERADMIN is a strict superset of admin/mod/user, but
     * {@code ROLE_ADMIN} and {@code ROLE_MOD} are documented SIBLINGS (no
     * {@code ADMIN > MOD} edge) and the AND-intersection composites
     * ({@code ROLE_GAMES_ADMIN}, {@code ROLE_FORUM_MOD},
     * {@code ROLE_*_EXTERNAL_CLIENT}) are intentionally ABSENT — so a hierarchy
     * can NEVER let a plain ADMIN satisfy an intersection role. The gateway's
     * coarse role gate + the route-access rows + the SUPERADMIN gateway bypass do
     * the actual cross-surface authorization; these edges only apply inside
     * reactive method security ({@code @PreAuthorize}), and only AFTER the
     * gateway's domain match (never crossing domains).
     *
     * <p>This bean merely DEFINES the edges. It is consumed by
     * {@link #methodSecurityExpressionHandler(RoleHierarchy)}, which is what
     * actually makes the hierarchy take effect in {@code @PreAuthorize}:
     * {@code @EnableReactiveMethodSecurity} does NOT auto-wire a stray
     * {@code RoleHierarchy} bean into its expression handler (the framework's
     * default {@code methodSecurityExpressionHandler} sets only the role prefix),
     * so before that handler bean existed these edges were inert for method
     * security.
     */
    @Bean
    RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy(
                "ROLE_SUPERADMIN > ROLE_ADMIN\n" +
                "ROLE_SUPERADMIN > ROLE_MOD\n" +
                "ROLE_SUPERADMIN > ROLE_USER");
    }

    /**
     * Wires {@link #roleHierarchy()} into reactive {@code @PreAuthorize} by
     * supplying the {@code MethodSecurityExpressionHandler} that
     * {@code @EnableReactiveMethodSecurity} consumes (the active
     * {@code ReactiveAuthorizationManagerMethodSecurityConfiguration}). The
     * framework's own default handler builds a bare
     * {@link DefaultMethodSecurityExpressionHandler} and sets ONLY the role
     * prefix — it never reads a {@code RoleHierarchy} bean — so without this
     * handler {@code hasRole('ADMIN')} is evaluated against the principal's RAW
     * authorities and a hierarchy-only {@code ROLE_SUPERADMIN} fails the gate
     * (the historic wave-2 FINDING). Setting the SAME (unchanged) hierarchy on
     * the handler makes the documented cascade {@code SUPERADMIN >= ADMIN >= MOD,
     * USER} actually take effect: a higher role satisfies a lower-role gate, and
     * NOTHING else (USER never climbs to ADMIN; ADMIN/MOD stay siblings).
     *
     * <p>Resolution mechanism (Spring Security 7.x): the active
     * {@code ReactiveAuthorizationManagerMethodSecurityConfiguration} takes an
     * {@code ObjectProvider<MethodSecurityExpressionHandler>} and resolves it with
     * {@code getIfUnique(default)}. The framework's own default handler bean is
     * marked {@code fallback=true}, so it does NOT count toward uniqueness — this
     * (non-fallback) bean is the unique candidate and is selected, WITHOUT a
     * bean-definition-override (the bean is deliberately given a DIFFERENT name
     * than the framework's {@code methodSecurityExpressionHandler}, so there is no
     * name collision and no {@code BeanDefinitionOverrideException}). The handler
     * is declared {@code static} so it is instantiated early enough to be a valid
     * method-security infrastructure bean (mirroring the framework's own
     * {@code static} declaration); the {@link RoleHierarchy} is passed in as a
     * method parameter (resolved from the {@link #roleHierarchy()} bean) rather
     * than referenced through {@code this}.
     */
    @Bean
    static MethodSecurityExpressionHandler gatewayMethodSecurityExpressionHandler(RoleHierarchy roleHierarchy) {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);
        return handler;
    }

    private ReactiveJwtAuthenticationConverter jwtConverter() {
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(casdoorAuthoritiesConverter());
        return converter;
    }

    /**
     * Casdoor JWT -&gt; authorities conversion. Delegates to the shared
     * {@link CasdoorAuthorities} so the single-issuer path here and the optional
     * multi-issuer path ({@link TenancyResourceServerConfig}) stay byte-identical
     * — three claim sources ({@code roles} -&gt; {@code ROLE_<UPPER>},
     * {@code permissions} verbatim, legacy {@code isAdmin} -&gt; {@code ROLE_ADMIN}),
     * a {@code ROLE_USER} floor, plus exactly one issuer-derived
     * {@code DOMAIN_<x>} authority (NON-role; {@code DOMAIN_default} for the
     * single-issuer fallback so this cluster is unchanged).
     */
    private Converter<Jwt, Flux<GrantedAuthority>> casdoorAuthoritiesConverter() {
        return CasdoorAuthorities.converter(domainRegistry,
                new CasdoorAuthorities.MfaConfig(mfaEnabled, mfaFreshnessWindowMillis));
    }
}
