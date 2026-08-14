package net.hugmesh.gateway.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.gateway.security.DomainRegistry;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * CONFIG-GATED, backward-compatible multi-issuer (per-brand Casdoor) wiring.
 *
 * <p>Contributes a per-issuer {@link ReactiveAuthenticationManagerResolver}
 * ONLY when {@code app.tenancy.issuers} actually carries issuer=domain pairs (the
 * {@code .contains('=')} guard) — NOT merely when the property is "present" with
 * the empty {@code ${APP_TENANCY_ISSUERS:}} default, which a bare
 * {@code @ConditionalOnProperty(name=...)} would have treated as present-and-true
 * and so ALWAYS activated. {@link SecurityConfig} additionally only swaps onto
 * this resolver when {@link DomainRegistry#isMultiIssuer()} (more than the lone
 * back-compat entry), so a single-issuer cluster keeps the existing single
 * {@code o.jwt(...)} jwk-set-uri path verbatim and is byte-for-byte unchanged.
 *
 * <p><b>Fail-closed on unknown issuer.</b> The resolver's allowlist is exactly
 * {@link DomainRegistry#trustedIssuers()} (the configured per-brand Casdoors). A
 * token whose {@code iss} is not in that set gets NO manager and 401s before any
 * authority is emitted.
 *
 * <p><b>Custom converter preserved per issuer.</b> {@code fromTrustedIssuers}'s
 * built-in managers use the DEFAULT authorities converter and would NOT emit the
 * {@code DOMAIN_<x>} authority. So we build each per-issuer
 * {@link JwtReactiveAuthenticationManager} ourselves from
 * {@link ReactiveJwtDecoders#fromIssuerLocation} (which applies the standard
 * exp/nbf + iss-binding validators) and set the SAME Casdoor authorities
 * converter on it — identical authority output to the single-issuer path, plus
 * the issuer-derived {@code DOMAIN_<x>}.
 */
@Configuration
// Fire ONLY when app.tenancy.issuers genuinely carries issuer=domain pairs. The
// '=' guard makes the empty ${APP_TENANCY_ISSUERS:} default a no-op: an empty
// string is "present and not false" to @ConditionalOnProperty, which would have
// activated this bean (and silently routed single-issuer clusters through the
// resolver / OIDC discovery). A valid CSV always contains at least one '='.
@ConditionalOnExpression("'${app.tenancy.issuers:}'.contains('=')")
public class TenancyResourceServerConfig {

    private final DomainRegistry domainRegistry;

    /** Explicit issuer-uri of the lone back-compat issuer (the single-issuer
     *  {@code spring.security.oauth2.resourceserver.jwt.issuer-uri}). Paired with
     *  {@link #backCompatJwkSetUri} to build a discovery-free decoder for it. */
    private final String backCompatIssuer;

    /** Explicit jwk-set-uri of the lone back-compat issuer — used to build the
     *  per-issuer decoder WITHOUT OIDC discovery (same no-network profile as the
     *  single-issuer {@code o.jwt(...)} path), so if this resolver is ever wired
     *  for a single back-compat issuer, validation stays discovery-free. Empty on
     *  pure multi-brand configs (each brand decoder discovers from its own iss). */
    private final String backCompatJwkSetUri;

    /** D8 MFA marker derivation — {@code app.mfa.enabled} (default {@code false}).
     *  MUST stay in lockstep with the single-issuer {@link SecurityConfig} so a
     *  token maps to the SAME authorities (incl. {@code MFA_SATISFIED}) regardless
     *  of which decoder path validated it. */
    private final boolean mfaEnabled;

    /** D8 MFA freshness window in millis — {@code app.mfa.freshness-window}
     *  (default 10m). Same key + default as {@link SecurityConfig}. */
    private final long mfaFreshnessWindowMillis;

    @Autowired
    public TenancyResourceServerConfig(
            DomainRegistry domainRegistry,
            @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri:}") String backCompatIssuer,
            @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri:}") String backCompatJwkSetUri,
            @Value("${app.mfa.enabled:false}") boolean mfaEnabled,
            @Value("${app.mfa.freshness-window:600000}") long mfaFreshnessWindowMillis) {
        this.domainRegistry = domainRegistry;
        this.backCompatIssuer = trimSlash(backCompatIssuer);
        this.backCompatJwkSetUri = backCompatJwkSetUri == null ? "" : backCompatJwkSetUri.trim();
        this.mfaEnabled = mfaEnabled;
        this.mfaFreshnessWindowMillis = mfaFreshnessWindowMillis;
    }

    /** Legacy convenience (MFA derivation OFF, default 10m window) — keeps the
     *  pre-D8 slice tests compiling. Production uses the {@code @Autowired}
     *  constructor above. */
    public TenancyResourceServerConfig(
            DomainRegistry domainRegistry,
            String backCompatIssuer,
            String backCompatJwkSetUri) {
        this(domainRegistry, backCompatIssuer, backCompatJwkSetUri, false, 600_000L);
    }

    private static String trimSlash(String s) {
        if (s == null) return "";
        String t = s.trim();
        return t.endsWith("/") ? t.substring(0, t.length() - 1) : t;
    }

    @Bean
    ReactiveAuthenticationManagerResolver<ServerWebExchange> tenantAuthManagerResolver() {
        // Cache one manager per trusted issuer (decoder construction does network
        // discovery — build lazily on first sight, never per request).
        Map<String, ReactiveAuthenticationManager> byIssuer = new ConcurrentHashMap<>();

        // Per-issuer resolver: ONLY trusted issuers (registry keys) get a manager;
        // an unknown iss yields Mono.empty() -> 401 (fail-closed).
        ReactiveAuthenticationManagerResolver<String> byIssuerResolver =
                byIssuerResolver(byIssuer);

        JwtIssuerReactiveAuthenticationManagerResolver delegate =
                new JwtIssuerReactiveAuthenticationManagerResolver(byIssuerResolver);
        return delegate::resolve;
    }

    /** Per-issuer resolver: maps a token's {@code iss} to its cached manager, or
     *  {@code Mono.empty()} (-> 401) when the issuer is not on the allowlist.
     *  Package-private rather than inlined so the fail-closed contract is unit
     *  testable without a Spring context or a synthetic exchange. */
    ReactiveAuthenticationManagerResolver<String> byIssuerResolver(
            Map<String, ReactiveAuthenticationManager> byIssuer) {
        return issuer -> {
            String iss = trustedIssuerOrNull(issuer);
            if (iss == null) {
                return Mono.empty();
            }
            return Mono.just(byIssuer.computeIfAbsent(iss, this::managerForIssuer));
        };
    }

    /**
     * Resolve {@code issuer} to its canonical entry in the trusted-issuer allowlist,
     * or {@code null} when it is not trusted.
     *
     * <p>Deliberately strict membership of a NON-EMPTY {@link DomainRegistry#trustedIssuers()}
     * rather than {@link DomainRegistry#isTrusted}: the latter delegates to
     * {@code domainOf}, which short-circuits to the legacy single-tenant "default"
     * WITHOUT inspecting its argument on an empty registry — i.e. it answers "trusted"
     * for any string at all, including an attacker-chosen issuer. Reaching
     * {@code decoderForIssuer} with an attacker-chosen {@code iss} would mean OIDC
     * discovery against an attacker-controlled URL.
     *
     * <p>That empty-registry state is REACHABLE: {@code app.tenancy.issuers=&#61;brand}
     * satisfies this class's {@code @ConditionalOnExpression} {@code .contains('=')}
     * guard (bean ACTIVE) yet parses to zero valid pairs (the {@code eq <= 0} skip),
     * and with no {@code jwt.issuer-uri} to seed the back-compat entry the map stays
     * empty. Today the SecurityConfig swap-in is gated on
     * {@link DomainRegistry#isMultiIssuer()} (false for an empty map), so this is
     * latent — but that gate is a caller's discipline, not this class's guarantee.
     * Fail closed here instead.
     *
     * <p>Does NOT change {@code domainOf}'s legacy fail-open, which stays load-bearing
     * for legacy single-tenant clusters.
     */
    private String trustedIssuerOrNull(String issuer) {
        if (issuer == null) return null;
        Set<String> trusted = domainRegistry.trustedIssuers();
        // Empty (or absent) allowlist: deny. Never fall back to a default.
        if (trusted == null || trusted.isEmpty()) return null;
        String candidate = trimSlash(issuer);
        if (candidate.isEmpty()) return null;
        for (String t : trusted) {
            // Return the SET's element so the cache key is canonical: "https://x" and
            // "https://x/" share one manager instead of a duplicate per variant.
            if (t != null && t.equals(candidate)) return t;
        }
        return null;
    }

    /** Build the per-issuer manager wired to the SAME Casdoor authorities
     *  converter the single-issuer path uses, so the {@code DOMAIN_<x>} authority
     *  is emitted in multi-issuer mode too.
     *
     *  <p>Decoder choice (equivalence hardening): for the LONE back-compat issuer
     *  (the one carrying a configured {@code jwk-set-uri}) the decoder is built
     *  DIRECTLY from that jwk-set-uri — {@code NimbusReactiveJwtDecoder.withJwkSetUri}
     *  plus the default exp/nbf validators AND an explicit {@code iss} validator —
     *  so it has the SAME no-OIDC-discovery network profile as {@code main}'s
     *  single-issuer {@code o.jwt(...)} path (which builds straight from
     *  jwk-set-uri). Per-BRAND issuers (no matching jwk-set-uri) fall back to
     *  {@link ReactiveJwtDecoders#fromIssuerLocation} (OIDC discovery), which is the
     *  correct behaviour for a genuinely multi-brand deployment that did not
     *  pre-declare each brand's JWKS endpoint. */
    private ReactiveAuthenticationManager managerForIssuer(String issuer) {
        JwtReactiveAuthenticationManager mgr =
                new JwtReactiveAuthenticationManager(decoderForIssuer(issuer));
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter());
        mgr.setJwtAuthenticationConverter(converter);
        return mgr;
    }

    /** Decoder for an issuer. The lone back-compat issuer (the one with a
     *  configured jwk-set-uri) gets a discovery-free {@code withJwkSetUri} decoder
     *  + the standard exp/nbf validators + an {@code iss}-binding validator — the
     *  SAME validation surface and no-network profile as the single-issuer path.
     *  Any other (per-brand) issuer uses {@code fromIssuerLocation} discovery. */
    private ReactiveJwtDecoder decoderForIssuer(String issuer) {
        String iss = trimSlash(issuer);
        if (!backCompatJwkSetUri.isEmpty() && !backCompatIssuer.isEmpty()
                && backCompatIssuer.equals(iss)) {
            NimbusReactiveJwtDecoder decoder =
                    NimbusReactiveJwtDecoder.withJwkSetUri(backCompatJwkSetUri).build();
            // Default validators (exp/nbf + the standard set) PLUS an explicit iss
            // validator so a token's `iss` must equal the configured issuer — the
            // equivalent binding fromIssuerLocation would have applied, without the
            // discovery round-trip.
            OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(iss);
            decoder.setJwtValidator(withIssuer);
            return decoder;
        }
        return ReactiveJwtDecoders.fromIssuerLocation(iss);
    }

    /** The Casdoor authorities converter — identical shape to
     *  {@code SecurityConfig.casdoorAuthoritiesConverter()} (kept in sync so a
     *  token maps to the same authorities regardless of which decoder path
     *  validated it), with the issuer-derived {@code DOMAIN_<x>} added. */
    private Converter<Jwt, Flux<GrantedAuthority>> authoritiesConverter() {
        return CasdoorAuthorities.converter(domainRegistry,
                new CasdoorAuthorities.MfaConfig(mfaEnabled, mfaFreshnessWindowMillis));
    }
}
