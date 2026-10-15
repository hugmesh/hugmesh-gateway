package net.hugmesh.gateway.config;

import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.handler.predicate.PredicateDefinition;
import org.springframework.cloud.gateway.route.RouteDefinition;

import java.net.URI;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit pins for the pki-tier headscale Host gate's two pure pieces (decision 79 = B,
 * hugmesh-admin-bff-api#57): where the host comes from
 * ({@link SecurityConfig#deriveHeadscaleHostPatterns}) and what it matches
 * ({@link SecurityConfig#isHeadscaleHost}). The end-to-end verdicts (403/401/200
 * through the real filter chain) live in
 * {@code PkiHeadscaleControlPlaneAuthzSpringBootTest}.
 */
class SecurityConfigHeadscaleHostGateTest {

    private static RouteDefinition route(String id, String... predicates) {
        RouteDefinition r = new RouteDefinition();
        r.setId(id);
        r.setUri(URI.create("http://127.0.0.1:9"));
        for (String p : predicates) r.getPredicates().add(new PredicateDefinition(p));
        return r;
    }

    /** The shape hugmesh-pki-gateway application-pki.yml:40-43 declares. */
    private static List<RouteDefinition> pkiRoutes(String headscaleHost) {
        return List.of(
                route("casdoor-auth", "Path=/api/auth/**"),
                route("casdoor-login", "Path=/login/**"),
                route("casdoor-oidc", "Path=/.well-known/**"),
                route("headscale", "Host=" + headscaleHost));
    }

    // ── derivation ───────────────────────────────────────────────────────────────

    @Test
    void pkiTier_derivesTheHostFromTheHeadscaleRoute_notAHandKeptCopy() {
        assertThat(SecurityConfig.deriveHeadscaleHostPatterns("hugmesh-pki-gateway",
                pkiRoutes("scale.hugmesh.net")))
            .containsExactly("scale.hugmesh.net");
        // A rebranded route is followed, not the historical literal.
        assertThat(SecurityConfig.deriveHeadscaleHostPatterns("hugmesh-pki-gateway",
                pkiRoutes("scale.example.org")))
            .containsExactly("scale.example.org");
    }

    @Test
    void perBrandPkiInstance_isPkiTierToo() {
        assertThat(SecurityConfig.deriveHeadscaleHostPatterns("brandx-pki-gateway",
                pkiRoutes("scale.brandx.example")))
            .containsExactly("scale.brandx.example");
    }

    @Test
    void everyHostArgument_isRead_shortcutListAndLongForm() {
        assertThat(SecurityConfig.deriveHeadscaleHostPatterns("hugmesh-pki-gateway",
                List.of(route("headscale", "Host=scale.a.example,Scale.B.example"))))
            .containsExactly("scale.a.example", "scale.b.example");

        RouteDefinition longForm = new RouteDefinition();
        longForm.setId("headscale");
        longForm.setUri(URI.create("http://127.0.0.1:9"));
        PredicateDefinition host = new PredicateDefinition();
        host.setName("Host");
        host.setArgs(new java.util.LinkedHashMap<>(Map.of("patterns", "scale.c.example")));
        longForm.getPredicates().add(host);
        assertThat(SecurityConfig.deriveHeadscaleHostPatterns("hugmesh-pki-gateway", List.of(longForm)))
            .containsExactly("scale.c.example");
    }

    @Test
    void otherTiers_neverArmTheGate_evenWithAHeadscaleRoute() {
        // The be gateway carries a `headscale-forward` route on the same Host; a
        // route literally named `headscale` on another tier must not arm it either.
        for (String name : List.of("hugmesh-be-gateway", "hugmesh-fe-gateway", "brandx-be-gateway",
                "", "unknown-gateway")) {
            assertThat(SecurityConfig.deriveHeadscaleHostPatterns(name, pkiRoutes("scale.hugmesh.net")))
                .as("tier %s", name)
                .isEmpty();
        }
        assertThat(SecurityConfig.deriveHeadscaleHostPatterns(null, pkiRoutes("scale.hugmesh.net")))
            .isEmpty();
    }

    @Test
    void pkiTier_withoutAHeadscaleRoute_hasNoGate_andStarts() {
        assertThat(SecurityConfig.deriveHeadscaleHostPatterns("hugmesh-pki-gateway",
                List.of(route("casdoor-auth", "Path=/api/auth/**"),
                        route("headscale-forward", "Host=scale.hugmesh.net"))))
            .isEmpty();
        assertThat(SecurityConfig.deriveHeadscaleHostPatterns("hugmesh-pki-gateway", List.of()))
            .isEmpty();
    }

    @Test
    void pkiTier_headscaleRouteWithNoHostPredicate_failsStartup() {
        assertThatThrownBy(() -> SecurityConfig.deriveHeadscaleHostPatterns("hugmesh-pki-gateway",
                List.of(route("headscale", "Path=/**"))))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("headscale");
    }

    @Test
    void pkiTier_headscaleRouteWithABlankHost_failsStartup() {
        RouteDefinition blank = new RouteDefinition();
        blank.setId("headscale");
        blank.setUri(URI.create("http://127.0.0.1:9"));
        PredicateDefinition host = new PredicateDefinition();
        host.setName("Host");
        host.setArgs(new java.util.LinkedHashMap<>(Map.of("_genkey_0", "  ")));
        blank.getPredicates().add(host);
        assertThatThrownBy(() -> SecurityConfig.deriveHeadscaleHostPatterns("hugmesh-pki-gateway",
                List.of(blank)))
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void theConstructor_itselfFailsStartup_onAnUnderivableHeadscaleHost() {
        // The throw must reach bean creation, not just the helper.
        assertThatThrownBy(() -> new SecurityConfig(
                new net.hugmesh.gateway.security.DomainRegistry("http://casdoor:8000", "", ""),
                null, "hugmesh-pki-gateway", false, 600_000L,
                List.of(route("headscale", "Path=/**"))))
            .isInstanceOf(IllegalStateException.class);
        assertThat(new SecurityConfig(
                new net.hugmesh.gateway.security.DomainRegistry("http://casdoor:8000", "", ""),
                null, "hugmesh-pki-gateway", false, 600_000L,
                pkiRoutes("scale.hugmesh.net")).headscaleHostPatterns())
            .containsExactly("scale.hugmesh.net");
    }

    // ── matching ─────────────────────────────────────────────────────────────────

    private static final List<String> SCALE = List.of("scale.hugmesh.net");

    @Test
    void matches_theHost_withAPort_anyCase_andARootDot() {
        for (String h : List.of("scale.hugmesh.net", "scale.hugmesh.net:443", "SCALE.Hugmesh.NET",
                "scale.hugmesh.net.", "scale.hugmesh.net.:8080", " scale.hugmesh.net ")) {
            assertThat(SecurityConfig.isHeadscaleHost(SCALE, h)).as(h).isTrue();
        }
    }

    @Test
    void doesNotMatch_otherHosts_includingLookAlikes() {
        for (String h : List.of("hugmesh.net", "id.hugmesh.net", "evilscale.hugmesh.net",
                "scale.hugmesh.net.evil.example", "xscale.hugmesh.net:443", "scale.hugmesh.network",
                "[::1]:8080", "", "scale")) {
            assertThat(SecurityConfig.isHeadscaleHost(SCALE, h)).as(h).isFalse();
        }
        assertThat(SecurityConfig.isHeadscaleHost(SCALE, null)).isFalse();
        assertThat(SecurityConfig.isHeadscaleHost(List.of(), "scale.hugmesh.net")).isFalse();
    }

    @Test
    void hostPatterns_useTheRoutePredicatesAntSyntax() {
        // HostRoutePredicateFactory accepts Ant patterns with '.' as the separator.
        List<String> wildcard = List.of("scale.**");
        assertThat(SecurityConfig.isHeadscaleHost(wildcard, "scale.brandx.example")).isTrue();
        assertThat(SecurityConfig.isHeadscaleHost(wildcard, "id.brandx.example")).isFalse();
    }
}
