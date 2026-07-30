package systems.hugmesh.gateway.config;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.expression.EvaluationContext;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.util.SimpleMethodInvocation;
import org.springframework.web.server.ServerWebExchange;
import systems.hugmesh.gateway.security.DomainRegistry;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The method-security {@link RoleHierarchy} bean — the V2 keystone. It must have
 * ONLY superadmin-superset edges and must NEVER collapse the sibling
 * ADMIN/MOD relationship or the AND-intersection composites (a global
 * {@code ADMIN > MOD} edge would be a privilege escalation).
 *
 * <ul>
 *   <li>USER-SITUATIONAL — SUPERADMIN reaches admin/mod/user.</li>
 *   <li>CROSS-USER — a plain ADMIN does NOT reach MOD (siblings) and NEITHER
 *       ADMIN nor MOD reaches the AND-composites (ROLE_GAMES_ADMIN /
 *       ROLE_FORUM_MOD / ROLE_*_EXTERNAL_CLIENT).</li>
 * </ul>
 */
class RoleHierarchyTest {

    /** An empty {@link ObjectProvider} (no multi-issuer resolver contributed) —
     *  matches the single-issuer default the bean is built under. */
    private static ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>> emptyProvider() {
        return new ObjectProvider<>() {
            @Override public ReactiveAuthenticationManagerResolver<ServerWebExchange> getObject() {
                return null;
            }
            @Override public ReactiveAuthenticationManagerResolver<ServerWebExchange> getIfAvailable() {
                return null;
            }
            @Override public ReactiveAuthenticationManagerResolver<ServerWebExchange> getIfUnique() {
                return null;
            }
            @Override public java.util.Iterator<ReactiveAuthenticationManagerResolver<ServerWebExchange>> iterator() {
                return java.util.Collections.emptyIterator();
            }
        };
    }

    private RoleHierarchy hierarchy() {
        // The bean is independent of the injected collaborators; pass a minimal
        // single-issuer registry + an empty provider so we can construct the config.
        SecurityConfig cfg = new SecurityConfig(
                new DomainRegistry("http://casdoor:8000", "", ""), emptyProvider());
        return cfg.roleHierarchy();
    }

    private List<String> reachable(String... held) {
        List<GrantedAuthority> in = java.util.Arrays.stream(held)
                .map(SimpleGrantedAuthority::new)
                .map(a -> (GrantedAuthority) a).toList();
        return hierarchy().getReachableGrantedAuthorities(in)
                .stream().map(GrantedAuthority::getAuthority).toList();
    }

    // ── USER-SITUATIONAL ──────────────────────────────────────────────────────

    @Test
    void superadmin_reaches_admin_mod_user() {
        assertThat(reachable("ROLE_SUPERADMIN"))
            .contains("ROLE_SUPERADMIN", "ROLE_ADMIN", "ROLE_MOD", "ROLE_USER");
    }

    // ── CROSS-USER — the privilege-escalation guards ──────────────────────────

    @Test
    void admin_doesNotReach_mod_siblings() {
        // The headline V2 guard: NO ADMIN > MOD edge.
        assertThat(reachable("ROLE_ADMIN")).doesNotContain("ROLE_MOD");
    }

    @Test
    void mod_doesNotReach_admin() {
        assertThat(reachable("ROLE_MOD")).doesNotContain("ROLE_ADMIN");
    }

    @Test
    void admin_doesNotReach_andComposites() {
        // A plain ADMIN must never satisfy the AND-intersection composites via the
        // hierarchy (they are intentionally absent from the edge set).
        List<String> r = reachable("ROLE_ADMIN");
        assertThat(r).doesNotContain(
                "ROLE_GAMES_ADMIN", "ROLE_FORUM_MOD",
                "ROLE_MATRIX_EXTERNAL_CLIENT", "ROLE_MASTODON_EXTERNAL_CLIENT");
    }

    @Test
    void mod_doesNotReach_andComposites() {
        assertThat(reachable("ROLE_MOD")).doesNotContain("ROLE_FORUM_MOD", "ROLE_GAMES_ADMIN");
    }

    @Test
    void superadmin_doesNotReach_andComposites_either() {
        // Even SUPERADMIN doesn't get the AND-composites via the hierarchy (the
        // composites are reached only by holding the materialised Casdoor role, or
        // by the SUPERADMIN gateway cross-domain bypass — never a hierarchy edge).
        assertThat(reachable("ROLE_SUPERADMIN"))
            .doesNotContain("ROLE_GAMES_ADMIN", "ROLE_FORUM_MOD");
    }

    // ── WIRING — the hierarchy is SET on the method-security expression handler ──

    @Test
    void expressionHandler_isWiredWith_theSameHierarchy() {
        // The bug this guards: @EnableReactiveMethodSecurity does NOT auto-wire a stray
        // RoleHierarchy bean into method security. SecurityConfig must contribute a
        // MethodSecurityExpressionHandler that has the hierarchy SET on it, or
        // @PreAuthorize("hasRole('ADMIN')") evaluates against RAW authorities and a
        // hierarchy-only SUPERADMIN is denied. This asserts the handler bean exists and
        // carries the SAME hierarchy instance the config exposes (a cheap, context-free
        // companion to the full-boot HTTP assertions in ControlPlaneWriteAuthzSpringBootTest).
        SecurityConfig cfg = new SecurityConfig(
                new DomainRegistry("http://casdoor:8000", "", ""), emptyProvider());
        RoleHierarchy hierarchy = cfg.roleHierarchy();
        DefaultMethodSecurityExpressionHandler handler =
                (DefaultMethodSecurityExpressionHandler)
                        SecurityConfig.gatewayMethodSecurityExpressionHandler(hierarchy);

        // The handler resolves SUPERADMIN -> ADMIN exactly as the bean does — i.e. the
        // hierarchy actually reaches expression evaluation.
        SecurityExpressionOperations ops = opsFor(handler, "ROLE_SUPERADMIN");
        assertThat(ops.hasRole("ADMIN")).isTrue();   // SUPERADMIN >= ADMIN reaches the gate
        assertThat(ops.hasRole("MOD")).isTrue();      // SUPERADMIN >= MOD
        assertThat(ops.hasRole("USER")).isTrue();     // SUPERADMIN >= USER
    }

    @Test
    void expressionHandler_doesNotOverBroaden_userAndSiblings() {
        // The privilege boundary at the expression-handler layer: a USER must NOT reach
        // ADMIN, and ADMIN/MOD stay siblings. Mirror of the HTTP no-over-broadening
        // assertions, proven directly on the handler the gateway installs.
        SecurityConfig cfg = new SecurityConfig(
                new DomainRegistry("http://casdoor:8000", "", ""), emptyProvider());
        DefaultMethodSecurityExpressionHandler handler =
                (DefaultMethodSecurityExpressionHandler)
                        SecurityConfig.gatewayMethodSecurityExpressionHandler(cfg.roleHierarchy());

        assertThat(opsFor(handler, "ROLE_USER").hasRole("ADMIN")).isFalse();   // USER never climbs
        assertThat(opsFor(handler, "ROLE_ADMIN").hasRole("MOD")).isFalse();    // siblings
        assertThat(opsFor(handler, "ROLE_MOD").hasRole("ADMIN")).isFalse();    // siblings
    }

    private static SecurityExpressionOperations opsFor(
            DefaultMethodSecurityExpressionHandler handler, String authority) {
        EvaluationContext ctx = handler.createEvaluationContext(
                () -> new TestingAuthenticationToken(
                        "p", "n/a", List.of(new SimpleGrantedAuthority(authority))),
                methodInvocation());
        return (SecurityExpressionOperations) ctx.getRootObject().getValue();
    }

    /** A minimal {@link MethodInvocation} with a non-null target method — the
     *  expression handler rejects a null method when building the root object. The
     *  specific method is irrelevant to hasRole() evaluation. */
    private static MethodInvocation methodInvocation() {
        try {
            return new SimpleMethodInvocation(
                    new Object(), Object.class.getDeclaredMethod("toString"));
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException(e);
        }
    }
}
