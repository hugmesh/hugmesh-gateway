package net.hugmesh.gateway.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The OPT-IN anonymous permit for the hugmesh-games {@code banned} federated remote
 * ({@code /_remotes/banned/**}).
 *
 * <p><b>Why it exists.</b> hugmesh-games ships a {@code banned} remote: its frontend
 * nginx proxies {@code /_remotes/banned/} to a {@code banned} container, and its
 * changelog 039 registers {@code /_remotes/banned/remoteEntry.json} as a
 * {@code requires=PUBLIC} federation module. The games host
 * ({@code games.<domain>}) is routed through the be-tier instance of this gateway.
 * So the prefix is not dead everywhere.
 *
 * <p><b>Why it is off by default.</b> No other product serves that prefix. On every
 * gateway that does not front games, an anonymous permit there opens whatever is
 * later mounted at it with no login. And on the be tier that does front games, the
 * games shell itself cannot use the permit for an anonymous visitor: the coarse floor
 * 401s that visitor on {@code /} and on {@code /api/federation/manifest} (the
 * manifest the games shell fetches with {@code credentials: 'omit'} before it wires
 * any remote), and games' own {@code /banned} route is a local component. Those two
 * facts are pinned by {@code SecurityConfigPathGateSliceTest}.
 *
 * <p><b>One switch, two lists.</b> {@value #PROPERTY} turns the permit on in BOTH
 * places it was on before: the coarse {@code permitAll} list in {@link SecurityConfig}
 * and the bff_ introspection skip list ({@code BffSessionAuthFilter}). A permit alone
 * would not restore the old behaviour: a revoked player's {@code bff_} cookie would
 * still be introspected there, and the revocation filter would answer 403.
 *
 * <p><b>Fail-closed parsing.</b> Only the literal {@code true} (any case, surrounding
 * blanks ignored) turns it on. Blank, missing, {@code yes}, {@code 1}, {@code on} and
 * any typo leave it off.
 */
public final class BannedRemotePermit {

    /** The single switch. Env form: {@code APP_SECURITY_BANNED_REMOTE_PUBLIC}. */
    public static final String PROPERTY = "app.security.banned-remote-public";

    /** The prefix the permit opens, in the same Ant/PathPattern form as its siblings. */
    public static final String PATTERN = "/_remotes/banned/**";

    private BannedRemotePermit() {
    }

    /** {@code true} only for the literal {@code true}, case-insensitive, trimmed. */
    public static boolean enabled(String raw) {
        return raw != null && raw.trim().equalsIgnoreCase("true");
    }

    /** {@code base}, plus {@link #PATTERN} when {@code on} (never duplicated). */
    static String[] publicPaths(String[] base, boolean on) {
        List<String> out = new ArrayList<>(Arrays.asList(base));
        if (on && !out.contains(PATTERN)) out.add(PATTERN);
        return out.toArray(String[]::new);
    }

    /** {@code base}, plus {@link #PATTERN} when {@code on} (never duplicated). */
    public static List<String> skipPaths(List<String> base, boolean on) {
        List<String> out = new ArrayList<>(base);
        if (on && !out.contains(PATTERN)) out.add(PATTERN);
        return List.copyOf(out);
    }
}
