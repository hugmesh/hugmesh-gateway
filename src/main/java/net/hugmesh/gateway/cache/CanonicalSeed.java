package net.hugmesh.gateway.cache;

import net.hugmesh.gateway.cache.GatewayRouteAccessService.Rule;

import java.util.List;
import java.util.Set;

/**
 * The canonical {@code gateway_route_access} seed from the route-access
 * contract, baked into the image so a gateway enforces sane defaults even
 * before (or without) a Postgres/Cassandra round-trip — the gate is never
 * silently fail-open.
 *
 * <p>The same rows live in the cluster's Postgres seed
 * ({@code cluster/manifests/route-access/schema.sql}); this in-memory copy is
 * the floor used when neither datastore is reachable. Once Postgres/Cassandra
 * answer, the loaded rows replace this snapshot wholesale.
 *
 * <p>Roles are Spring authorities ({@code ROLE_USER}, {@code ROLE_ADMIN}) or the
 * sentinel {@code PUBLIC} (anonymous-allowed). {@code **} is Ant-style.
 */
final class CanonicalSeed {

    private CanonicalSeed() {}

    static final String PKI = "hugmesh-pki-gateway";
    static final String BE = "hugmesh-be-gateway";
    static final String FE = "hugmesh-fe-gateway";

    /** Sentinel gateway name used for the closed deny-floor when the instance
     *  name is absent/blank — so the floor row still carries a stable,
     *  non-null {@code gateway} value and a recognisable id. */
    static final String UNKNOWN = "unknown-gateway";

    /** Rules for {@code gateway} from the canonical seed. The three canonical
     *  names hit their tier directly; a per-brand instance name
     *  ({@code ${BRAND}-{pki,be,fe}-gateway}) derives its tier by SUFFIX and a
     *  truly unknown name gets a CLOSED-BY-DEFAULT floor — never the old
     *  fail-open {@code List.of()} (V7). A {@code null}/blank application name is
     *  ALSO closed-by-default (it falls through to the same deny-floor as an
     *  unknown name) so a misconfigured {@code spring.application.name} can NEVER
     *  leave the gate fail-open with an empty rule set. */
    static List<Rule> forGateway(String gateway) {
        if (gateway == null || gateway.isBlank()) return bySuffix(UNKNOWN);
        return switch (gateway) {
            case PKI -> pki();
            case BE -> be();
            case FE -> fe();
            default -> bySuffix(gateway);   // per-brand instances ${BRAND}-{pki,be,fe}-gateway
        };
    }

    /**
     * Per-brand instance names follow {@code ${BRAND}-{pki,be,fe}-gateway}.
     * Derive the tier from the suffix and reuse that tier's seed so a
     * runtime-added brand gateway is CLOSED-by-default (its own tier floor) until
     * the Postgres rows load — never fail-open (V7). A truly unknown suffix gets a
     * single deny-all-ungranted floor so no path is silently ungoverned.
     */
    private static List<Rule> bySuffix(String gateway) {
        if (gateway.endsWith("-pki-gateway")) return pki();
        if (gateway.endsWith("-be-gateway"))  return be();
        if (gateway.endsWith("-fe-gateway"))  return fe();
        // Truly unknown gateway: a closed floor (only ADMIN reaches anything)
        // so no path is silently ungoverned before Postgres rows load.
        return List.of(r(gateway, "/**", "ROLE_ADMIN"));
    }

    /**
     * DECISION 56 = "a declared set of privileged rows" (hugmesh-generator#347,
     * operator answer 2026-09-18; option 2 of the three named on
     * hugmesh-gateway#35, which hugmesh-generator#244 comment 2026-09-18T03:52Z
     * left open as decision 41's residual). D8's default — the baked floor NEVER
     * demands a second factor — stays the default for every row {@link #r} builds
     * EXCEPT the ones named here. Bounding it to a small, explicit set (rather
     * than "every row that carries it in Postgres", option 3) keeps the lock-out
     * risk D8 exists to avoid bounded to surfaces an operator can name and review.
     *
     * <p><b>DERIVED, not invented</b> — the intersection of two things measured
     * against generator {@code origin/main} @ {@code fefd5084} and this repo's
     * merged tree (hugmesh-gateway#33, decision 41, folded in alongside this
     * change) on 2026-09-18:
     * <ol>
     *   <li>every {@code ALLOW} row the cluster Postgres seed's blanket flip UPDATE
     *       (generator {@code specs/cluster/manifests/route-access/initdb/
     *       20-schema.sql}, the statement right after the decision-28 row-scoped
     *       one) sets {@code mfa_required = true} on — its predicate is
     *       {@code allow = true AND (url_pattern = '/bff/admin' OR url_pattern LIKE
     *       '/bff/admin/%' OR url_pattern = '/bff/superadmin' OR url_pattern LIKE
     *       '/bff/superadmin/%')}; AND
     *   <li>the rows {@link #be()} / {@link #fe()} actually bake, i.e. this set
     *       names no row {@link #r} is never called with.
     * </ol>
     *
     * <pre>
     *   be():  /bff/superadmin/**                ROLE_SUPERADMIN
     *   fe():  /bff/admin/phone-fleet/**         ROLE_FLEET_ADMIN
     *   fe():  /bff/admin/phone-fleet/**         ROLE_ADMIN
     *   fe():  /bff/admin/phone-fleet/**         ROLE_SUPERADMIN
     *   fe():  /bff/admin/**                     ROLE_ADMIN
     *   fe():  /bff/superadmin/**                ROLE_SUPERADMIN   (decision 41)
     * </pre>
     *
     * <p><b>Deliberately NOT in the set</b> (so a future "obviously belongs"
     * addition has to argue past this, not slip in):
     * <ul>
     *   <li>{@code pki()}'s {@code /** -> ROLE_SUPERADMIN} headscale catch-all and
     *       {@code be()}'s {@code /bff/image-builds/arch/** -> ROLE_SUPERADMIN} —
     *       neither pattern is under the two prefixes the blanket flip touches, so
     *       their Postgres counterparts are {@code mfa_required=false} too;
     *   <li>the {@code fe} {@code /bff/superadmin/games-services/**} DENY row
     *       (decision 28 = D) — it is {@code mfa_required=true} in the CLUSTER
     *       seed, but {@link #decide} raises {@code mfaRequiredOnGrant} only from
     *       rows that GRANT (deny rows can never raise it), decision 41 forbids
     *       baking it into the floor at all (D8 would carry the wall without the
     *       floor — see the {@link #fe()} row comment), and this decision does not
     *       authorise mirroring it either — asked and answered NO on
     *       hugmesh-generator#347: this mechanism WOULD let a future edit declare
     *       it (it is an {@code ALLOW}-row-only gate, not a deny-row gate, so
     *       declaring a deny row here would be inert by construction, not merely
     *       unauthorised), and it is not done.
     * </ul>
     *
     * <p>Entries are {@link Rule#id()} strings — the exact {@code "seed:" +
     * gateway + ":" + pattern + ":" + role} {@link #r} below computes — so a typo
     * here is simply never matched rather than silently mis-targeting a different
     * row; {@code canonicalSeed_mfaRequiredFallbackRows_everyEntryMatchesARealBakedRow}
     * pins that every entry actually is a row {@link #forGateway} emits somewhere.
     */
    static final Set<String> MFA_REQUIRED_FALLBACK_ROWS = Set.of(
            "seed:" + BE + ":/bff/superadmin/**:ROLE_SUPERADMIN",
            "seed:" + FE + ":/bff/admin/phone-fleet/**:ROLE_FLEET_ADMIN",
            "seed:" + FE + ":/bff/admin/phone-fleet/**:ROLE_ADMIN",
            "seed:" + FE + ":/bff/admin/phone-fleet/**:ROLE_SUPERADMIN",
            "seed:" + FE + ":/bff/admin/**:ROLE_ADMIN",
            "seed:" + FE + ":/bff/superadmin/**:ROLE_SUPERADMIN");

    private static Rule r(String gateway, String pattern, String role) {
        // domain=null => UNSCOPED (applies to any target brand). The baked-in seed
        // is the per-tier floor; per-brand domain scoping is carried only by the
        // admin-managed Postgres rows.
        //
        // mfaRequired (D8, narrowed by decision 56): false for every row EXCEPT
        // the ones named in MFA_REQUIRED_FALLBACK_ROWS above, which carry true.
        // This is the gateway HALF of the dual-write trio — it MUST match the
        // generator Postgres seed's blanket-flip predicate in
        // specs/cluster/manifests/route-access/initdb/20-schema.sql (restricted to
        // rows CanonicalSeed actually bakes) AND the admin-bff
        // 001-gateway-route-access.xml copy (DDL only — no seed rows to match).
        // Keeping every OTHER row false means a datastore-unreachable fallback can
        // never accidentally lock out a surface nobody declared; mfa_required is
        // enabled per-row beyond this declared set only by an admin-managed
        // Postgres row.
        String id = "seed:" + gateway + ":" + pattern + ":" + role;
        boolean mfaRequired = MFA_REQUIRED_FALLBACK_ROWS.contains(id);
        return new Rule(id, gateway, pattern, role, null, true, null, mfaRequired);
    }

    /**
     * An explicit {@code allow=false} row — the seed counterpart of the Postgres
     * {@code gateway_route_access.allow} column's {@code false} value, same shape
     * as {@link #r} in every other respect (unscoped domain, no casdoor_user pin,
     * {@code mfa_required=false}).
     *
     * <p><b>Why a deny row is genuinely enforced here.</b>
     * {@link GatewayRouteAccessService#decide} picks the LONGEST matching
     * {@code url_pattern} and evaluates only the rows at that length: an
     * {@code allow=false} row whose role the principal HOLDS sets {@code
     * explicitDeny} (deny-wins, returned before any grant), and a principal that
     * does NOT hold the role simply finds no granting row at the longest pattern,
     * so the path is governed-but-ungranted ⇒ DENY as well. Either way the answer
     * is {@link GatewayRouteAccessService.Decision#DENY}, which the
     * {@code GatewayRouteAccessFilter} turns into a 403. That is strictly stronger
     * than leaving the path out of the seed: an UNMATCHED path yields
     * {@code NO_RULE}, and NO_RULE FORWARDS on the coarse {@code authenticated()}
     * floor.
     *
     * <p>The id carries a {@code :deny} discriminator so a deny row can never
     * collide with an allow row for the same gateway/pattern/role.
     *
     * <p>NOTE the two principals a deny row cannot stop, by design and unchanged
     * here: {@code ROLE_SUPERADMIN} and {@code ROLE_ADMIN}/{@code ROLE_GAME-MASTER}
     * short-circuit in {@code GatewayRouteAccessFilter} BEFORE {@code decide()} is
     * consulted. The service-only surfaces below rely on their OWN app-side
     * {@code SERVICE} authorization for that tier; the row closes the
     * every-logged-in-user hole.
     */
    private static Rule deny(String gateway, String pattern, String role) {
        return new Rule("seed:" + gateway + ":" + pattern + ":" + role + ":deny",
                gateway, pattern, role, null, false, null, false);
    }

    private static List<Rule> pki() {
        return List.of(
                r(PKI, "/api/auth/**",    "ROLE_USER"),
                r(PKI, "/login/**",       "PUBLIC"),
                r(PKI, "/.well-known/**", "PUBLIC"),
                // SUPERADMIN floor for the headscale control plane (bug #15). The pki
                // gateway also fronts the cross-domain headscale control plane on its
                // own Host (application-pki.yml: the `headscale` route is matched by
                // `Host=scale.hugmesh.net` with NO Path predicate, so its paths
                // are NOT covered by the three rows above). Without a rule those paths
                // got Decision.NO_RULE and ANY authenticated same-domain ROLE_USER
                // reached the superadmin-tier control plane. This `/**` catch-all is
                // the correct anchor (headscale has Host-but-no-Path); longest-pattern-
                // match KEEPS the three rows above intact for their own paths while
                // EVERYTHING else (headscale) floors to SUPERADMIN. MUST be
                // ROLE_SUPERADMIN, NOT ROLE_ADMIN — a per-domain admin must NOT reach
                // the cross-domain infra control plane (only SUPERADMIN crosses
                // domains; see GatewayRouteAccessFilter). Mirrors the be() precedent
                // `/bff/superadmin/** -> ROLE_SUPERADMIN`.
                r(PKI, "/**",             "ROLE_SUPERADMIN"));
    }

    private static List<Rule> be() {
        return List.of(
                // Homeserver surfaces are gated by the PLATFORM roles, not the
                // broad ROLE_USER floor (account-states ban/congruence): holding
                // ROLE_MATRIX / ROLE_MASTODON is what grants matrix / mastodon
                // access, so removing the role (a ban) makes the allow-predicate
                // false here and the principal is denied. ROLE_MOD is PAIRED on
                // each platform row (not a bare floor) so a mod reaching a
                // homeserver moderation surface is allowed alongside the platform
                // holders; ADMIN / GAME-MASTER bypass the gate entirely in
                // GatewayRouteAccessFilter, so they need no seed row here. The
                // raw homeserver bearer channel (native clients carrying no JWT)
                // is adjudicated separately by HomeserverTokenRevocationFilter.
                // ── Matrix (tuwunel) ──────────────────────────────────────────
                r(BE, "/_matrix/**",            "ROLE_MATRIX"),
                r(BE, "/_matrix/**",            "ROLE_MOD"),
                r(BE, "/.well-known/matrix/**", "ROLE_MATRIX"),
                r(BE, "/.well-known/matrix/**", "ROLE_MOD"),
                // ── Mastodon (akkoma) ─────────────────────────────────────────
                r(BE, "/api/v1/**",             "ROLE_MASTODON"),
                r(BE, "/api/v1/**",             "ROLE_MOD"),
                r(BE, "/api/v2/**",             "ROLE_MASTODON"),
                r(BE, "/api/v2/**",             "ROLE_MOD"),
                r(BE, "/oauth/**",              "ROLE_MASTODON"),
                r(BE, "/oauth/**",              "ROLE_MOD"),
                // ── External-client ISSUANCE gate (separate from USAGE above) ──
                // The platform rows above gate token-USAGE (use matrix/mastodon
                // through OUR UI). These more-specific rows gate token-ISSUANCE:
                // the credential-minting sub-paths a NATIVE client (Element /
                // Tusky / Ivory) drives to obtain its own personal-client token.
                // Issuance requires the dedicated EXTERNAL-CLIENT role
                // (matrix-external-client → ROLE_MATRIX_EXTERNAL_CLIENT,
                // mastodon-external-client → ROLE_MASTODON_EXTERNAL_CLIENT, auto
                // via casdoorAuthoritiesConverter); base ROLE_MATRIX / ROLE_MASTODON
                // alone is NOT enough to mint a native token. Because these
                // patterns are LONGER than the /_matrix/** (11) and /oauth/** (9)
                // floors, longest-pattern-match makes them the deciding rule on the
                // issuance paths only, while every OTHER homeserver path stays on
                // the USAGE gate. ROLE_MOD is paired (a mod may register a native
                // client); ADMIN / GAME-MASTER bypass the gate in the filter.
                //
                // Our-own-UI brokered token is unaffected: it is minted by an
                // internal service identity (NOT a native client) and never
                // traverses /oauth/authorize, /oauth/token, /api/v1/apps or
                // /_matrix/client/*/login|register — so these rows never gate it.
                // Token-USAGE on those native sessions stays on the base role +
                // HomeserverTokenRevocationFilter (which denies
                // external-client:<localpart>:<platform> ONLY for kind=personal
                // tokens, leaving the brokered our-UI token working).
                //
                // ·· Matrix native login + device registration ··
                r(BE, "/_matrix/client/*/login/**",    "ROLE_MATRIX_EXTERNAL_CLIENT"),
                r(BE, "/_matrix/client/*/login/**",    "ROLE_MOD"),
                r(BE, "/_matrix/client/*/register/**", "ROLE_MATRIX_EXTERNAL_CLIENT"),
                r(BE, "/_matrix/client/*/register/**", "ROLE_MOD"),
                // ·· Mastodon OAuth app registration + authorize + token ··
                r(BE, "/api/v1/apps",          "ROLE_MASTODON_EXTERNAL_CLIENT"),
                r(BE, "/api/v1/apps",          "ROLE_MOD"),
                r(BE, "/oauth/authorize/**",   "ROLE_MASTODON_EXTERNAL_CLIENT"),
                r(BE, "/oauth/authorize/**",   "ROLE_MOD"),
                r(BE, "/oauth/token",          "ROLE_MASTODON_EXTERNAL_CLIENT"),
                r(BE, "/oauth/token",          "ROLE_MOD"),
                // ── Image-builder console seam (build-distribution) ───────────
                // The mesh-WORKLOAD image-build surface is gated on the GRANTED
                // capability ROLE_IMAGE_BUILDER (NOT an admin default): an admin
                // reaches it only if separately granted that role; SUPERADMIN
                // reaches it via the cross-domain bypass. The arch/core build
                // sub-surface and the superadmin infra console stay SUPERADMIN-only
                // by longest-pattern-match (the arch/** pattern is LONGER than the
                // /bff/image-builds/** floor, so it wins). Do NOT pair ROLE_ADMIN
                // on /bff/image-builds/** — that would let every per-domain admin
                // build images, breaking the build≠run / workload-vs-arch boundary.
                r(BE, "/bff/image-builds/arch/**", "ROLE_SUPERADMIN"),  // arch/core builds: superadmin only (wins, longer)
                r(BE, "/bff/image-builds/**",      "ROLE_IMAGE_BUILDER"), // mesh-workload builds: granted capability
                r(BE, "/bff/superadmin/**",        "ROLE_SUPERADMIN"),  // infra control plane (tailnet)
                // ── hugmesh-games (OPTIONAL slug `games`) ──────────────────
                // The games portal floor + namespace admin API on the games host.
                // The admin API surface is namespaced under /games/** so it does
                // NOT collide with the platform /api/admin/** row; it keys on the
                // DERIVED composite ROLE_GAMES_ADMIN ONLY (= ROLE_GAMES intersect
                // (ROLE_ADMIN union ROLE_MOD), materialized in Casdoor by
                // games-admin-sync), so the gateway's OR-of-allow table still
                // yields the AND — a single role (plain ROLE_GAMES / ROLE_ADMIN /
                // ROLE_MOD) is default-deny on the admin API. Because
                // /games/api/admin/** is LONGER than the /games/** portal floor,
                // longest-pattern-match makes it the deciding rule on the admin API
                // while the portal floor governs the rest of /games/**. The portal
                // floor keys on the network-wide ROLE_GAMES access role (a games
                // BAN is role removal -> governed-but-ungranted -> DENY); ROLE_ADMIN
                // and ROLE_MOD are PAIRED (supersets the converter does NOT
                // auto-grant ROLE_GAMES to). Mirrors the cluster Postgres seed; when
                // the games slug is deselected gate_optional_services prunes the
                // Postgres rows + the games host route, but this baked floor stays
                // closed-by-default so the games surface is never UNGOVERNED on the
                // datastore-unreachable fallback.
                r(BE, "/games/api/admin/**",    "ROLE_GAMES_ADMIN"), // games namespace admin API (games + (admin|mod) ONLY; wins, longer)
                r(BE, "/games/**",              "ROLE_GAMES"),       // games portal floor (games-access)
                r(BE, "/games/**",              "ROLE_ADMIN"),       // (admins superset)
                r(BE, "/games/**",              "ROLE_MOD"),         // (mods superset)
                // hugmesh-apis floor (NOT a homeserver surface) keeps ROLE_USER.
                r(BE, "/api/**",                "ROLE_USER"),
                r(BE, "/api/admin/**",          "ROLE_ADMIN"),
                // ── edge-ai-tts voice synthesis (OPTIONAL slug `edge-ai-tts`) ────
                // matrix-ui's optional voice synthesis calls the Piper TTS wrapper
                // on its own /v1 path space (the be-gateway `edge-ai-tts` route,
                // NOT under /api/**), so it needs its own row. Authenticated floor:
                // a single ROLE_USER row, mirroring the cluster Postgres seed
                // (specs/cluster/manifests/route-access/initdb/20-schema.sql) — no
                // ROLE_ADMIN pairing, because this is a capability floor and the
                // converter does not auto-grant ROLE_USER to admins (admins reach it
                // via the cross-domain bypass). The cross-repo infra this was waiting
                // on has landed (manifests + image + the ArgoCD app + the be-gateway
                // route + the Postgres row), so the baked floor keeps the surface
                // GOVERNED on the datastore-unreachable fallback instead of leaving
                // it ungoverned. When the slug is deselected gate_optional_services
                // prunes the Postgres row + the route; this floor stays closed-by-
                // default either way.
                r(BE, "/v1/synthesize/**",      "ROLE_USER"),
                // ── edge-ai-analysis verdict API (OPTIONAL slug `edge-ai-analysis`)
                // The analysis wrapper (image NSFW/abuse classify, perceptual hash,
                // content moderate, log summarize) on the SAME /v1 space, be-gateway
                // route `edge-ai-analysis`. Same single ROLE_USER floor, same
                // reasoning as the tts row above; MORE SPECIFIC than the /v1/** base
                // below so it wins the longest-pattern match.
                r(BE, "/v1/analyze/**",         "ROLE_USER"),
                // ── edge-ai inference API (OPTIONAL slug `edge-ai`) ──────────────
                // The OpenAI-compatible model API (Ollama on the GPU/edge_ai node),
                // fronted by the be-gateway's `edge-ai` route — which carries a Host
                // predicate and NO Path predicate, i.e. it is the ai.<domain>
                // CATCHALL. Without this row every /v1 path OTHER than the two
                // sub-paths above (e.g. /v1/chat/completions, /v1/embeddings,
                // /v1/models) decided NO_RULE on the datastore-unreachable fallback,
                // and NO_RULE FORWARDS — the model API was UNGOVERNED by this layer,
                // gated only by the coarse authenticated() floor, so a principal
                // holding no ROLE_USER at all (a ROLE_MATRIX-only account, say)
                // reached it. This is the third of the three /v1 rows the cluster
                // Postgres seed already carries; the gateway's baked copy had only
                // the synthesize one (dual-write seed drift, recorded on issue #4).
                // ⚠ It is deliberately the BASE row, not a widening of the two above:
                // longest-pattern-match keeps /v1/analyze/** and /v1/synthesize/**
                // resolving to their own rows. When the edge-ai slug is deselected
                // gate_optional_services drops the Postgres row + the route; this
                // floor stays closed-by-default either way.
                r(BE, "/v1/**",                 "ROLE_USER"));
    }

    private static List<Rule> fe() {
        return List.of(
                r(FE, "/",                  "PUBLIC"),
                // The rest of the anonymous SPA shell the '/' row already implies:
                // the document, the root-level hashed bundles the Angular browser
                // build serves from the host-shell webroot (Ant '*' does not
                // cross '/', so only webroot files match), the module-federation
                // manifests, favicon and static assets. Mirrors the SecurityConfig
                // FE_SHELL_PUBLIC_GET_PATHS floor (GET-only, fe tier only) so the
                // coarse layer and the route-access layer agree the anonymous
                // front page is servable. Historically the '/' PUBLIC row existed
                // but the coarse authenticated() floor 401'd anonymous '/' before
                // this table was ever consulted (the live-verified front-page
                // parity skew) — the two layers now open the SAME surface.
                r(FE, "/index.html",        "PUBLIC"),
                r(FE, "/favicon.ico",       "PUBLIC"),
                r(FE, "/importmap.json",    "PUBLIC"),
                r(FE, "/remoteEntry.json",  "PUBLIC"),
                r(FE, "/*.js",              "PUBLIC"),
                r(FE, "/*.css",             "PUBLIC"),
                r(FE, "/assets/**",         "PUBLIC"),
                // Public federation reads (federation-api permitAll's both at the
                // app layer; the cluster fe spec's vanity-subdomain route documents
                // the gateway-side allowance as the deferred missing piece): the
                // vanity profile resolve (path + Host-derived collection resolve)
                // and the install-state capabilities projection a LOGGED-OUT host
                // shell reads to grey-out optional services. Scoped to the exact
                // public reads (NOT /api/federation/**) — the manifest /
                // module-registry / username surfaces stay gated.
                r(FE, "/api/federation/vanity",       "PUBLIC"),
                r(FE, "/api/federation/vanity/**",    "PUBLIC"),
                r(FE, "/api/federation/capabilities", "PUBLIC"),
                // The social SPA shells are congruent with the be platform gates:
                // the matrix shell needs ROLE_MATRIX, the mastodon shell needs
                // ROLE_MASTODON, with ROLE_MOD paired so a mod can reach either.
                // A platform ban (role removal) closes the front door here too,
                // not just the be homeserver surface.
                r(FE, "/social/matrix/**",   "ROLE_MATRIX"),
                r(FE, "/social/matrix/**",   "ROLE_MOD"),
                r(FE, "/social/mastodon/**", "ROLE_MASTODON"),
                r(FE, "/social/mastodon/**", "ROLE_MOD"),
                // NATIVE-LOGIN model: the login page and the credential-submit
                // endpoint are ANONYMOUS. The login-ui SPA shell (/login/**) and
                // the /bff/login credential POST are the ONLY authentication entry
                // points now that Casdoor's hosted page is never browser-exposed —
                // an unauthenticated visitor holds NO role yet, so gating these on
                // ROLE_USER was a chicken-and-egg lock-out (you'd need a session to
                // reach the thing that mints the session). PUBLIC = anonymous-allowed;
                // this matches the SecurityConfig coarse floor (FE_SHELL_PUBLIC_GET_PATHS
                // `/login/**` + PUBLIC_PATHS `/bff/login`) so the two layers open the
                // SAME surface (the front-page-parity invariant). The user-bff drives
                // the Casdoor /api/login leg SERVER-SIDE and mints the opaque bff_
                // session; no token or Casdoor URL ever reaches the browser.
                r(FE, "/login/**",          "PUBLIC"),
                r(FE, "/admin/**",          "ROLE_ADMIN"),
                r(FE, "/bff/login",         "PUBLIC"),
                r(FE, "/bff/register/**",   "ROLE_USER"),
                r(FE, "/bff/provision/**",  "ROLE_USER"),
                r(FE, "/bff/me/**",         "ROLE_USER"),
                // Public login-page announcements. The admin-bff serves
                // GET /bff/public/announcements/login UNAUTHENTICATED; the
                // pre-auth LOGIN page renders published login-target banners.
                // PUBLIC = anonymous-allowed (the SecurityConfig PUBLIC_PATHS
                // floor lets the unauth'd request reach the gate; this row lets
                // the route-access layer ALLOW it too). The authed
                // /bff/announcements/** (home + forum) and ROLE_ADMIN
                // /bff/admin/announcements/** keep their own (non-overlapping
                // prefix) gates below.
                r(FE, "/bff/public/announcements/**", "PUBLIC"),
                // Public appeal-contact resolver. The admin-bff serves
                // GET /bff/public/appeal-contact UNAUTHENTICATED (permitAll,
                // returns {"email":"..."}, no PII); the pre-auth login-ui appeal
                // page renders the contact address a banned/anonymous visitor
                // should reach. PUBLIC = anonymous-allowed (the SecurityConfig
                // PUBLIC_PATHS floor lets the unauth'd request reach the gate;
                // this row lets the route-access layer ALLOW it too). Scoped to
                // the exact route (NOT a blanket /bff/public/**), mirroring the
                // announcements precedent; the ROLE_ADMIN /bff/admin/** prefix
                // below stays gated.
                r(FE, "/bff/public/appeal-contact", "PUBLIC"),
                // Fleet-owner surface — the ONE /bff/admin/** subpath a non-superadmin
                // ROLE_FLEET_ADMIN capability reaches (the owner+domain tenancy wall +
                // fleet entitlement are enforced in admin-bff's PhoneFleetOwnerController).
                // The longer /bff/admin/phone-fleet/** pattern wins the longest-match over
                // the /bff/admin/** ROLE_ADMIN floor below, so a pure fleet owner is not
                // default-denied. DUAL-WRITE PARTNER: the cluster Postgres seed
                // (generator route-access/initdb/20-schema.sql) carries the identical three
                // rows; this baked floor is the dual-DB-outage fail-safe parity copy.
                // (admin-bff's 001-gateway-route-access changelog is table DDL only — it
                // seeds NO rows, so it is NOT a companion here.)
                r(FE, "/bff/admin/phone-fleet/**", "ROLE_FLEET_ADMIN"),
                r(FE, "/bff/admin/phone-fleet/**", "ROLE_ADMIN"),
                r(FE, "/bff/admin/phone-fleet/**", "ROLE_SUPERADMIN"),
                r(FE, "/bff/admin/**",      "ROLE_ADMIN"),
                // ── SUPERADMIN PLATFORM CONSOLE at the PUBLIC BROWSER DOOR ────
                // #244 = ACCEPT (decision 41, 2026-09-17). This is the DUAL-WRITE
                // PARTNER of the cluster Postgres seed row
                //   ('hugmesh-fe-gateway','/bff/superadmin/**','ROLE_SUPERADMIN',true)
                // in generator specs/cluster/manifests/route-access/initdb/20-schema.sql,
                // which landed FIRST and names this file as the half still missing.
                // The two halves must stay in lockstep: without this row the
                // datastore-unreachable fallback is WEAKER than the Postgres rules
                // on the highest-value surface the public browser door fronts.
                //
                // WHAT IT CHANGES on the fallback, for one request by an
                // authenticated principal that is NOT admin/superadmin:
                //   BEFORE  no fe pattern matched /bff/superadmin/… at all, so
                //           decide() returned NO_RULE (ungoverned) and the filter
                //           FORWARDED on the coarse authenticated() floor. The
                //           refusal still happened — admin-bff's own
                //           SecurityConfig `pathMatchers("/bff/superadmin/**")
                //           .hasRole("SUPERADMIN")` — but one layer in, with NO
                //           X-Route-Denied header, nothing in the gateway's denial
                //           log, and the request crossing the namespace boundary.
                //   AFTER   this is the longest matching pattern, the caller holds
                //           no granting row at that length ⇒ governed-but-ungranted
                //           ⇒ DENY at the door, 403 WITH
                //           `X-Route-Denied: hugmesh-fe-gateway:<path>`.
                // The status code does NOT move; the layer, the header and the log do.
                //
                // WHAT IT DOES *NOT* CHANGE. ROLE_ADMIN and ROLE_SUPERADMIN
                // short-circuit in GatewayRouteAccessFilter BEFORE decide() is
                // consulted, so no row here alters what a privileged principal
                // reaches: a plain ROLE_ADMIN still arrives at admin-bff and is
                // still refused there by hasRole("SUPERADMIN"). This is
                // defence-in-depth and a clearer failure mode, NOT the closing of
                // an open door.
                //
                // NO games-services DENY refinement HERE — and, since 2026-09-17,
                // that is a DELIBERATE DIVERGENCE from the cluster seed rather than
                // a shared omission. Read this before "restoring parity":
                //   * #244's ACCEPT (decision 41) is stated "without the
                //     games-services deny row", and decision 41 authorises exactly
                //     ONE row here — the platform prefix above.
                //   * the CLUSTER seed DOES carry
                //     ('hugmesh-fe-gateway','/bff/superadmin/games-services/**',
                //      'ROLE_SUPERADMIN',false) again, put back by operator
                //     decision 28 = D (hugmesh-generator#347, landed 4764ab4f) with
                //     mfa_required pinned TRUE on the row itself, which is the whole
                //     reason D was chosen over leaving it out: isMfaRequiredSurface()
                //     is allow-blind and reads the LONGEST match, so the deny row
                //     carries the step-up floor for that subtree instead of stripping
                //     it.
                //   * a baked COPY could not reproduce that: D8 forbids
                //     mfa_required=true on any baked row (see r() below), so the copy
                //     would carry the wall WITHOUT the floor. What it WOULD change is
                //     decide()'s answer on the fallback for a principal holding
                //     ROLE_SUPERADMIN at /bff/superadmin/games-services/… — ALLOW on
                //     the platform row today, explicit DENY with a copy — and
                //     GatewayRouteAccessFilter short-circuits ROLE_SUPERADMIN BEFORE
                //     decide(), so even that is inert for a live request.
                // Whether the baked floor should mirror the D28 row is therefore NOT
                // decided by 41 and is NOT decided here; it is recorded on #244. The
                // measured divergence is asserted, in both repos, rather than
                // narrated: see canonicalSeed_feGateway_superadminRow_* and
                // hugmesh-generator's fallback-floor-parity.feature.
                //
                // UPDATE 2026-09-18 (decision 56, hugmesh-generator#347): this
                // row's id IS a member of MFA_REQUIRED_FALLBACK_ROWS above, so
                // r() now computes mfaRequired=true for it — the paragraph
                // that used to be here ("mfaRequired STAYS false ... the baked
                // floor deliberately does NOT carry mfa_required=true") is no
                // longer accurate FOR THIS ROW and has been corrected. The
                // cluster seed's flip UPDATE (`SET mfa_required = true WHERE
                // allow AND url_pattern LIKE '/bff/superadmin/%'`) reaches the
                // POSTGRES copy of this row; decision 56 closes the residual
                // that used to leave the BAKED floor without the same step-up
                // requirement, so a dual-DB outage no longer drops MFA
                // enforcement on this exact prefix — see
                // canonicalSeed_declaredMfaRows_isMfaRequiredSurfaceIsTrueOnTheFallback
                // in GatewayRouteAccessServiceTest. Every OTHER baked row not
                // named in MFA_REQUIRED_FALLBACK_ROWS still keeps D8's
                // mfaRequired=false default unchanged.
                r(FE, "/bff/superadmin/**", "ROLE_SUPERADMIN"),
                // Character Forge (OPTIONAL slug `character-forge`): the 3D
                // character-maker remote (/character-forge/** UI shell,
                // StripPrefix'd to the character-forge-ui nginx) and its BFF
                // (/bff/character-forge/**, declared BEFORE the /bff/** catch-all
                // in the cluster route table). Plain capability floor ROLE_USER —
                // the character-studio precedent; do NOT pair ROLE_ADMIN on a
                // capability floor (the gateway admin-bypass covers admins).
                // Mirrors the cluster Postgres seed rows; when the slug is
                // deselected gate_optional_services prunes the Postgres rows +
                // the fe route, but this baked floor keeps the surface governed
                // (ungranted anonymous = DENY) on the datastore-unreachable
                // fallback.
                r(FE, "/character-forge/**",     "ROLE_USER"),
                r(FE, "/bff/character-forge/**", "ROLE_USER"),
                // hugmesh-games (OPTIONAL slug `games`) namespace admin UI,
                // namespaced under /games/** so it does NOT collide with the
                // platform /admin/** row above. Same games + (admin|mod) gate:
                // keyed on the DERIVED composite ROLE_GAMES_ADMIN ONLY
                // (= ROLE_GAMES intersect (ROLE_ADMIN union ROLE_MOD)), so a single
                // role is default-deny and the one allow row encodes the AND.
                // Mirrors the cluster Postgres seed (fe-gateway carries ONLY this
                // games row; the games portal floor lives on the be-gateway host).
                r(FE, "/games/admin/**",    "ROLE_GAMES_ADMIN"), // games namespace admin UI (games + (admin|mod) ONLY)
                // ── SERVICE-ONLY INTERNAL INGEST SURFACES: explicit DENY ──────
                // The fe route table (generator specs/cluster/apps/20-gateway-fe.yaml)
                // carries `/bff/user/**` -> user-bff, `/bff/mesh/**` -> mesh-bff and a
                // `/bff/**` -> admin-bff catch-all, and Ant-matching means those `**`
                // predicates DO route the service-to-service `/…/internal/**` receivers
                // beneath them — three comments in that tree used to claim otherwise.
                // Each receiver is meant to be reached ONLY in-cluster (ROLE_SERVICE
                // client-credentials JWT + cluster-CA mTLS + X-Internal-Token), never
                // through a gateway:
                //   * /bff/user/internal/**  user-bff's meshdevice registry + the
                //     PENDING->ACTIVE character-moderation flip,
                //   * /bff/mesh/internal/**  the meshbridge node-directory /
                //     mesh-room bridge-sync ingest,
                //   * /bff/internal/**       admin-bff's internal API (accounts/ensure,
                //     session/introspect, device-enrollment, phone ingest, go-live,
                //     image-build ingest) — which admin-bff permitAll()s app-side, so
                //     its InternalTokenWebFilter is the only wall and that filter is
                //     inert when app.internal.token is unset.
                // WITHOUT these rows the seed has no pattern matching them at all, so
                // decide() returns NO_RULE and the gateway FORWARDS on the coarse
                // authenticated() floor — i.e. the datastore-unreachable fallback was
                // WEAKER than the Postgres rules, re-opening exactly the hole the
                // cluster seed closes. That is the whole point of this class being the
                // fail-CLOSED floor, so the rows must exist HERE too.
                // DUAL-WRITE PARTNER: the generator cluster Postgres seed
                // (specs/cluster/manifests/route-access/initdb/20-schema.sql,
                // "SERVICE-ONLY INTERNAL INGEST") and compose/route-access-seed.sql
                // carry the identical three rows, role + allow byte-for-byte.
                // gateway_route_access governs EXTERNAL traffic only, so these rows
                // cannot touch the in-cluster legs (meshbridge -> user-bff/mesh-bff,
                // gateway -> admin-bff session exchange, which the gateway makes
                // server-side and never through its own filter chain).
                deny(FE, "/bff/user/internal/**", "ROLE_USER"), // SERVICE-only ingest (meshdevice/moderation)
                deny(FE, "/bff/mesh/internal/**", "ROLE_USER"), // SERVICE-only bridge-sync ingest
                deny(FE, "/bff/internal/**",      "ROLE_USER")); // admin-bff internal API (permitAll app-side)
    }
}
