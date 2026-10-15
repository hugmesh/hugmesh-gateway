-- Local-dev seed for the gateway_route_access SOURCE OF TRUTH (Postgres).
-- The gateway reads ONLY the rows for its own SPRING_APPLICATION_NAME, so this
-- carries every gateway's canonical rules; flip SPRING_APPLICATION_NAME on the
-- gateway container to exercise a different rule set without a rebuild.
--
-- Mirrors cluster/manifests/route-access/schema.sql + the route-access contract.
-- role values are Spring authorities (ROLE_USER, ROLE_ADMIN) or the sentinel
-- PUBLIC (anonymous-allowed). The gateway uses longest-pattern-match, so
-- /api/admin/** (ROLE_ADMIN) correctly overrides /api/** (ROLE_USER).

CREATE TABLE IF NOT EXISTS gateway_route_access (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    gateway      text        NOT NULL,
    url_pattern  text        NOT NULL,
    role         text        NOT NULL,
    casdoor_user text,
    allow        boolean     NOT NULL DEFAULT true,
    -- Per-row BRAND scope (multi-brand architecture tier). NULL/'default' =
    -- applies to ANY target domain (back-compat: every row below leaves it NULL,
    -- so single-tenant + the canonical seed are unchanged). A per-brand row
    -- carries its own domain, so a brand-Y `/api/admin/** -> ROLE_ADMIN` grant can
    -- NEVER be re-granted to a brand-X admin — the gateway filter passes the
    -- request's target domain (derived from Host) and a scoped row only applies to
    -- its own brand. Defense-in-depth alongside the filter's hard-deny on
    -- domain mismatch.
    domain       text,
    updated_at   timestamptz NOT NULL DEFAULT now()
);
-- Idempotent add for a table created by an EARLIER (pre-domain) seed run.
ALTER TABLE gateway_route_access ADD COLUMN IF NOT EXISTS domain text;
CREATE INDEX IF NOT EXISTS idx_route_access_gw ON gateway_route_access (gateway, url_pattern);

INSERT INTO gateway_route_access (gateway, url_pattern, role, allow) VALUES
  -- pki-gateway (id.hugmesh.net -> casdoor)
  ('hugmesh-pki-gateway',  '/api/auth/**',          'ROLE_USER',  true),
  ('hugmesh-pki-gateway',  '/login/**',             'PUBLIC',     true),
  ('hugmesh-pki-gateway',  '/.well-known/**',       'PUBLIC',     true),
  -- NO bare '/**' row for the pki gateway (decision 79 = B,
  -- hugmesh-admin-bff-api#57, 2026-09-23). The headscale control plane (the
  -- `headscale` route in hugmesh-pki-gateway application-pki.yml, Host=scale.<domain>
  -- with NO Path predicate) used to be floored here by a '/**' -> ROLE_SUPERADMIN
  -- row (bug #15). It could not stop a same-brand ROLE_ADMIN / ROLE_GAME-MASTER
  -- (GatewayRouteAccessFilter forwards both in their own domain before any row is
  -- read), and the admin API can never recreate a '/**' row. The gateway's
  -- SecurityConfig now requires ROLE_SUPERADMIN for EVERY request on that route's
  -- Host, ahead of PUBLIC_PATHS, so no row is needed here. Mirrors
  -- CanonicalSeed.pki().
  -- be-gateway (matrix/mastodon/api.hugmesh.net)
  -- Homeserver surfaces are gated by the PLATFORM roles (account-states
  -- ban/congruence), NOT the broad ROLE_USER floor: a ban removes ROLE_MATRIX /
  -- ROLE_MASTODON and the longest-pattern allow-predicate goes false here.
  -- ROLE_MOD is PAIRED on each platform row (a mod reaches the moderation
  -- surface alongside platform holders); ADMIN / GAME-MASTER bypass the gate in
  -- the filter, so they need no row. The raw homeserver-bearer channel is
  -- adjudicated separately by HomeserverTokenRevocationFilter.
  ('hugmesh-be-gateway',   '/_matrix/**',           'ROLE_MATRIX',   true),
  ('hugmesh-be-gateway',   '/_matrix/**',           'ROLE_MOD',      true),
  ('hugmesh-be-gateway',   '/.well-known/matrix/**','ROLE_MATRIX',   true),
  ('hugmesh-be-gateway',   '/.well-known/matrix/**','ROLE_MOD',      true),
  ('hugmesh-be-gateway',   '/api/v1/**',            'ROLE_MASTODON', true),
  ('hugmesh-be-gateway',   '/api/v1/**',            'ROLE_MOD',      true),
  ('hugmesh-be-gateway',   '/api/v2/**',            'ROLE_MASTODON', true),
  ('hugmesh-be-gateway',   '/api/v2/**',            'ROLE_MOD',      true),
  ('hugmesh-be-gateway',   '/oauth/**',             'ROLE_MASTODON', true),
  ('hugmesh-be-gateway',   '/oauth/**',             'ROLE_MOD',      true),
  -- External-client ISSUANCE gate (separate from USAGE rows above). The rows
  -- above gate token-USAGE (use matrix/mastodon via OUR UI); these more-specific
  -- rows gate token-ISSUANCE — the credential-minting sub-paths a NATIVE client
  -- (Element/Tusky/Ivory) drives to obtain its own personal-client token, which
  -- require the dedicated external-client role. Longest-pattern-match makes them
  -- the deciding rule on the issuance paths only; every other homeserver path
  -- stays on the USAGE gate. ROLE_MOD paired; ADMIN/GAME-MASTER bypass in the
  -- filter. The brokered our-UI token (internal service identity) never traverses
  -- these paths, so it is unaffected.
  ('hugmesh-be-gateway',   '/_matrix/client/*/login/**',    'ROLE_MATRIX_EXTERNAL_CLIENT',   true),
  ('hugmesh-be-gateway',   '/_matrix/client/*/login/**',    'ROLE_MOD',                      true),
  ('hugmesh-be-gateway',   '/_matrix/client/*/register/**', 'ROLE_MATRIX_EXTERNAL_CLIENT',   true),
  ('hugmesh-be-gateway',   '/_matrix/client/*/register/**', 'ROLE_MOD',                      true),
  ('hugmesh-be-gateway',   '/api/v1/apps',          'ROLE_MASTODON_EXTERNAL_CLIENT', true),
  ('hugmesh-be-gateway',   '/api/v1/apps',          'ROLE_MOD',                      true),
  ('hugmesh-be-gateway',   '/oauth/authorize/**',   'ROLE_MASTODON_EXTERNAL_CLIENT', true),
  ('hugmesh-be-gateway',   '/oauth/authorize/**',   'ROLE_MOD',                      true),
  ('hugmesh-be-gateway',   '/oauth/token',          'ROLE_MASTODON_EXTERNAL_CLIENT', true),
  ('hugmesh-be-gateway',   '/oauth/token',          'ROLE_MOD',                      true),
  -- Image-builder console seam (build-distribution). The mesh-WORKLOAD build
  -- surface is gated on the GRANTED capability ROLE_IMAGE_BUILDER, NOT an admin
  -- default: do NOT pair ROLE_ADMIN here (that would let every per-domain admin
  -- build images). The arch/core build sub-surface + the superadmin infra console
  -- stay SUPERADMIN-only by longest-pattern-match (arch/** is LONGER, so it wins).
  -- SUPERADMIN reaches everything via the gateway cross-domain bypass, so it needs
  -- no per-surface row for ordinary admin paths.
  ('hugmesh-be-gateway',   '/bff/image-builds/arch/**', 'ROLE_SUPERADMIN',    true),  -- arch/core builds: superadmin only (wins, longer)
  ('hugmesh-be-gateway',   '/bff/image-builds/**',      'ROLE_IMAGE_BUILDER', true),  -- mesh-workload builds: image_builder (admins granted it)
  ('hugmesh-be-gateway',   '/bff/superadmin/**',        'ROLE_SUPERADMIN',    true),  -- superadmin infra console (tailnet)
  ('hugmesh-be-gateway',   '/api/**',               'ROLE_USER',     true),
  ('hugmesh-be-gateway',   '/api/admin/**',         'ROLE_ADMIN',    true),
  -- ── games portal + games namespace admin API (be-gateway) ──────────────────
  -- SECOND dual-write gap on this same file (skeptic finding F2, round 3). The
  -- cluster Postgres seed and the baked CanonicalSeed.be() both carry these four
  -- rows; this local-dev copy carried NONE, and the /v1 fix alone would have left
  -- the file still drifting. It matters MORE than the /v1 gap it sits beside:
  -- no be-gateway pattern in this file is /games-prefixed, so /games/api/admin/**
  -- matched nothing, decide() returned NO_RULE, and NO_RULE FORWARDS — an ADMIN
  -- surface left ungoverned by this layer in any stack pointed at this seed,
  -- versus a ROLE_USER capability floor for /v1.
  -- ROLE_GAMES is the games-access capability; ROLE_ADMIN and ROLE_MOD are PAIRED
  -- supersets here (the converter does NOT auto-grant ROLE_GAMES to them), which
  -- is why the games floor carries an admin pairing where the /v1 floors above do
  -- not. The namespace admin API is LONGER, so longest-pattern-match keeps it on
  -- ROLE_GAMES_ADMIN rather than widening it to the portal floor.
  ('hugmesh-be-gateway',   '/games/api/admin/**',   'ROLE_GAMES_ADMIN', true),  -- games namespace admin API (wins, longer)
  ('hugmesh-be-gateway',   '/games/**',             'ROLE_GAMES',       true),  -- games portal floor (games-access)
  ('hugmesh-be-gateway',   '/games/**',             'ROLE_ADMIN',       true),  -- (admins superset)
  ('hugmesh-be-gateway',   '/games/**',             'ROLE_MOD',         true),  -- (mods superset)
  -- ── edge-AI /v1 path space (be-gateway) ────────────────────────────────────
  -- A path space DISTINCT from /api/** above, fronted by three OPTIONAL slugs:
  -- edge-ai-tts (/v1/synthesize/**, matrix-ui voice synthesis), edge-ai-analysis
  -- (/v1/analyze/**) and edge-ai itself — whose be-gateway route is a Host
  -- predicate (ai.<domain>) with NO Path predicate, i.e. the /v1 CATCHALL.
  -- WITHOUT the /v1/** base row every other /v1 path (/v1/chat/completions,
  -- /v1/embeddings, /v1/models) matched no rule here, decide() returned NO_RULE,
  -- and NO_RULE FORWARDS: in this dev stack the model API was governed only by
  -- the coarse authenticated() floor, so a principal holding no ROLE_USER at all
  -- (a ROLE_MATRIX-only account) reached it.
  -- Each row is a plain ROLE_USER capability floor — no ROLE_ADMIN pairing (the
  -- converter does not auto-grant ROLE_USER to admins, who reach it via the
  -- gateway's own bypass). The two sub-path rows are LONGER than the base, so
  -- longest-pattern-match keeps them deciding their own paths rather than the
  -- base widening them.
  -- Third leg of the dual-write trio, byte-for-byte: the cluster seed
  -- (route-access/initdb/20-schema.sql) and the baked CanonicalSeed.be() rows
  -- already carry all three; this local-dev copy carried none (issue #4).
  ('hugmesh-be-gateway',   '/v1/analyze/**',        'ROLE_USER',     true),  -- edge-ai-analysis verdict API
  ('hugmesh-be-gateway',   '/v1/synthesize/**',     'ROLE_USER',     true),  -- edge-ai-tts voice synthesis API
  ('hugmesh-be-gateway',   '/v1/**',                'ROLE_USER',     true),  -- edge-ai OpenAI-compatible inference API
  -- fe-gateway (hugmesh.net host + MFE + /bff proxy)
  -- FULL PARITY with CanonicalSeed.fe() (issue #34): this INSERT must carry every
  -- row that method returns, in the same order, so
  -- composeSeed_feGateway_wholeBlockMatchesTheBakedCanonicalSeedExactly
  -- (GatewayRouteAccessServiceTest) enumerates them and fails on any future
  -- drift instead of trusting a hand-list.
  ('hugmesh-fe-gateway',   '/',                     'PUBLIC',        true),
  -- The rest of the anonymous SPA shell the '/' row already implies: the document,
  -- the root-level hashed bundles, the module-federation manifests, favicon and
  -- static assets. Mirrors SecurityConfig's FE_SHELL_PUBLIC_GET_PATHS floor
  -- (GET-only, fe tier only) so the coarse layer and this table agree.
  ('hugmesh-fe-gateway',   '/index.html',           'PUBLIC',        true),
  ('hugmesh-fe-gateway',   '/favicon.ico',          'PUBLIC',        true),
  ('hugmesh-fe-gateway',   '/importmap.json',       'PUBLIC',        true),
  ('hugmesh-fe-gateway',   '/remoteEntry.json',     'PUBLIC',        true),
  ('hugmesh-fe-gateway',   '/*.js',                 'PUBLIC',        true),
  ('hugmesh-fe-gateway',   '/*.css',                'PUBLIC',        true),
  ('hugmesh-fe-gateway',   '/assets/**',            'PUBLIC',        true),
  -- Public federation reads (federation-api permitAll's both app-side): the
  -- vanity profile resolve and the install-state capabilities projection a
  -- LOGGED-OUT host shell reads. Scoped to the exact public reads (NOT
  -- /api/federation/**) — the manifest / module-registry / username surfaces stay
  -- gated.
  ('hugmesh-fe-gateway',   '/api/federation/vanity',       'PUBLIC', true),
  ('hugmesh-fe-gateway',   '/api/federation/vanity/**',    'PUBLIC', true),
  ('hugmesh-fe-gateway',   '/api/federation/capabilities', 'PUBLIC', true),
  -- Social SPA shells congruent with the be platform gates.
  ('hugmesh-fe-gateway',   '/social/matrix/**',     'ROLE_MATRIX',   true),
  ('hugmesh-fe-gateway',   '/social/matrix/**',     'ROLE_MOD',      true),
  ('hugmesh-fe-gateway',   '/social/mastodon/**',   'ROLE_MASTODON', true),
  ('hugmesh-fe-gateway',   '/social/mastodon/**',   'ROLE_MOD',      true),
  -- NATIVE-LOGIN model: /login (the login-ui SPA shell) and /bff/login (the
  -- credential submit) are ANONYMOUS — they are the only auth entry points now
  -- that Casdoor's hosted page is never browser-exposed, and an unauthenticated
  -- visitor holds no role yet (ROLE_USER here was a chicken-and-egg lock-out).
  -- PUBLIC = anonymous-allowed; matches the SecurityConfig coarse floor so the two
  -- layers open the same surface. The user-bff drives the Casdoor /api/login leg
  -- server-side and mints the opaque bff_ session (no token reaches the browser).
  ('hugmesh-fe-gateway',   '/login/**',             'PUBLIC',     true),
  ('hugmesh-fe-gateway',   '/admin/**',             'ROLE_ADMIN', true),
  ('hugmesh-fe-gateway',   '/bff/login',            'PUBLIC',     true),
  ('hugmesh-fe-gateway',   '/bff/register/**',      'ROLE_USER',  true),
  ('hugmesh-fe-gateway',   '/bff/provision/**',     'ROLE_USER',  true),
  ('hugmesh-fe-gateway',   '/bff/me/**',            'ROLE_USER',  true),
  -- Public login-page announcements / appeal-contact resolver. admin-bff serves
  -- both UNAUTHENTICATED (permitAll, no PII); the pre-auth login-ui reads them.
  -- Scoped to the exact routes (NOT a blanket /bff/public/**) — the authed
  -- /bff/announcements/** and ROLE_ADMIN /bff/admin/** prefixes stay gated below.
  ('hugmesh-fe-gateway',   '/bff/public/announcements/**', 'PUBLIC', true),
  ('hugmesh-fe-gateway',   '/bff/public/appeal-contact',   'PUBLIC', true),
  -- Fleet-owner surface — the ONE /bff/admin/** subpath a non-superadmin
  -- ROLE_FLEET_ADMIN capability reaches (the owner+domain tenancy wall + fleet
  -- entitlement are enforced in admin-bff's PhoneFleetOwnerController). The
  -- longer /bff/admin/phone-fleet/** pattern wins the longest-match over the
  -- /bff/admin/** ROLE_ADMIN floor below, so a pure fleet owner is not
  -- default-denied. Mirrors the baked CanonicalSeed.fe() rows.
  ('hugmesh-fe-gateway',   '/bff/admin/phone-fleet/**', 'ROLE_FLEET_ADMIN', true),
  ('hugmesh-fe-gateway',   '/bff/admin/phone-fleet/**', 'ROLE_ADMIN',       true),
  ('hugmesh-fe-gateway',   '/bff/admin/phone-fleet/**', 'ROLE_SUPERADMIN',  true),
  ('hugmesh-fe-gateway',   '/bff/admin/**',         'ROLE_ADMIN', true),
  -- Superadmin platform console at the PUBLIC browser door (hugmesh-generator#244
  -- = ACCEPT, decision 41, 2026-09-17). Dual-write partner of the baked
  -- CanonicalSeed.fe() row added in hugmesh-gateway#33: without this row here the
  -- local-dev compose stack still shows the pre-#244 posture (NO_RULE -> forward)
  -- even after #33 merges, because this file REPLACES the baked floor wholesale
  -- when Postgres loads. No games-services DENY refinement here, same as the
  -- baked copy (decision 41 authorises exactly this one row).
  ('hugmesh-fe-gateway',   '/bff/superadmin/**',    'ROLE_SUPERADMIN', true),
  -- Wiki BFF (/bff/wiki/** -> hugmesh-wiki-bff-api), all three rows (decision
  -- 80a = B, hugmesh-generator#329, 2026-09-23). Mirrors the cluster seed
  -- (route-access/initdb/20-schema.sql) + the baked CanonicalSeed.fe() rows role
  -- for role: the superadmin + admin console seams win the longest match over the
  -- ROLE_WIKI access floor. Do NOT pair ROLE_WIKI on the admin row or ROLE_ADMIN on
  -- the floor. (This file has no mfa_required column; the cluster seed carries the
  -- decision-80b flag for the two console rows.)
  ('hugmesh-fe-gateway',   '/bff/wiki/superadmin/**', 'ROLE_SUPERADMIN', true),
  ('hugmesh-fe-gateway',   '/bff/wiki/admin/**',      'ROLE_ADMIN',      true),
  ('hugmesh-fe-gateway',   '/bff/wiki/**',            'ROLE_WIKI',       true),
  -- Character Forge (OPTIONAL slug `character-forge`): the 3D character-maker
  -- remote UI shell + its BFF. Plain ROLE_USER capability floor
  -- (character-studio precedent); do NOT pair ROLE_ADMIN on a capability floor
  -- (the gateway admin-bypass covers admins). Mirrors the cluster seed
  -- (route-access/initdb/20-schema.sql) + the baked CanonicalSeed.fe() rows.
  ('hugmesh-fe-gateway',   '/character-forge/**',     'ROLE_USER', true),
  ('hugmesh-fe-gateway',   '/bff/character-forge/**', 'ROLE_USER', true),
  -- hugmesh-games (OPTIONAL slug `games`) namespace admin UI, namespaced under
  -- /games/** so it does not collide with the platform /admin/** row above. Same
  -- games + (admin|mod) gate as the be-gateway games rows: keyed on the DERIVED
  -- composite ROLE_GAMES_ADMIN ONLY, so a single role is default-deny and the one
  -- allow row encodes the AND. Mirrors the baked CanonicalSeed.fe() row.
  ('hugmesh-fe-gateway',   '/games/admin/**',       'ROLE_GAMES_ADMIN', true),
  -- SERVICE-ONLY INTERNAL INGEST SURFACES: explicit DENY. The fe route table
  -- Ant-matches `/bff/user/**` -> user-bff, `/bff/mesh/**` -> mesh-bff and the
  -- `/bff/**` -> admin-bff catch-all, so those `**` predicates DO route the
  -- service-to-service `/…/internal/**` receivers beneath them. Without a row the
  -- longest-pattern walk finds nothing, decide() returns NO_RULE and the gateway
  -- FORWARDS on the coarse authenticated() floor — reaching user-bff's meshdevice
  -- registry + PENDING->ACTIVE character-moderation flip, mesh-bff's bridge-sync
  -- ingest, and admin-bff's internal API (which permitAll()s that prefix app-side,
  -- leaving an unset app.internal.token as the only wall). Each receiver is meant
  -- to be reached ONLY in-cluster (ROLE_SERVICE + mTLS + X-Internal-Token); this
  -- table governs EXTERNAL traffic only, so the in-cluster legs are untouched.
  -- Mirrors the cluster seed (route-access/initdb/20-schema.sql "SERVICE-ONLY
  -- INTERNAL INGEST") + the baked CanonicalSeed.fe() deny rows, byte-for-byte.
  ('hugmesh-fe-gateway',   '/bff/user/internal/**', 'ROLE_USER', false),
  ('hugmesh-fe-gateway',   '/bff/mesh/internal/**', 'ROLE_USER', false),
  ('hugmesh-fe-gateway',   '/bff/internal/**',      'ROLE_USER', false)
ON CONFLICT DO NOTHING;
