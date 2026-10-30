-- gateway_route_access — which Casdoor roles may reach which URL patterns from
-- OUTSIDE a given gateway (external = from the VPN/cloud, before the gateway).
-- Managed by the admin-api (CRUD); each hugmesh-*-gateway loads the rows for
-- its own gateway name, caches them in Cassandra (periodic refresh like the
-- existing revocation/url-registry caches), and denies a request unless the
-- caller's Casdoor roles match an `allow` rule for the matched URL pattern.
--
-- This is the hugmesh-id-gateway Postgres-backed pattern WITHOUT the random
-- per-app URL generation — just role-based external access control to the
-- already-known services. Roles are owned by Casdoor; rows reference a Casdoor
-- role (and optionally a specific Casdoor user) by name.
CREATE TABLE IF NOT EXISTS gateway_route_access (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    gateway      text        NOT NULL,   -- hugmesh-pki-gateway | -be-gateway | -fe-gateway
    url_pattern  text        NOT NULL,   -- Spring path pattern, e.g. /api/admin/**, /social/**
    role         text        NOT NULL,   -- Casdoor role, e.g. ROLE_ADMIN, ROLE_USER
    casdoor_user text,                   -- optional: pin to a specific Casdoor user
    allow        boolean     NOT NULL DEFAULT true,
    -- Per-row BRAND scope (multi-brand architecture tier). NULL/'default' = applies
    -- to ANY target domain (back-compat: every canonical seed row below leaves it
    -- NULL/unscoped, so single-tenant + the in-image CanonicalSeed floor are
    -- unchanged). The merged gateway (GatewayRouteAccessService.loadFromPostgres +
    -- the Cassandra mirror) now SELECTs this column, and its domainApplies()/
    -- appliesTo() treat NULL/blank/'default' as unscoped; without the column the
    -- deployed gateway's row load fails outright. A per-brand row carries its own
    -- domain so a brand-Y `/api/admin/** -> ROLE_ADMIN` grant can NEVER be
    -- re-granted to a brand-X admin — the gateway filter passes the request's
    -- target domain (derived from Host) and a scoped row only applies to its own
    -- brand. Defense-in-depth alongside the filter's hard-deny on domain mismatch.
    domain       text,
    -- Per-row MFA REQUIREMENT (Casdoor MFA tier — D6/D8). DEFAULT false = INERT:
    -- every canonical seed row below omits this column from its INSERT list, so the
    -- default applies and the deployed posture is BYTE-IDENTICAL until an operator
    -- flips a row to true. This column is the DUAL-WRITE PARTNER of the gateway G4
    -- CanonicalSeed mfa_required field (hugmesh-gateway) + the admin-bff
    -- 001-copy RouteRule/RouteAccessRepository mirror — the merged gateway's
    -- GatewayRouteAccessService.loadFromPostgres SELECTs this column, and
    -- GatewayRouteAccessFilter.decide() (when app.mfa.enabled) requires the
    -- principal to hold MFA_SATISFIED on a matched true row, else 403 fail-closed.
    -- A row with mfa_required=false never gates on MFA, so legacy/single-issuer
    -- tokens with no MFA claim are unaffected = additive. ⚠ MUST merge in LOCKSTEP
    -- with the gateway G4 + admin-bff 001-copy so all three sides SELECT/write the
    -- same column (mirrors the domain-column dual-write idiom directly above).
    mfa_required boolean     NOT NULL DEFAULT false,
    updated_at   timestamptz NOT NULL DEFAULT now()
);
-- Idempotent add for a table created by an EARLIER (pre-domain) initdb run so an
-- in-place cluster upgrade gains the column the merged gateway now SELECTs.
ALTER TABLE gateway_route_access ADD COLUMN IF NOT EXISTS domain text;
-- Idempotent add (mirrors the domain-column idiom) so an in-place upgrade of a
-- pre-MFA cluster gains the mfa_required column the merged gateway now SELECTs.
-- DEFAULT false keeps every existing row inert (no MFA gate) until an operator
-- flips it — byte-identical to today. Dual-write partner of gateway G4 +
-- admin-bff 001-copy (see the CREATE-TABLE note above).
--
-- ⚠ NOT NULL MUST MATCH THE CREATE TABLE ABOVE. It did not: this ALTER shipped
-- NULLABLE while the CREATE TABLE declares NOT NULL, so a cluster created by a
-- fresh initdb and a cluster upgraded in place genuinely differed. On the upgraded
-- one the admin-bff CRUD (the table's only writer) could store mfa_required = NULL,
-- and the merged gateway's loadFromPostgres reads that column back as a primitive
-- boolean — a NULL is not "false by another name", it is a third state nothing in
-- the read path is written for. The three statements below converge BOTH shapes,
-- and each is a no-op on a cluster that is already correct:
--   1. ADD COLUMN … NOT NULL DEFAULT false  — fresh/new tables get the right shape
--      immediately (Postgres 11+ fills the default without a table rewrite). It is
--      SKIPPED by IF NOT EXISTS on a cluster that already has the nullable column,
--      which is exactly why 2–4 are needed.
--   2. backfill the NULLs FIRST — SET NOT NULL fails outright if any row is NULL,
--      so the order matters. This is the only other statement in this file that
--      writes mfa_required; it can only ever turn NULL into false, never true into
--      false, and tests/scripts/test-mfa-required-rules.sh pins its exact shape and
--      its position before the flip UPDATE at the end of the file.
--   3./4. then re-assert the DEFAULT and the NOT NULL the CREATE TABLE promises.
ALTER TABLE gateway_route_access ADD COLUMN IF NOT EXISTS mfa_required boolean NOT NULL DEFAULT false;
UPDATE gateway_route_access SET mfa_required = false WHERE mfa_required IS NULL;
ALTER TABLE gateway_route_access ALTER COLUMN mfa_required SET DEFAULT false;
ALTER TABLE gateway_route_access ALTER COLUMN mfa_required SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_route_access_gw ON gateway_route_access (gateway, url_pattern);
-- De-duplicate any rows a PRE-FIX re-application of this file already produced
-- (the `id` PK is a random uuid, never supplied by the INSERT below, so
-- `ON CONFLICT DO NOTHING` could not previously detect a repeat row) before
-- adding the real uniqueness constraint just below — otherwise CREATE UNIQUE
-- INDEX fails outright on an already-duplicated table during an in-place
-- upgrade. Keeps the row with the lowest ctid (arbitrary but stable) per key.
-- The domain leg compares the NORMALIZED scope (see the index note below), so
-- an in-place upgrade also collapses alias-spelled duplicates the OLD lexical
-- key permitted (a NULL row beside a 'Default' row, or brand-x beside a
-- space-padded Brand-X) BEFORE the stricter index is created — otherwise that
-- CREATE aborts the whole initdb on exactly the clusters this repair targets.
DELETE FROM gateway_route_access a USING gateway_route_access b
  WHERE a.ctid < b.ctid
    AND a.gateway = b.gateway
    AND a.url_pattern = b.url_pattern
    AND a.role = b.role
    AND COALESCE(a.casdoor_user, '') = COALESCE(b.casdoor_user, '')
    AND COALESCE(NULLIF(lower(trim(a.domain)), 'default'), '')
      = COALESCE(NULLIF(lower(trim(b.domain)), 'default'), '');
-- Real uniqueness key for a seed row: the table's only constraint was the
-- random `id uuid PRIMARY KEY`, so `ON CONFLICT DO NOTHING` below never fired
-- on a re-apply (every run generates fresh, non-colliding ids) — re-applying
-- this file against an existing route-access-db (the file's own header claims
-- this is supported for an in-place cluster upgrade) duplicated all seed
-- rows. casdoor_user/domain are nullable and NULLs never compare equal in a
-- plain unique index, so COALESCE them to a non-null sentinel.
--
-- PER-DOMAIN MFA SCOPE (issue #47 × the casdoor-choice schema): the domain leg
-- is keyed on the GATEWAY'S OWN scope equivalence, not the raw text.
-- GatewayRouteAccessService.domainApplies() (hugmesh-gateway) treats
-- NULL / blank / the word default — case-insensitively, trimmed — as ONE
-- unscoped class that applies to every domain, and compares a scoped domain
-- trimmed + case-insensitively. The old lexical key COALESCE(domain, '') let
-- the table hold two rows the gateway cannot tell apart (NULL beside
-- 'Default', brand-x beside a space-padded Brand-X) with contradictory
-- allow/mfa_required values. Per-domain SIBLING rows are now a supported
-- idiom (a domain-scoped row beside the unscoped canonical row expresses
-- per-domain MFA tightening — see the per-domain arm of the UPDATE at the end
-- of this file and docs/MFA-ROLLOUT.md §1.2a), so the key must collapse
-- exactly what the gateway collapses:
--   COALESCE(NULLIF(lower(trim(domain)), 'default'), '')
--
-- The DROP is REQUIRED for the in-place upgrade: CREATE UNIQUE INDEX
-- IF NOT EXISTS is a no-op while the OLD lexical index still holds the name,
-- and the INSERT's ON CONFLICT target below must match the index expression
-- EXACTLY — with the old expression still in place the re-applied INSERT
-- aborts the whole initdb ("no unique or exclusion constraint matching the
-- ON CONFLICT specification"). Dropping + recreating on every re-apply is
-- cheap at this table's size, and the de-dup DELETE above has already
-- collapsed any alias-duplicates the stricter key would reject.
DROP INDEX IF EXISTS uq_route_access_row;
CREATE UNIQUE INDEX IF NOT EXISTS uq_route_access_row
  ON gateway_route_access (gateway, url_pattern, role, COALESCE(casdoor_user, ''), COALESCE(NULLIF(lower(trim(domain)), 'default'), ''));

-- Retire the misspelled api-docs row an earlier apply seeded: the real fe route
-- is /api-docs/** (see the renamed row below), so /apidocs/** matched nothing
-- and left the api-docs mount governed only by the coarse authenticated floor.
DELETE FROM gateway_route_access
 WHERE gateway = 'hugmesh-fe-gateway'
   AND url_pattern = '/apidocs/**';

-- Canonical seed — one allow row per (gateway, url_pattern, role) in the routing
-- contract. Role semantics (mirroring the hugmesh.games SecurityConfig
-- casdoorAuthoritiesConverter):
--   PUBLIC          public: no Casdoor JWT required (login, OIDC discovery, the
--                   front page). The gateway lets the request through unauth'd.
--   ROLE_USER       the authenticated floor: any valid Casdoor principal holds
--                   it (this is the "public-floor" of /api/auth/** etc.).
--   ROLE_ADMIN      JWT "roles" claim contains admin, or the legacy isAdmin flag.
--   ROLE_MOD        Casdoor 'moderator' group: network-wide Matrix + Mastodon
--                   moderation ONLY. A SIBLING of ROLE_ADMIN, NOT a superset of
--                   it — ROLE_MOD never matches the infra/admin rows
--                   (/api/admin/**, /admin/**, /bff/admin/** stay ROLE_ADMIN),
--                   and there is no route to vault/k8s or observability
--                   (uptrace/grafana/clickhouse have no external gateway route at
--                   all), so default-deny keeps ROLE_MOD off everything else.
--   ROLE_GAMES      Casdoor network-wide sibling, "Games Member". Grants nothing
--                   on its own (no route row keys on it) — it is one INPUT to the
--                   games-namespace-admin gate, never the gate itself.
--   ROLE_GAMES_ADMIN  DERIVED/composite role (membership = ROLE_GAMES intersect
--                   (ROLE_ADMIN union ROLE_MOD), materialized by games-admin-sync;
--                   see manifests/casdoor/init-data-configmap.yaml). It is the
--                   ONLY role on the games-namespace admin rows (/games/api/admin/**
--                   on be-gateway, /games/admin/** on fe-gateway). Because the gate
--                   is a SINGLE allow row keyed on this intersection role, the
--                   OR-of-allow-rows table expresses the required AND of
--                   "games + (admin|mod)": ROLE_GAMES alone or ROLE_ADMIN alone is
--                   default-deny — only the combination reaches the surface.
-- A request is allowed iff the caller holds the role of a matching allow row for
-- THIS gateway; the most specific matching url_pattern wins (admin paths first).
INSERT INTO gateway_route_access (gateway, url_pattern, role, allow) VALUES
  -- pki-gateway (id.hugmesh.net -> Casdoor)
  ('hugmesh-pki-gateway', '/api/auth/**',          'ROLE_USER',      true),  -- public-floor
  ('hugmesh-pki-gateway', '/login/**',             'PUBLIC', true),  -- public
  ('hugmesh-pki-gateway', '/.well-known/**',       'PUBLIC', true),  -- public (OIDC/jwks)
  ('hugmesh-pki-gateway', '/**',                   'ROLE_SUPERADMIN', true),  -- headscale control-plane (scale.) catch-all -> SUPERADMIN-only; the 3 specific rows above win by most-specific match (bug #15)

  -- be-gateway (api./matrix./mastodon.hugmesh.net -> APIs/Matrix/Mastodon)
  -- ROLE_MOD moderation surfaces — MORE SPECIFIC than the ROLE_MASTODON /api/v1/**
  -- platform-access floor below, so they win the most-specific match and gate
  -- akkoma moderation to moderators/admins (NOT plain ROLE_MASTODON). ROLE_ADMIN is
  -- paired on each so admins (a superset) keep reaching these moderation surfaces.
  -- Matrix admin is enforced by admin-room membership (tuwunel-admin-sync), not an
  -- HTTP surface, so no /_synapse/admin/** row is needed (Conduit-family exposes none).
  ('hugmesh-be-gateway',  '/api/v1/pleroma/admin/**', 'ROLE_MOD',    true),  -- akkoma moderation REST
  ('hugmesh-be-gateway',  '/api/v1/pleroma/admin/**', 'ROLE_ADMIN',  true),  -- (admins superset)
  ('hugmesh-be-gateway',  '/api/pleroma/admin/**',    'ROLE_MOD',    true),  -- legacy akkoma admin
  ('hugmesh-be-gateway',  '/api/pleroma/admin/**',    'ROLE_ADMIN',  true),  -- (admins superset)
  ('hugmesh-be-gateway',  '/pleroma/admin/**',        'ROLE_MOD',    true),  -- AdminFE assets
  ('hugmesh-be-gateway',  '/pleroma/admin/**',        'ROLE_ADMIN',  true),  -- (admins superset)
  -- ── PER-PLATFORM ACCESS roles (ban/congruence foundation) ─────────────────
  -- The homeserver client surfaces are now gated by the per-PLATFORM access roles
  -- ROLE_MATRIX / ROLE_MASTODON (seeded in manifests/casdoor/init-data-configmap.yaml),
  -- NOT the broad ROLE_USER floor. Holding ROLE_USER alone no longer reaches Matrix
  -- or Mastodon — a principal must hold the matching platform role. A platform BAN
  -- is the ABSENCE of the role: removal makes every allow-predicate here false, so
  -- the path becomes governed-but-ungranted -> DENY (no allow=false / ban row).
  -- ADMIN/MOD remain a superset (paired on each row) because the
  -- casdoorAuthoritiesConverter does NOT auto-grant the platform roles to them.
  --
  -- ⚠️ The broad ROLE_USER homeserver rows ( /_matrix/**, /api/v1/**, /oauth/** )
  -- and the bare ROLE_MOD floor rows that used to live here were REMOVED at this
  -- flip. DEPLOY-TOGETHER with the Casdoor seed+BACKFILL: every current homeserver
  -- holder must be granted ROLE_MATRIX/ROLE_MASTODON BEFORE this row set reaches a
  -- live cluster, or they lock out (see init-data-configmap.yaml deploy note).
  --
  -- Matrix client surface: /_matrix/** + the spec-required /.well-known/matrix/**
  -- delegation + /_synapse/** (host-scoped catch-all on the matrix host so the
  -- broader /api/** ROLE_USER floor below can never win the most-specific match on
  -- a matrix-host request that lacks an /_matrix prefix).
  ('hugmesh-be-gateway',  '/_matrix/**',               'ROLE_MATRIX',   true),  -- Matrix C-S API
  ('hugmesh-be-gateway',  '/_matrix/**',               'ROLE_MOD',      true),  -- (mod superset)
  ('hugmesh-be-gateway',  '/_matrix/**',               'ROLE_ADMIN',    true),  -- (admin superset)
  ('hugmesh-be-gateway',  '/.well-known/matrix/**',    'ROLE_MATRIX',   true),  -- Matrix client/server discovery
  ('hugmesh-be-gateway',  '/.well-known/matrix/**',    'ROLE_MOD',      true),  -- (mod superset)
  ('hugmesh-be-gateway',  '/.well-known/matrix/**',    'ROLE_ADMIN',    true),  -- (admin superset)
  ('hugmesh-be-gateway',  '/_synapse/**',              'ROLE_MATRIX',   true),  -- Synapse-compat surface (host-scoped)
  ('hugmesh-be-gateway',  '/_synapse/**',              'ROLE_MOD',      true),  -- (mod superset)
  ('hugmesh-be-gateway',  '/_synapse/**',              'ROLE_ADMIN',    true),  -- (admin superset)
  -- Mastodon client surface: /api/v1/** + /api/v2/** + /oauth/** + media/streaming
  -- (the host-scoped catch-alls so the /api/** ROLE_USER floor never wins on a
  -- mastodon-host request).
  ('hugmesh-be-gateway',  '/api/v1/**',                'ROLE_MASTODON', true),  -- Mastodon REST API v1
  ('hugmesh-be-gateway',  '/api/v1/**',                'ROLE_MOD',      true),  -- (mod superset)
  ('hugmesh-be-gateway',  '/api/v1/**',                'ROLE_ADMIN',    true),  -- (admin superset)
  ('hugmesh-be-gateway',  '/api/v2/**',                'ROLE_MASTODON', true),  -- Mastodon REST API v2
  ('hugmesh-be-gateway',  '/api/v2/**',                'ROLE_MOD',      true),  -- (mod superset)
  ('hugmesh-be-gateway',  '/api/v2/**',                'ROLE_ADMIN',    true),  -- (admin superset)
  ('hugmesh-be-gateway',  '/oauth/**',                 'ROLE_MASTODON', true),  -- Mastodon OAuth
  ('hugmesh-be-gateway',  '/oauth/**',                 'ROLE_MOD',      true),  -- (mod superset)
  ('hugmesh-be-gateway',  '/oauth/**',                 'ROLE_ADMIN',    true),  -- (admin superset)
  ('hugmesh-be-gateway',  '/media/**',                 'ROLE_MASTODON', true),  -- Mastodon media
  ('hugmesh-be-gateway',  '/media/**',                 'ROLE_MOD',      true),  -- (mod superset)
  ('hugmesh-be-gateway',  '/media/**',                 'ROLE_ADMIN',    true),  -- (admin superset)
  ('hugmesh-be-gateway',  '/api/v1/streaming/**',      'ROLE_MASTODON', true),  -- Mastodon streaming
  ('hugmesh-be-gateway',  '/api/v1/streaming/**',      'ROLE_MOD',      true),  -- (mod superset)
  ('hugmesh-be-gateway',  '/api/v1/streaming/**',      'ROLE_ADMIN',    true),  -- (admin superset)
  -- ── EXTERNAL-CLIENT (personal-client / native-app) ISSUANCE rows ───────────
  -- Personal native clients (Element/Tusky/Ivory) reach the homeservers ONLY
  -- through the gateway (sole ingress; raw homeserver unreachable per the
  -- NetworkPolicy+mTLS isolation). The token-ISSUANCE sub-paths are gated by the
  -- DEDICATED external-client roles ROLE_MATRIX_EXTERNAL_CLIENT /
  -- ROLE_MASTODON_EXTERNAL_CLIENT (seeded in manifests/casdoor/init-data-configmap.yaml),
  -- which are SEPARATE from the base ROLE_MATRIX/ROLE_MASTODON. Base role =
  -- use-via-OUR-UI (brokered token); external-client role = may register/use a
  -- NATIVE client through the passthrough. Mods/admins grant/revoke the external-
  -- client role; removing it revokes the user's personal-client tokens at the
  -- gateway (HomeserverTokenRevocationFilter, external-client:<localpart>:<platform>,
  -- kind=personal only) WITHOUT touching our-UI access. PARITY with the gateway
  -- CanonicalSeed (hugmesh-gateway). Token-USAGE (/_matrix/**, /api/v1/**,
  -- /api/v2/**) stays gated by the base roles above + the revocation filter.
  --
  -- The brokered mint our BFFs run does NOT traverse these issuance paths: it runs
  -- as an INTERNAL service identity that the GatewayRouteAccessFilter short-circuits
  -- (or via an internal route bypassing this gate), so these external-client rows
  -- govern only genuine native-client issuance traffic and never lock out
  -- ROLE_USER/MOD/ADMIN using OUR UI. Versioned Matrix login variants (v3, r0) are
  -- enumerated explicitly rather than assuming one '*' covers them.
  --   Mastodon issuance: OAuth flow + dynamic app registration.
  ('hugmesh-be-gateway',  '/oauth/**',                 'ROLE_MASTODON_EXTERNAL_CLIENT',  true),  -- Mastodon OAuth (token/authorize) — external client
  ('hugmesh-be-gateway',  '/api/v1/apps',              'ROLE_MASTODON_EXTERNAL_CLIENT',  true),  -- Mastodon app registration — external client
  --   Matrix issuance: client login + device registration (versioned).
  ('hugmesh-be-gateway',  '/_matrix/client/v3/login',  'ROLE_MATRIX_EXTERNAL_CLIENT',    true),  -- Matrix login (v3) — external client
  ('hugmesh-be-gateway',  '/_matrix/client/r0/login',  'ROLE_MATRIX_EXTERNAL_CLIENT',    true),  -- Matrix login (r0) — external client
  ('hugmesh-be-gateway',  '/_matrix/client/v3/register', 'ROLE_MATRIX_EXTERNAL_CLIENT',  true),  -- Matrix register/device (v3) — external client
  ('hugmesh-be-gateway',  '/_matrix/client/r0/register', 'ROLE_MATRIX_EXTERNAL_CLIENT',  true),  -- Matrix register/device (r0) — external client
  -- ── Image-builder console seam (build-distribution) + superadmin infra console ─
  -- PARITY with the merged gateway CanonicalSeed.java (hugmesh-gateway repo).
  -- The mesh-WORKLOAD image-build surface is gated on the GRANTED capability
  -- ROLE_IMAGE_BUILDER (NOT an admin default): an admin reaches it ONLY if
  -- separately granted that role. Do NOT pair ROLE_ADMIN on /bff/image-builds/** —
  -- that would let every per-domain admin build images, breaking the build≠run /
  -- workload-vs-arch boundary. The arch/core build sub-surface + the superadmin
  -- infra console stay SUPERADMIN-only by longest-pattern-match: /bff/image-builds/
  -- arch/** is LONGER than /bff/image-builds/**, so it wins. SUPERADMIN reaches
  -- ordinary admin paths via the gateway cross-domain bypass, so it needs no
  -- per-surface row there.
  --
  -- ⚠ ORPHANED, ON PURPOSE, AND KEPT (audited 2026-08-26). All EIGHT '/bff/…'
  -- rows on hugmesh-be-gateway — the three immediately below, plus
  -- /bff/superadmin/games-services/**, /bff/games-services/instances/**,
  -- /bff/games-services/catalog/**, /bff/superadmin/workloads/** and
  -- /bff/admin/workloads/** further down — govern a path this gateway does NOT
  -- ROUTE: apps/20-gateway-be.yaml declares no /bff route at all. They
  -- were the whole reason the superadmin console looked "already granted" while
  -- being unreachable from a browser (see the fe-gateway '/bff/superadmin/**' row
  -- and its note, further down). They are NOT deleted, for three reasons:
  --   1. THEY GRANT NOTHING. This table is consulted only for a request the
  --      gateway has already matched to a route, so an allow row with no route
  --      cannot admit traffic. Deleting them removes documentation, not risk.
  --   2. optional-services.yaml KEYS ON THEM. games.routeAccessRows and
  --      workloadConsole.routeAccessRows list
  --      { gateway: hugmesh-be-gateway, urlPattern: /bff/… } tuples that
  --      gate_optional_services removes on deselection; deleting the rows here
  --      would leave those entries pointing at nothing (and
  --      tests/stack/test-optional-services-exclude.sh reads that pairing).
  --   3. THE BE GATEWAY IS A LEGITIMATE SECOND DOOR. It fronts api.<domain> and
  --      the tailnet; if a /bff route is ever added there, the access posture must
  --      already be written down — that is exactly the "gateway-scoped write"
  --      hazard test-mfa-required-rules.sh defect (c) exists for.
  -- What IS enforced instead: tests/scripts/test-superadmin-bff-reachability.sh
  -- pins this orphan set by name, so a NEW un-routed /bff row fails loudly rather
  -- than quietly reading as a grant.
  ('hugmesh-be-gateway',  '/bff/image-builds/arch/**', 'ROLE_SUPERADMIN',    true),  -- arch/core builds: superadmin only (tailnet; wins, longer) — ORPHANED: no /bff route on be
  ('hugmesh-be-gateway',  '/bff/image-builds/**',      'ROLE_IMAGE_BUILDER', true),  -- mesh-workload builds: image_builder (admins granted it)
  ('hugmesh-be-gateway',  '/bff/superadmin/**',        'ROLE_SUPERADMIN',    true),  -- superadmin infra console (tailnet) — ORPHANED: no /bff route on be
  ('hugmesh-be-gateway',  '/api/admin/**',         'ROLE_ADMIN',     true),  -- hugmesh admin API (NOT ROLE_MOD)
  -- hugmesh-games NAMESPACE admin (games BFF /api/admin/** surface, namespaced
  -- under /games/** so it does NOT collide with the platform /api/admin/** row
  -- above). The requirement is games + (admin|mod): nobody reaches this surface
  -- unless they hold ROLE_GAMES AND (ROLE_ADMIN OR ROLE_MOD). That AND is
  -- materialized in Casdoor as the DERIVED role ROLE_GAMES_ADMIN (membership =
  -- ROLE_GAMES intersect (ROLE_ADMIN union ROLE_MOD), reconciled by games-admin-sync
  -- — see manifests/casdoor/init-data-configmap.yaml). This is the SINGLE allow
  -- row for the surface and keys on ROLE_GAMES_ADMIN ONLY — NOT ROLE_GAMES,
  -- ROLE_ADMIN, or ROLE_MOD individually — so the gateway's OR-of-allow-rows table
  -- still yields the AND, and any single role is default-deny. More specific than
  -- the /api/** ROLE_USER floor, so it wins the most-specific match.
  ('hugmesh-be-gateway',  '/games/api/admin/**',   'ROLE_GAMES_ADMIN', true),  -- games namespace admin API (games + (admin|mod) ONLY)
  -- ── OPTIONAL slug `games` — games portal floor on the games.<GAMES_DOMAIN> host ──
  -- The games BFF/portal surface under /games/** (games members reach the portal;
  -- the more-specific /games/api/admin/** row above wins for the admin API). Keyed
  -- on the network-wide ROLE_GAMES access role; a games BAN is role removal ->
  -- governed-but-ungranted -> DENY. ADMIN/MOD paired so they keep reaching it.
  -- ⚠ gate_optional_services REMOVES these rows + the games host route when the
  -- games slug is deselected (see optional-services.yaml games.routeAccessRows).
  ('hugmesh-be-gateway',  '/games/**',             'ROLE_GAMES',     true),  -- games portal floor (games-access)
  ('hugmesh-be-gateway',  '/games/**',             'ROLE_ADMIN',     true),  -- (admins superset)
  ('hugmesh-be-gateway',  '/games/**',             'ROLE_MOD',       true),  -- (mods superset)
  -- ── GAMES APP-STORE (games-services control plane) — admin-bff surfaces ──────────
  -- The per-domain FOSS game-server app-store control plane (catalog + offers +
  -- instances) lives in the admin-bff under /bff/superadmin/games-services/** (global
  -- catalog curation, SUPERADMIN ONLY) and /bff/games-services/** (per-domain
  -- admin/runner instance ops). The admin-bff itself ALSO enforces these via
  -- @PreAuthorize + DomainScope; these gateway rows are the coarse defence-in-depth
  -- (most-specific match wins, ahead of the /bff/admin/** floor). The DERIVED roles
  -- ROLE_GAMES_SERVICES_ADMIN (= ROLE_GAMES_SERVICES ∩ (ROLE_ADMIN ∪ ROLE_MOD)) and
  -- ROLE_GAMES_SERVICES_RUNNER (= ROLE_GAMES_SERVICES ∩ ROLE_MOD) are materialized by
  -- games-services-{admin,runner}-sync (manifests/casdoor); keying a surface on a
  -- single derived role yields the required AND (any single input role is default-deny).
  -- ⚠ gate_optional_services REMOVES these rows when the games slug is deselected
  -- (see optional-services.yaml games.routeAccessRows).
  ('hugmesh-be-gateway',  '/bff/superadmin/games-services/**', 'ROLE_SUPERADMIN', true),  -- global catalog + per-domain offers (SUPERADMIN ONLY)
  ('hugmesh-be-gateway',  '/bff/games-services/instances/**',  'ROLE_GAMES_SERVICES_ADMIN',  true),  -- create/run/stop instances (games-services ∩ (admin|mod))
  ('hugmesh-be-gateway',  '/bff/games-services/instances/**',  'ROLE_GAMES_SERVICES_RUNNER', true),  -- mod-delegated run/stop (games-services ∩ mod)
  ('hugmesh-be-gateway',  '/bff/games-services/catalog/**',    'ROLE_GAMES_SERVICES',        true),  -- read offered catalog (games-services-access floor)
  -- HTTP game consoles, path-routed by be-gateway to per-instance Services (PR7). A
  -- games-services member reaches a running console; admins/mods are supersets.
  ('hugmesh-be-gateway',  '/games/servers/**',     'ROLE_GAMES_SERVICES', true),  -- per-instance HTTP console floor
  ('hugmesh-be-gateway',  '/games/servers/**',     'ROLE_ADMIN',          true),  -- (admins superset)
  ('hugmesh-be-gateway',  '/games/servers/**',     'ROLE_MOD',            true),  -- (mods superset)
  -- ── WORKLOAD CONSOLE (podman/OpenShift-equivalent pod-mgmt + live-log + exec) ──────
  -- The admin-bff surfaces /bff/admin/workloads/** (ADMIN read-only own-domain, grant-gated)
  -- and /bff/superadmin/workloads/** (SUPERADMIN cross-cluster read + RUNTIME_MUTATE/exec/
  -- port-forward/lifecycle). The admin-bff itself is the TOTAL authz predicate (the central
  -- WebFilter: dangerous-tier kill + namespace allowlist + grant + step-up + Lease + device/
  -- SSH-license); these gateway rows are the coarse defence-in-depth, MORE SPECIFIC than the
  -- /bff/admin/** and /bff/superadmin/** floors so they win the most-specific match. The
  -- DANGEROUS surfaces (logs-stream / exec / exec-tty WS / port-forward) are reachable ONLY
  -- over the TAILNET (the superadmin surface is tailnet-only by deployment — same posture as
  -- /bff/superadmin/** infra console). SHIPS DARK: the admin-bff gate
  -- (app.workload-console.enabled) + the DB master flag + an active grant all default off.
  -- ⚠ gate_optional_services REMOVES these rows when the workloadConsole slug is deselected
  -- (see optional-services.yaml workloadConsole.routeAccessRows). DEFAULT: deselected.
  ('hugmesh-be-gateway',  '/bff/superadmin/workloads/**', 'ROLE_SUPERADMIN', true),  -- workload console superadmin (cross-cluster read + mutate/exec/port-forward; tailnet-only)
  ('hugmesh-be-gateway',  '/bff/admin/workloads/**',      'ROLE_ADMIN',      true),  -- workload console admin (read-only own-domain, grant-gated by the BFF)
  -- hugmesh-federation-api module-federation registry/manifest/bundles API. MORE
  -- SPECIFIC than the /api/** floor below, so it wins the most-specific match.
  -- Single ROLE_USER row = the coarse authenticated floor (lets a logged-in
  -- caller reach the manifest + bundles); fine-grained authz (modules/overrides=
  -- ROLE_ADMIN, moderation=ROLE_MOD/ADMIN) is enforced INSIDE federation's
  -- SecurityConfig, NOT mirrored here (the converter does not auto-grant ROLE_USER
  -- to admins/mods, so per-subpath ROLE_ADMIN/ROLE_MOD rows would have to be
  -- duplicated — the single floor row keeps it self-contained, matching /api/**).
  ('hugmesh-be-gateway',  '/api/federation/**',    'ROLE_USER',      true),  -- federation registry/manifest/bundles (authenticated floor; ADMIN/MOD enforced in federation)
  -- Forum admin-console seam on the api host (admin-bff -> forum-bff, if exposed
  -- on the be-gateway). ADMIN-only, MORE SPECIFIC than the /api/** floor so it wins
  -- the most-specific match. There is NO /api/forum/** floor row for phpBB itself —
  -- phpBB is backend-only and has NO be-gateway route (it is reachable ONLY as
  -- forum-bff's in-cluster upstream inside the hugmesh-forum default-deny ns).
  ('hugmesh-be-gateway',  '/api/forum/admin/**',   'ROLE_ADMIN',     true),  -- forum admin seam (admin-only; NO phpbb floor row)
  ('hugmesh-be-gateway',  '/api/**',               'ROLE_USER',      true),  -- hugmesh APIs
  -- edge-ai inference API (ai.<domain> host route -> Ollama /v1 on the GPU/edge_ai
  -- node). Authenticated floor: any mesh user may call the model API; finer
  -- per-domain gating can add a ROLE_EDGE_AI row (cf. ROLE_OWNCAST). Distinct /v1
  -- path space, so no overlap with /api/**. ⚠ OPTIONAL slug `edge-ai`:
  -- gate_optional_services drops this row when edge-ai is deselected.
  -- edge-ai-analysis task API (/v1/analyze/** -> the analysis wrapper). MORE SPECIFIC
  -- than /v1/** below; same ROLE_USER floor. ⚠ OPTIONAL slug `edge-ai-analysis`:
  -- gate_optional_services drops this row when edge-ai-analysis is deselected.
  ('hugmesh-be-gateway',  '/v1/analyze/**',        'ROLE_USER',      true),  -- edge-ai-analysis verdict API
  -- edge-ai-tts voice synthesis API (/v1/synthesize/** -> the Piper TTS wrapper;
  -- VN voice feature, B3). MORE SPECIFIC than /v1/** below; same ROLE_USER floor.
  -- ⚠ OPTIONAL slug `edge-ai-tts`: gate_optional_services drops this row when
  -- edge-ai-tts is deselected.
  ('hugmesh-be-gateway',  '/v1/synthesize/**',     'ROLE_USER',      true),  -- edge-ai-tts voice synthesis API
  ('hugmesh-be-gateway',  '/v1/**',                'ROLE_USER',      true),  -- edge-ai OpenAI-compatible inference API

  -- fe-gateway (hugmesh.net -> Angular host + MFEs + same-origin /bff)
  ('hugmesh-fe-gateway',  '/',                     'PUBLIC', true),  -- public front page
  -- The rest of the anonymous SPA shell the '/' row already implies: the
  -- document, the root-level hashed bundles the Angular browser build serves
  -- from the host-shell webroot (Ant '*' does not cross '/', so only webroot
  -- files match), the module-federation manifests, favicon and static assets.
  -- Mirrors the SecurityConfig FE_SHELL_PUBLIC_GET_PATHS floor (GET-only, fe
  -- tier only) so the coarse layer and the route-access layer agree the
  -- anonymous front page is servable. PARITY with the gateway CanonicalSeed
  -- fe() (hugmesh-gateway PR #72) — these rows were added there and were
  -- missing here (dual-write seed drift), this closes that gap.
  ('hugmesh-fe-gateway',  '/index.html',           'PUBLIC', true),  -- public (anon SPA shell doc)
  ('hugmesh-fe-gateway',  '/favicon.ico',          'PUBLIC', true),  -- public (anon SPA shell)
  ('hugmesh-fe-gateway',  '/importmap.json',       'PUBLIC', true),  -- public (module-federation import map)
  ('hugmesh-fe-gateway',  '/remoteEntry.json',     'PUBLIC', true),  -- public (module-federation remote entry)
  ('hugmesh-fe-gateway',  '/*.js',                 'PUBLIC', true),  -- public (webroot hashed JS bundles)
  ('hugmesh-fe-gateway',  '/*.css',                'PUBLIC', true),  -- public (webroot hashed CSS bundles)
  ('hugmesh-fe-gateway',  '/assets/**',            'PUBLIC', true),  -- public (static assets)
  -- Public federation reads (federation-api permitAll's both at the app layer;
  -- the cluster fe spec's vanity-subdomain route documents the gateway-side
  -- allowance as the deferred missing piece): the vanity profile resolve
  -- (path + Host-derived collection resolve) and the install-state
  -- capabilities projection a LOGGED-OUT host shell reads to grey-out
  -- optional services. Scoped to the exact public reads (NOT
  -- /api/federation/**) — the manifest / module-registry / username surfaces
  -- stay gated by the ROLE_USER floor row below. PARITY with the gateway
  -- CanonicalSeed fe() (hugmesh-gateway PR #72).
  ('hugmesh-fe-gateway',  '/api/federation/vanity',       'PUBLIC', true),  -- public (vanity profile/collection resolve)
  ('hugmesh-fe-gateway',  '/api/federation/vanity/**',    'PUBLIC', true),  -- public (vanity profile/collection resolve)
  ('hugmesh-fe-gateway',  '/api/federation/capabilities', 'PUBLIC', true),  -- public (install-state capabilities projection)
  -- The LOGGED-IN home page's second read: the host shell (federationApiBase:"")
  -- fetches /api/federation/manifest on the front-door origin to hydrate the
  -- service cards' module wiring. ROLE_USER (not PUBLIC): federation-api's own
  -- SecurityConfig requires an authenticated caller and ManifestService
  -- role/visibility-filters the payload — the row mirrors that floor exactly.
  ('hugmesh-fe-gateway',  '/api/federation/manifest',     'ROLE_USER', true),  -- logged-in home page module manifest
  -- ── MATRIX/MASTODON CLIENT SURFACE AT THE FRONT DOOR ──────────────────────
  -- Companion of the fe-gateway routes matrix-cs-api / matrix-wellknown /
  -- mastodon-client-api / mastodon-oauth (apps/20-gateway-fe.yaml +
  -- tests/stack/gateway-routes/fe/application-routes.yml). Exposing the CS-API at
  -- the front door is an ACCESS decision, so it is written down here rather than
  -- left implicit in a route table.
  --
  -- DECISION: the client protocol paths are OPEN — anonymous traffic reaches the
  -- homeserver, and authorization is the HOMESERVER's job, not the session's.
  --
  -- WHY NOT a bff_ session gate. A native client (Element/Tusky/Ivory) holds a
  -- MATRIX access token or a Mastodon OAuth token and NEVER holds a bff_ session
  -- cookie or a Casdoor JWT. Worse, the first two calls of the handshake —
  -- GET /_matrix/client/versions and POST /_matrix/client/v3/login — are
  -- pre-authentication BY DEFINITION: the client is asking how to log in. A
  -- session gate would 401 exactly those calls, so "gate it on bff_" does not
  -- mean "clients need to log in first", it means EXTERNAL CLIENTS CAN NEVER
  -- LOG IN AT ALL. The requirement and the gate are mutually exclusive.
  --
  -- WHY THIS IS SAFE. These are not unauthenticated admin surfaces; they are
  -- protocol endpoints that carry their own credential. tuwunel/Mastodon
  -- authenticate and authorize every non-discovery request themselves, and the
  -- only endpoints reachable without a token are the ones the spec REQUIRES to be
  -- public (version negotiation, login-flow advertisement, discovery).
  --
  -- THIS IS NOT A NEW HOLE — the floor was already open, only the route was
  -- missing. The shared gateway image permitAll's /_matrix/**, /.well-known/**,
  -- /api/v1/**, /api/v2/** and /oauth/** on EVERY tier via
  -- SecurityConfig.HOMESERVER_PASSTHROUGH_PATHS (hugmesh-gateway), documented
  -- there as: homeserver traffic carries an opaque token, not a Casdoor JWT, so
  -- requiring a JWT would 401 it before the real authz ever runs. Verified live
  -- against the compose front door BEFORE this change:
  --   GET https://localhost:8488/_matrix/client/versions       -> 200 text/html
  --   GET https://localhost:8488/.well-known/matrix/client     -> 200 text/html
  --   GET https://localhost:8488/be/_matrix/client/versions    -> 401
  -- The first two are the SPA fallback answering (200, NOT 401) — proof the coarse
  -- floor already admits these paths anonymously at the fe tier. The third 401s
  -- because /be/** is outside the passthrough list. So this change adds ROUTING to
  -- an already-open surface; it does not widen the security floor.
  --
  -- WHAT STILL GATES THIS SURFACE (defence in depth, all unchanged):
  --   * HomeserverTokenRevocationFilter resolves the Matrix/Mastodon bearer and
  --     denies revoked tokens — platform ban, per-credential revoke, and
  --     external-client revoke (kind=personal) all land here.
  --   * The rows BELOW: GatewayRouteAccessFilter forwards anonymous requests
  --     untouched, but any request that DOES carry a Casdoor principal (our own
  --     UIs proxied with the user's session) must hold the per-platform access
  --     role. A platform ban is the ABSENCE of the role, so it still bites.
  --   * The banners only advertise the URL to holders of the dedicated
  --     ROLE_*_EXTERNAL_CLIENT grant, which mods/admins issue and revoke.
  --
  -- These rows MIRROR the be-gateway posture verbatim (same patterns, same roles,
  -- ~40 lines above) — the fe front door is now a second ingress to the same
  -- homeservers, so it must not be MORE permissive than the first. Deliberately
  -- NO PUBLIC row: PUBLIC would also waive the role check for authenticated
  -- callers, which is precisely the ban-enforcement we want to keep.
  ('hugmesh-fe-gateway',  '/_matrix/**',               'ROLE_MATRIX',   true),  -- Matrix C-S API (front door)
  ('hugmesh-fe-gateway',  '/_matrix/**',               'ROLE_MOD',      true),  -- (mod superset)
  ('hugmesh-fe-gateway',  '/_matrix/**',               'ROLE_ADMIN',    true),  -- (admin superset)
  ('hugmesh-fe-gateway',  '/.well-known/matrix/**',    'ROLE_MATRIX',   true),  -- Matrix client/server discovery
  ('hugmesh-fe-gateway',  '/.well-known/matrix/**',    'ROLE_MOD',      true),  -- (mod superset)
  ('hugmesh-fe-gateway',  '/.well-known/matrix/**',    'ROLE_ADMIN',    true),  -- (admin superset)
  ('hugmesh-fe-gateway',  '/api/v1/**',                'ROLE_MASTODON', true),  -- Mastodon REST API v1 (front door)
  ('hugmesh-fe-gateway',  '/api/v1/**',                'ROLE_MOD',      true),  -- (mod superset)
  ('hugmesh-fe-gateway',  '/api/v1/**',                'ROLE_ADMIN',    true),  -- (admin superset)
  ('hugmesh-fe-gateway',  '/api/v2/**',                'ROLE_MASTODON', true),  -- Mastodon REST API v2 (front door)
  ('hugmesh-fe-gateway',  '/api/v2/**',                'ROLE_MOD',      true),  -- (mod superset)
  ('hugmesh-fe-gateway',  '/api/v2/**',                'ROLE_ADMIN',    true),  -- (admin superset)
  ('hugmesh-fe-gateway',  '/oauth/**',                 'ROLE_MASTODON', true),  -- Mastodon OAuth (front door)
  ('hugmesh-fe-gateway',  '/oauth/**',                 'ROLE_MOD',      true),  -- (mod superset)
  ('hugmesh-fe-gateway',  '/oauth/**',                 'ROLE_ADMIN',    true),  -- (admin superset)
  -- External-client ISSUANCE rows, mirroring the be-gateway block above: the
  -- dedicated ROLE_*_EXTERNAL_CLIENT grant is what a NATIVE client's token mint
  -- needs, separate from the base use-via-our-UI roles. Same longest-pattern-match
  -- reasoning as be (these patterns are longer than /_matrix/** and /oauth/**).
  ('hugmesh-fe-gateway',  '/_matrix/client/v3/login',    'ROLE_MATRIX_EXTERNAL_CLIENT',    true),  -- Matrix login (v3) — external client
  ('hugmesh-fe-gateway',  '/_matrix/client/r0/login',    'ROLE_MATRIX_EXTERNAL_CLIENT',    true),  -- Matrix login (r0) — external client
  ('hugmesh-fe-gateway',  '/_matrix/client/v3/register', 'ROLE_MATRIX_EXTERNAL_CLIENT',    true),  -- Matrix register/device (v3) — external client
  ('hugmesh-fe-gateway',  '/_matrix/client/r0/register', 'ROLE_MATRIX_EXTERNAL_CLIENT',    true),  -- Matrix register/device (r0) — external client
  ('hugmesh-fe-gateway',  '/api/v1/apps',                'ROLE_MASTODON_EXTERNAL_CLIENT',  true),  -- Mastodon app registration — external client
  ('hugmesh-fe-gateway',  '/oauth/**',                   'ROLE_MASTODON_EXTERNAL_CLIENT',  true),  -- Mastodon OAuth (token/authorize) — external client
  ('hugmesh-fe-gateway',  '/social/matrix/**',     'ROLE_USER',      true),
  ('hugmesh-fe-gateway',  '/social/mastodon/**',   'ROLE_USER',      true),
  -- phpBB forum micro-frontend UI (hugmesh-forum-ui at /social/forum/**),
  -- served at the apex PATH (NOT a forum. subdomain — the *.hugmesh.net
  -- vanity wildcard would swallow forum.<domain>). Gated by the dedicated forum
  -- ACCESS role ROLE_FORUM (the new Casdoor forum-access role) — congruent with
  -- how /social/matrix + /social/mastodon gate the social shells, and the model
  -- ban-by-role-removal uses (drop ROLE_FORUM -> this row default-denies on the
  -- next refresh). Admins reach it via the gateway admin-bypass (the converter does
  -- NOT grant admins ROLE_FORUM), so do NOT pair ROLE_ADMIN here — matching the
  -- matrix/mastodon floors which pair no ROLE_ADMIN. The phpBB pod itself has NO
  -- route row (backend-only, isolated in hugmesh-forum).
  ('hugmesh-fe-gateway',  '/social/forum/**',      'ROLE_FORUM',     true),  -- phpBB forum UI (forum-access floor)
  -- DB-hosted module-federation FRAGMENT bundles served by the remote-fragment
  -- static fleet (user-profile/card + admin contained-pages). The authenticated
  -- host's loadRemoteModule fetches them; they are content-addressed (non-secret)
  -- bytes and visibility is enforced upstream (federation emits only enabled/
  -- visible modules into its manifest), so the gateway gate is the ROLE_USER floor
  -- (the host itself loads them only after login). If anonymous profile cards are
  -- ever needed, add a sibling PUBLIC row for the public sub-path.
  ('hugmesh-fe-gateway',  '/_fragments/**',        'ROLE_USER',      true),
  -- NATIVE-LOGIN: the login-ui SPA shell is ANONYMOUS (the only login surface now
  -- that Casdoor's hosted page is never browser-exposed; a logged-out visitor holds
  -- no role yet, so ROLE_USER was a chicken-and-egg lock-out). PUBLIC matches the
  -- gateway SecurityConfig FE_SHELL_PUBLIC_GET_PATHS `/login/**`. Pairs with the
  -- `/bff/login` PUBLIC row below.
  ('hugmesh-fe-gateway',  '/login/**',             'PUBLIC',         true),
  ('hugmesh-fe-gateway',  '/admin/**',             'ROLE_ADMIN',     true),
  -- Moderation micro-frontend UI (hugmesh-mod-ui at /mod/**). ROLE_MOD floor;
  -- ROLE_ADMIN paired so admins (a superset that the converter does NOT
  -- auto-grant ROLE_MOD/USER to) keep reaching the moderation UI. More specific
  -- than the /** front-page catch-all, so it wins the most-specific match.
  ('hugmesh-fe-gateway',  '/mod/**',               'ROLE_MOD',       true),  -- moderation UI (mod floor)
  ('hugmesh-fe-gateway',  '/mod/**',               'ROLE_ADMIN',     true),  -- (admins superset)
  -- Self-service user micro-frontend UI (hugmesh-user-ui at /user/**). The
  -- authenticated floor — any logged-in principal reaches their own profile/prefs.
  ('hugmesh-fe-gateway',  '/user/**',              'ROLE_USER',      true),  -- user self-service UI
  -- Character Studio (VN) micro-frontend UI (hugmesh-character-studio-ui at
  -- /character-studio/**). Authenticated floor — any logged-in principal reaches it.
  -- ⚠ gate_optional_services REMOVES this row when the character-studio slug is
  -- deselected (so a matched route to a pruned upstream cannot stale-grant / 502).
  ('hugmesh-fe-gateway',  '/character-studio/**',  'ROLE_USER',      true),  -- character-studio VN UI
  -- Character Forge (3D) micro-frontend UI (hugmesh-character-forge-ui at
  -- /character-forge/**). Authenticated floor — any logged-in principal reaches it.
  -- ⚠ gate_optional_services REMOVES this row when the character-forge slug is
  -- deselected (so a matched route to a pruned upstream cannot stale-grant / 502).
  ('hugmesh-fe-gateway',  '/character-forge/**',   'ROLE_USER',      true),  -- character-forge 3D UI
  -- API documentation micro-frontend UI (hugmesh-api-docs at /api-docs/**) —
  -- the path the fe gateway route, the prod federation manifest
  -- ("apidocs": "/api-docs/remoteEntry.json") and the image base-href all use.
  -- ROLE_ADMIN only — the rendered OpenAPI/spec docs are admin-gated, matching
  -- federation's spec floor (its swagger-ui is ROLE_ADMIN).
  ('hugmesh-fe-gateway',  '/api-docs/**',          'ROLE_ADMIN',     true),  -- API docs UI (admin only)
  -- hugmesh-games namespace admin UI (games admin surface, namespaced under
  -- /games/** so it does NOT collide with the platform /admin/** row above). Same
  -- games + (admin|mod) gate: keyed on the DERIVED composite ROLE_GAMES_ADMIN
  -- ONLY (= ROLE_GAMES intersect (ROLE_ADMIN union ROLE_MOD)), so a single role
  -- is default-deny. More specific than /admin/** (different prefix) and self-
  -- contained — the one allow row encodes the AND.
  ('hugmesh-fe-gateway',  '/games/admin/**',       'ROLE_GAMES_ADMIN', true),  -- games namespace admin UI (games + (admin|mod) ONLY)
  -- ── games member + games admin SCREENS on the fe gateway (2026-10-28) ─────────
  -- The `games` native-federation remote (hugmesh-games/games-ui) is mounted by
  -- the host shell at /games (member catalog + play) and /games/admin (admin
  -- surfaces), and talks ONLY to the games BFF through the fe-gateway route
  -- games-bff (Path=/games/api/**, StripPrefix=1). Three rows, longest pattern
  -- wins, PAIRED SUPERSETS exactly like the be-gateway /games/** trio above:
  --   /games/api/admin/** -> ROLE_GAMES_ADMIN only (the derived composite — the
  --                          admin API is games AND (admin|mod), same AND as the
  --                          /games/admin/** HTML row above and the be-gateway
  --                          /games/api/admin/** row);
  --   /games/api/**       -> ROLE_GAMES floor + ROLE_ADMIN/ROLE_MOD supersets
  --                          (the member API: catalog, launch, launches);
  --   /games/**           -> ROLE_GAMES floor + ROLE_ADMIN/ROLE_MOD supersets
  --                          (remoteEntry.json + chunks + the member HTML path).
  -- The remote's bundle bytes live under /games/, never under /games/admin/, so
  -- the pre-existing /games/admin/** row keeps gating ONLY the admin HTML path —
  -- a ROLE_GAMES member loads the remote, and the host shell's gamesAdminGuard +
  -- this table's /games/api/admin/** row keep the admin screens and API closed.
  -- Identical rows live in hugmesh-gateway CanonicalSeed.java fe() and
  -- hugmesh-gateway compose/route-access-seed.sql (the three sources must stay
  -- identical). ⚠ gate_optional_services REMOVES these rows when the games slug
  -- is deselected (optional-services.yaml games.routeAccessRows).
  ('hugmesh-fe-gateway',  '/games/api/admin/**',   'ROLE_GAMES_ADMIN', true),  -- games BFF admin API via the browser door (games + (admin|mod) ONLY)
  ('hugmesh-fe-gateway',  '/games/api/**',         'ROLE_GAMES',     true),  -- games BFF member API floor (games-access)
  ('hugmesh-fe-gateway',  '/games/api/**',         'ROLE_ADMIN',     true),  -- (admins superset)
  ('hugmesh-fe-gateway',  '/games/api/**',         'ROLE_MOD',       true),  -- (mods superset)
  ('hugmesh-fe-gateway',  '/games/**',             'ROLE_GAMES',     true),  -- games remote + member screens floor (games-access)
  ('hugmesh-fe-gateway',  '/games/**',             'ROLE_ADMIN',     true),  -- (admins superset)
  ('hugmesh-fe-gateway',  '/games/**',             'ROLE_MOD',       true),  -- (mods superset)
  -- GAMES APP-STORE operator UI (the admin-ui federated remote at /admin/games-services,
  -- PR8). Keyed on the DERIVED ROLE_GAMES_SERVICES_ADMIN ONLY (= ROLE_GAMES_SERVICES ∩
  -- (ROLE_ADMIN ∪ ROLE_MOD)), so a single role is default-deny — the one allow row
  -- encodes the AND. The RUNNER (mod) reaches the same operator UI for run/stop; the UI
  -- greys-out create/enable for a runner (the BFF authz is the real gate). More specific
  -- than the /admin/** floor (longer prefix). ⚠ gate_optional_services REMOVES this row
  -- when the games slug is deselected.
  ('hugmesh-fe-gateway',  '/admin/games-services/**', 'ROLE_GAMES_SERVICES_ADMIN',  true),  -- games app-store operator UI (games-services ∩ (admin|mod))
  ('hugmesh-fe-gateway',  '/admin/games-services/**', 'ROLE_GAMES_SERVICES_RUNNER', true),  -- runner reaches the operator UI for run/stop (BFF greys-out create)
  -- PUBLIC announcements read surface for the anonymous LOGIN page banner
  -- (admin-bff GET /bff/public/announcements/login -> permitAll, see the admin-bff
  -- SecurityConfig + the shared announcements API contract). The login page is
  -- shown BEFORE a Casdoor JWT exists, so this read path must pass the gateway
  -- unauth'd — mirror the front-page '/' PUBLIC row. More SPECIFIC than the
  -- /bff/login + /bff/admin/** etc. ROLE_USER/ROLE_ADMIN rows below (distinct
  -- /bff/public/ prefix), so most-specific-match keeps it anonymous WITHOUT
  -- opening any other /bff/** subpath. Anonymous body_html is sanitized
  -- server-side at write + rendered in a sandboxed srcdoc iframe by the UI.
  ('hugmesh-fe-gateway',  '/bff/public/announcements/**', 'PUBLIC', true),  -- public login-page announcements (UNAUTHENTICATED)
  -- PUBLIC appeal-contact resolver for the login-ui appeal page shown to a
  -- banned/suspended (or logged-out) user (admin-bff GET /bff/public/appeal-contact
  -- -> permitAll, returns {"email":"..."}, no PII). Reached BEFORE a Casdoor JWT
  -- exists, so it must pass the gateway unauth'd. Mirrors the gateway CanonicalSeed
  -- fe() row + SecurityConfig PUBLIC_PATHS (hugmesh-gateway PR #22). EXACT path
  -- (not /bff/public/**) so most-specific-match keeps ONLY this resolver anonymous.
  ('hugmesh-fe-gateway',  '/bff/public/appeal-contact', 'PUBLIC', true),  -- public appeal-contact resolver (UNAUTHENTICATED)
  -- NATIVE-LOGIN credential submit (UNAUTHENTICATED): the anonymous browser POSTs
  -- {username,password} from OUR login-ui form to /bff/login BEFORE it holds any
  -- session/role; user-bff drives Casdoor /api/login server-side and mints the opaque
  -- bff_ session (no token reaches the browser). PUBLIC matches the gateway
  -- SecurityConfig PUBLIC_PATHS `/bff/login`; ROLE_USER was a chicken-and-egg lock-out.
  ('hugmesh-fe-gateway',  '/bff/login',            'PUBLIC',         true),
  -- ANONYMOUS PASSWORD RESET (UNAUTHENTICATED). The forgot-password legs on
  -- user-bff (PasswordResetController): the visitor has NO session and NO working
  -- credential BY DEFINITION — that is the situation the flow exists to repair —
  -- so ROLE_USER here would be the same chicken-and-egg lock-out `/bff/login`
  -- documents one line above. Until these rows existed there was no password
  -- reset anywhere in the platform and a forgotten password was PERMANENT.
  --
  -- TWO EXACT PATHS, deliberately NOT a '/bff/password-reset/**' subtree: a
  -- sibling endpoint added under that prefix later would inherit anonymity by
  -- accident. Same scoping discipline as the '/bff/public/appeal-contact' row
  -- above (which explains the identical choice), and it matches the BFF's own
  -- SecurityConfig, which permits the two exact paths and nothing else.
  --
  -- THREE LAYERS MUST AGREE and these rows are only one of them. The gateway's
  -- coarse anyExchange().authenticated() floor runs BEFORE this table is ever
  -- consulted, so hugmesh-gateway SecurityConfig.PUBLIC_PATHS needs the SAME two
  -- exact paths — the front-page-parity invariant this file documents throughout.
  -- The third is the fe-gateway ROUTE itself (20-gateway-fe.yaml + the compose
  -- tests/stack/gateway-routes/fe/application-routes.yml predicate list).
  ('hugmesh-fe-gateway',  '/bff/password-reset/request', 'PUBLIC',   true),  -- forgot-password: request a mailed code (UNAUTHENTICATED)
  ('hugmesh-fe-gateway',  '/bff/password-reset/confirm', 'PUBLIC',   true),  -- forgot-password: redeem the code (UNAUTHENTICATED)
  ('hugmesh-fe-gateway',  '/bff/register/**',      'ROLE_USER',      true),
  ('hugmesh-fe-gateway',  '/bff/provision/**',     'ROLE_USER',      true),
  ('hugmesh-fe-gateway',  '/bff/me/**',            'ROLE_USER',      true),
  -- ── SUPERADMIN CONSOLE AT THE FRONT DOOR — INCIDENT NARRATIVE (2026-08-26) ─
  -- ⚠ THE ROW THIS BLOCK DESCRIBES IS NOT INSERTED HERE. It is the fe-gateway
  -- '/bff/superadmin/**' -> ROLE_SUPERADMIN row in the "SUPERADMIN PLATFORM
  -- CONSOLE at the PUBLIC BROWSER DOOR (#244, ACCEPT)" block FURTHER DOWN in this
  -- file. Merge note, 2026-09-16 (#351, operator decision 20 "land the whole
  -- branch"): `integrate/superadmin` carried its own copy of that row from
  -- `fix/superadmin-route-access-row`, and main had landed the same row
  -- independently under decision 8. Git merged both in with no conflict, which
  -- produced a DUPLICATE (gateway, url_pattern, role) tuple — which the conflict
  -- clause at the foot of this INSERT tolerates silently at seed time, so it would
  -- never have surfaced as an error, but two rows carrying two different
  -- rationales for one rule. (That clause is deliberately NOT spelled out in full
  -- here: scripts/gen-route-access-oracle.py cuts this INSERT's body at the first
  -- occurrence of that token BEFORE it strips `--` comments, so naming it inside a
  -- comment ABOVE the real one truncates the generated e2e oracle. Measured
  -- 2026-09-16 on this very block: 154 rows -> 119, losing every
  -- hugmesh-superadmin-gateway row, and both of the generator's vacuity floors
  -- (MIN_ROWS 100, MIN_FE_ROWS 50) still passed. Filed as its own issue.)
  -- The branch's copy was
  -- DROPPED and main's kept (decision 20 also closes that branch as superseded).
  -- The analysis below is kept because it is the incident record, and because the
  -- DENY row below it is genuinely new.
  -- OBSERVED: there was NO browser path to ANY /bff/superadmin/** endpoint, on
  -- any gateway a browser can reach. The two halves of the routing contract had
  -- drifted apart in opposite directions and each half looked correct alone:
  --
  --   * hugmesh-fe-gateway ROUTES the family. apps/20-gateway-fe.yaml ends with
  --     the `Path=/bff/**` catch-all to hugmesh-admin-bff-api (and the compose
  --     lane, tests/stack/gateway-routes/fe/application-routes.yml, ends the same
  --     way), so /bff/superadmin/anything is forwarded to admin-bff — which is
  --     the correct upstream, since every superadmin surface named below IS an
  --     admin-bff controller. But the fe-gateway had NO /bff/superadmin row, and
  --     a routed path with zero matching allow rows is DEFAULT-DENY.
  --   * hugmesh-be-gateway had the allow rows (/bff/superadmin/**,
  --     /bff/superadmin/games-services/**, /bff/superadmin/workloads/**,
  --     /bff/image-builds/**) and ZERO /bff routes — apps/20-gateway-be.yaml
  --     declares no /bff route at all, so those rows govern traffic that
  --     never arrives. They grant nothing; they are also harmless (see below).
  --
  -- The consequence was silent and total: the already-shipped admin-ui superadmin
  -- pages — backing-services, fleet-entitlements, phone-devices, the desktop
  -- dials, and the superadmin half of the workload console — were dead ends. The
  -- gateway is not "missing a feature"; it correctly default-denies a surface
  -- nobody ever granted. This row is the grant.
  --
  -- WHY A SINGLE `**` FLOOR AND NOT PER-PAGE ROWS: /bff/superadmin/** is already
  -- the shape used on both other gateways, so the three doors now agree. Rows are
  -- resolved by LONGEST MATCHING url_pattern (see this file's header and
  -- tests/scripts/test-mfa-required-rules.sh defect (b)), NOT by position in this
  -- INSERT — so this floor cannot shadow, and cannot be shadowed by, anything:
  -- there is no broader fe row that matches /bff/superadmin/… (the fe gateway has
  -- no '/bff/**' and no '/**' row), and any LONGER fe row added later
  -- automatically wins over it. Placement here is for a reader's benefit only:
  -- the superadmin floor sits directly above the admin floor it out-ranks.
  --
  -- ⚠ WHAT THIS DELIBERATELY WIDENS, stated rather than buried. The workload
  -- console's dangerous tier (/bff/superadmin/workloads/{logs-stream,exec,
  -- exec-tty,port-forward,lifecycle}) is described further down this file as
  -- "reachable ONLY over the TAILNET". In practice that property was being held
  -- up by nothing but this bug: optional-services.yaml mounts the console UI at
  -- `/admin/workloads` — i.e. inside the PUBLIC fe admin shell — and the shipped
  -- admin-ui bundle calls /bff/superadmin/workloads/** from there. So the tailnet
  -- claim was already contradicted by the UI mount; only the missing row made it
  -- true. This row makes the two agree in the other direction: the tier is now
  -- reachable at the front door BY ROLE_SUPERADMIN ONLY. The remaining walls are
  -- the ones that were always the real ones — the admin-bff's central WebFilter
  -- (dangerous-tier kill switch + namespace allowlist + TTL'd grant + step-up +
  -- Lease + device/SSH licence) and the fact that the whole slug SHIPS DARK and
  -- DEFAULT-DESELECTED. An operator who wants the old posture back adds a DENY
  -- row at the LONGER pattern, which wins on length:
  --     ('hugmesh-fe-gateway','/bff/superadmin/workloads/**','ROLE_SUPERADMIN',false)
  -- (same idiom as the SERVICE-ONLY INTERNAL INGEST deny rows below).
  --
  -- ⚠ NOT pruned by gate_optional_services — and what that costs, per slug.
  -- This row is deliberately absent from every *.routeAccessRows list in
  -- optional-services.yaml, because it also carries backing-services /
  -- fleet-entitlements / phone-devices / desktop-dials / cloud-backups, none of
  -- which are optional-gated: pruning it with any one slug would re-break five
  -- unrelated pages. The consequence is that a superadmin-prefixed surface owned
  -- by an OPTIONAL slug stays matched at the fe door after that slug is
  -- deselected. That is TWO surfaces today, and each is stated here with the wall
  -- that is actually left. (tests/scripts/test-superadmin-bff-reachability.sh §13
  -- EXECUTES both real builders' gate for every slug and fails on a THIRD.)
  --
  --   * workloadConsole -> /bff/superadmin/workloads/**  — ALLOW survives, via
  --     this floor. CORRECTION, because the earlier wording here was wrong and
  --     the repo contradicted it in two places: it is NOT true that "the admin-bff
  --     has no workloads controller to reach". The controller SHIPS in the
  --     always-present admin-bff and is dark at RUNTIME, exactly as
  --     build-{rpi5,x86-host}-stage4.sh's own workloadConsole comment says ("the
  --     BFF endpoints live in the always-present admin-bff"). The walls left are:
  --     (1) the BFF's WorkloadAuthorizationFilter denies a DISABLED prefix
  --     (app.workload-console.enabled=false when the overlay is pruned), so a
  --     direct in-cluster call 404s too; (2) the fail-closed NoopWorkloadClient
  --     503s every k8s call; (3) the DB master flag workload_console_config
  --     .{admin_enabled,dangerous_tier_enabled} defaults false plus TTL'd grants;
  --     (4) ROLE_SUPERADMIN + the mfa_required flip below. Defence-in-depth at
  --     deselect therefore drops from "gateway wall + BFF wall" to "BFF wall" for
  --     the superadmin half — a REAL reduction, not a null one.
  --   * games (app-store control plane) -> /bff/superadmin/games-services/**  —
  --     CLOSED, see the explicit DENY row immediately below this one. Unlike the
  --     workload console, NO shipped admin-ui bundle path calls
  --     /bff/superadmin/games-services/* (verified against
  --     tests/stack/.uidist/_remotes/admin, which names workloads but never
  --     games-services), so denying it at the fe door costs nothing and restores
  --     the exact status quo ante: before this floor existed there was no fe row
  --     for that family at all, and the app-store control plane was reachable only
  --     over the tailnet. It is denied UNCONDITIONALLY — selected or not — because
  --     a row that only appears on deselect is not expressible: _opt_drop_rows can
  --     REMOVE a row, never ADD one.
  --
  -- ⚠ ALSO PRE-EXISTING, and not caused by this row: the fe '/bff/admin/**'
  -- floor further below already matched /bff/admin/workloads/** long before
  -- 2026-08-26, so the ADMIN (read-only) half of the workload console has always
  -- survived deselection at the front door. docs/OPTIONAL-SERVICES.md §7.2's OFF
  -- #1 cell used to claim "the gateway 404s the whole prefix"; that was already
  -- false for the admin half and is now false for the superadmin half too. The
  -- doc is corrected in the same commit.
  --
  -- An operator who wants the workload console's tailnet-only posture back adds
  -- the same shape of DENY row, which wins on length:
  --     ('hugmesh-fe-gateway','/bff/superadmin/workloads/**','ROLE_SUPERADMIN',false)
  -- It is NOT added here because the shipped admin-ui DOES call those six paths
  -- from the public /admin/workloads mount; adding it darks a shipped page. That
  -- is an operator posture decision, not a defect — and the suite's
  -- longest-pattern control proves the row would take effect.
  --
  -- ⚠ MFA: this row is under the '/bff/superadmin/%' prefix of the mfa_required
  -- flip UPDATE at the end of this file, so it is flipped to mfa_required=true
  -- automatically — no companion edit, and test-mfa-required-rules.sh check (b)
  -- would go red if it were not.
  --
  -- ⚠ DUAL-WRITE PARTNER in OTHER repo: the hugmesh-gateway CanonicalSeed.fe()
  -- baked fallback floor must gain this same row, or a dual-DB outage drops the
  -- superadmin console back to a dead end (the same shape as the phone-fleet
  -- lockstep note in the block below).
  -- (the floor row itself is in the #244 ACCEPT block further down — see the
  --  merge note at the head of this block)
  -- Explicit DENY, MORE SPECIFIC than the fe /bff/superadmin/** floor (which,
  -- since the 2026-09-16 merge, is in the #244 ACCEPT block further DOWN this file) (longest matching
  -- url_pattern wins, and deny-wins at that length — same idiom as the
  -- attestation-server /attest/api/create-account row further down). The games
  -- app-store control plane is an add-on of the OPTIONAL `games` slug
  -- (docs/GAMES-APPSTORE.md), its endpoints live in the ALWAYS-PRESENT
  -- admin-bff, and gate_optional_services can only remove rows — so without this
  -- row the floor above would keep the app-store curation surface matched at the
  -- PUBLIC front door on a games-DESELECTED build, which is strictly wider than
  -- the posture that existed before the floor was added. No shipped admin-ui
  -- path calls it (the operator UI at /admin/games-services rides the
  -- '/admin/games-services/**' + '/bff/games-services/**' families instead), so
  -- this costs nothing and keeps the control plane tailnet-only via
  -- hugmesh-be-gateway / hugmesh-superadmin-gateway.
  --
  -- ⚠ SEEDED, AND SEEDED WITH mfa_required = true — OPERATOR DECISION 28 = D,
  -- answered 2026-09-17 on hugmesh-generator#347 (comment 5722264043) and tracked
  -- on #351. This row is the one thing `integrate/superadmin` carried that the
  -- 2026-09-16 land pass left out, on a merge-time reading that decision 8 (#244
  -- ACCEPT, framed "without the games-services deny row") was the SPECIFIC answer
  -- and decision 20 ("land the whole branch") merely the later GENERAL one. That
  -- reading was parked for the operator rather than taken, and the operator did
  -- NOT pick a side: D closes the trade-off instead. The row goes back (decision
  -- 20 lands literally) AND the step-up floor survives (decision 8's one real
  -- gain), because the row itself carries mfa_required = true.
  --
  -- WHY A true ON A DENY ROW IS NOT NOISE — TWO DIFFERENT GATEWAY FUNCTIONS.
  -- Read out of hugmesh-gateway on 2026-09-17, not inferred:
  --   * GatewayRouteAccessService.decide() raises its D8 floor
  --     (`mfaRequiredOnGrant`) ONLY from rows that GRANT the principal — the
  --     `if (r.allow())` arm and the isPublic() arm, nowhere else. A deny row can
  --     never raise it. On the ALLOW path the true below is therefore genuinely
  --     inert, which is exactly what "marking a deny row would be noise" meant,
  --     and that sentence is still correct — for THAT function.
  --   * GatewayRouteAccessFilter's D8 PRIVILEGED floor does not call decide() at
  --     all. It calls GatewayRouteAccessService.isMfaRequiredSurface() (the JWT
  --     branch and the opaque-`bff_`-session branch each call it once), and that
  --     function is allow-BLIND and role-BLIND: it takes the LONGEST matching
  --     url_pattern and returns true if ANY rule at that length carries
  --     mfaRequired — `if (r.mfaRequired()) return true;`, with no allow test and
  --     no authority test anywhere in its body.
  -- That asymmetry is the whole of decision D. The deny row wins the longest
  -- match for this subtree, so WITHOUT a true on it isMfaRequiredSurface() would
  -- answer false for /bff/superadmin/games-services/** and the privileged step-up
  -- floor would stop applying there — the cost the 2026-09-16 note measured, and
  -- the reason option A (leave the row out) was recommended. WITH the true, the
  -- floor is carried by the deny row itself and the subtree keeps it.
  --
  -- HOW THE true GETS ONTO THE ROW — not as a 5th value in the tuple.
  -- Three independent reasons, the first two of which are this file's own
  -- argument at the flip UPDATE (reasons 1-3 there) applied to one row:
  --   1. mfa_required is NOT in uq_route_access_row, so a parallel 5-value row
  --      collides on the 5-tuple and ON CONFLICT DO NOTHING silently drops it.
  --   2. On an IN-PLACE re-apply the row already exists, ON CONFLICT DO NOTHING
  --      skips it, and a 5-value INSERT leaves mfa_required false forever. Only a
  --      write that CHANGES the existing row converges on both paths.
  --   3. A 5-value tuple is invisible to every row parser in the repo: the
  --      4-field ROW_FULL_RE in tests/scripts/cluster_manifest_integrity.py, and
  --      the ROW_RE in tests/scripts/test-mfa-required-rules.sh,
  --      tests/scripts/test-superadmin-bff-reachability.sh and
  --      tests/e2e/specs/rbac-route-access.ts all stop at `,true|false)`. The row
  --      would exist in Postgres and be absent from every static model of it.
  -- So the row is seeded 4-value like every other row, and a ROW-SCOPED UPDATE
  -- placed immediately BEFORE the blanket flip at the foot of this file pins its
  -- mfa_required. That statement names this one
  -- (gateway, url_pattern, role, allow=false) tuple and nothing else;
  -- tests/scripts/test-mfa-required-rules.sh asserts its shape, that it changes
  -- exactly one row on the first apply and zero on the second, that the BLANKET
  -- flip still touches allow=true rows only, and that no OTHER deny row anywhere
  -- in the file ends up mfa_required=true.
  --
  -- WHAT THE ROW COSTS, stated so the next reader does not re-litigate it: it
  -- denies NOBODY who is not already denied. A privileged principal
  -- short-circuits in GatewayRouteAccessFilter before decide() runs; a
  -- non-privileged one is already governed-but-ungranted DENY under the
  -- /bff/superadmin/** floor. Its value is posture, not enforcement — it states
  -- that an OPTIONAL slug's control plane is not offered at the public browser
  -- door, and it restores the exact status quo ante for a games-DESELECTED build
  -- (which gate_optional_services cannot do on its own: _opt_drop_rows can only
  -- REMOVE a row, never ADD one, so the deny must be unconditional).
  ('hugmesh-fe-gateway',  '/bff/superadmin/games-services/**', 'ROLE_SUPERADMIN', false),  -- games app-store control plane: DENY at the PUBLIC browser door (tailnet-only posture); mfa_required pinned true by the row-scoped UPDATE below (#347 decision 28 = D)
  -- ── FLEET-OWNER phone console (fleet-admin entitlement tier) ────────────────
  -- The admin-bff /bff/admin/phone-fleet/** surface lets a NON-superadmin fleet
  -- owner manage ONLY their own phones on the PUBLIC fe-gateway. It rides the
  -- /bff/** catch-all route to admin-bff (20-gateway-fe.yaml) but needs its OWN
  -- route-access rows: the generic /bff/admin/** row below is ROLE_ADMIN-ONLY, so
  -- a pure ROLE_FLEET_ADMIN would be DEFAULT-DENIED at the gateway on the
  -- most-specific match unless a ROLE_FLEET_ADMIN allow row exists on the LONGER
  -- /bff/admin/phone-fleet/** pattern (longest-pattern-wins, like
  -- /bff/forum/admin/** over /bff/forum/**). Because the longer pattern WINS, the
  -- /bff/admin/** ROLE_ADMIN row no longer covers this subpath, so ROLE_ADMIN and
  -- ROLE_SUPERADMIN are PAIRED here explicitly (the converter does not auto-grant
  -- the narrower fleet role to them). The owner+domain tenancy wall + the
  -- fleet_entitlement gate are enforced INSIDE admin-bff (@PreAuthorize + the
  -- physical_owner/owner_domain scope predicate) — these gateway rows are the
  -- coarse defence-in-depth. The SUPERADMIN owner-assignment + entitlement-admin
  -- endpoints (/bff/superadmin/phone-devices/<id>/owner,
  -- /bff/superadmin/fleet-entitlements/**) were described here as needing "NO new
  -- row — they fall under the existing be-gateway + superadmin-gateway
  -- '/bff/superadmin/** -> ROLE_SUPERADMIN' floors (tailnet-only)".
  -- ⚠ THAT SENTENCE WAS FALSE, and it is corrected by the fe-gateway
  -- '/bff/superadmin/**' row added in the block ABOVE: gateway_route_access is
  -- keyed on the gateway NAME, so a be-gateway or superadmin-gateway floor
  -- governs nothing that arrives at the fe-gateway — and BOTH of those endpoints
  -- are called by admin-ui pages served from the fe front door. See the
  -- "SUPERADMIN CONSOLE AT THE FRONT DOOR" block above for the full incident.
  -- ⚠ DUAL-WRITE PARTNER in OTHER repo: the gateway
  -- CanonicalSeed.fe() baked floor must gain the SAME three rows in lockstep (done).
  -- (admin-bff's 001-gateway-route-access changelog is table DDL only — it seeds NO
  -- route-access ROWS, so it is NOT a row-seed partner despite the mfa_required
  -- SCHEMA note above.)
  ('hugmesh-fe-gateway',  '/bff/admin/phone-fleet/**', 'ROLE_FLEET_ADMIN', true),  -- fleet-owner phone console (non-superadmin; owner+domain wall + entitlement in admin-bff)
  ('hugmesh-fe-gateway',  '/bff/admin/phone-fleet/**', 'ROLE_ADMIN',       true),  -- (admins superset — longer pattern wins, so pair explicitly)
  ('hugmesh-fe-gateway',  '/bff/admin/phone-fleet/**', 'ROLE_SUPERADMIN',  true),  -- (superadmins superset — longer pattern wins, so pair explicitly)
  ('hugmesh-fe-gateway',  '/bff/admin/**',         'ROLE_ADMIN',     true),
  -- ── SUPERADMIN PLATFORM CONSOLE at the PUBLIC BROWSER DOOR (#244, ACCEPT) ──
  -- ⚠ #244 PREMISE CORRECTED — and unlike #329's, this correction HOLDS, which is
  -- why the two rows read so differently. The issue BODY says the shipped
  -- admin-ui superadmin pages "ride the public fe /bff/** catch-all and are
  -- DEFAULT-DENIED at the browser door today". They were not. Measured on this
  -- tree immediately before the row below: the fe gateway carried 80 rows and
  -- NONE of their patterns matched /bff/superadmin/… — there is no /bff/** row
  -- and no /** row on this gateway (that is exactly what /bff/wiki/** DID have,
  -- and why #329 was the opposite shape). With no matching pattern
  -- GatewayRouteAccessService.decide() returns NO_RULE (:185 `if (bestLen < 0)
  -- return Decision.NO_RULE;   // ungoverned path`), GatewayRouteAccessFilter
  -- rejects ONLY on Decision.DENY (:445), and the request was FORWARDED down the
  -- Path=/bff/** route to admin-bff. What refused it was admin-bff itself,
  -- app-side: SecurityConfig.java:293
  --     ex.pathMatchers("/bff/superadmin/**").hasRole("SUPERADMIN");
  -- Measured at the compose front door as a plain member, BEFORE this row:
  --     /bff/superadmin/workloads/             -> 403, and NO X-Route-Denied
  --     /bff/superadmin/games-services/catalog -> 403, and NO X-Route-Denied
  -- The ABSENT header is the whole tell. A gateway denial always carries it
  -- (GatewayRouteAccessFilter javadoc :64, emitted at :589), so a BARE 403 is the
  -- documented signature of an app-side refusal one layer further in.
  -- LINE NUMBERS in this block are hugmesh-gateway main @ debcebc8 (merged
  -- 2026-09-09, re-read 2026-09-16); the service refs (:185/:219/:380) are
  -- unchanged since 2026-09-04, the filter refs moved when the D8 privileged MFA
  -- floor was placed BEFORE the bypasses (:278-284 JWT, :349-355 non-JWT) —
  -- which is exactly what lets this row bind a superadmin once the flag flips.
  --
  -- WHAT THIS ROW CHANGES, as before/after for ONE request. A ROLE_USER — or any
  -- authenticated principal that is not admin/superadmin — at /bff/superadmin/…:
  --   BEFORE  gateway NO_RULE -> FORWARD -> admin-bff answers 403. No
  --           X-Route-Denied, nothing in the gateway's denial log, and the
  --           request crossed the namespace boundary to reach the BFF at all.
  --   AFTER   this row is the longest matching pattern, the caller holds no
  --           granting row at that length => governed-but-ungranted => DENY at
  --           the door (:219). 403 WITH `X-Route-Denied: hugmesh-fe-gateway:<path>`,
  --           logged by the gateway, and admin-bff never sees the request.
  -- The STATUS CODE does not move. The layer, the header and the log do — which
  -- is why every member test plan had to carve this surface out by hand as a
  -- named exception so a tester would not misfile a bare 403 (#299 N6).
  --
  -- ⚠ WHAT IT DOES *NOT* CHANGE. ROLE_ADMIN (own-domain) and ROLE_SUPERADMIN
  -- (cross-domain) SHORT-CIRCUIT in GatewayRouteAccessFilter BEFORE decide() is
  -- consulted — :291 and :323 on the JWT branch, mirrored at :361 and
  -- :385 on the non-JWT branch, which is the opaque `bff_` session an actual
  -- browser presents. So NO row on this gateway alters what a privileged
  -- principal reaches: a plain ROLE_ADMIN still arrives at admin-bff and is still
  -- refused there by hasRole("SUPERADMIN"). ACCEPT is defence-in-depth and a
  -- clearer failure mode, NOT the closing of an open door. Identical residual to
  -- the /bff/wiki/superadmin/** row below.
  --
  -- THE REAL GAIN IS THE MFA FLOOR, and it is prospective rather than immediate.
  -- isMfaRequiredSurface() returns false for an UNGOVERNED path (:380 `if
  -- (bestLen < 0) return false;             // ungoverned path — no floor`), so
  -- before this row the D6/D8 privileged step-up floor COULD NOT fire on the
  -- superadmin surface at the public door no matter what
  -- APP_MFA_ENFORCE_PRIVILEGED_FLOOR was set to — there was nothing for it to
  -- hang on. This row sits under /bff/superadmin/, so the flip UPDATE at the foot
  -- of this file picks it up and the gate finally has a surface. That is the
  -- argument the operator accepted; the flag itself is NOT flipped here.
  --
  -- THE games-services DENY REFINEMENT IS NOW SEEDED — OPERATOR DECISION 28 = D
  -- (#347, answered 2026-09-17), which SUPERSEDES the "without the games-services
  -- deny row" clause this block used to carry. #244's question was framed that
  -- way because the carrier commit 63c8952f paired its allow row with a DENY row
  -- at /bff/superadmin/games-services/** whose mfa_required was left false: as
  -- the LONGEST matching pattern it would then have taken the subtree out of the
  -- step-up floor, which is the one thing #244's ACCEPT buys. That objection was
  -- to the row AS 63c8952f WROTE IT, not to the row. The operator's answer seeds
  -- it with mfa_required = true instead, so the subtree keeps the floor — see the
  -- block above the row itself for the measurement (isMfaRequiredSurface() is
  -- allow-blind and role-blind, decide()'s grant-scoped floor is not).
  -- Unchanged: the row still denies NOBODY the floor below does not already deny
  -- (a privileged principal bypasses decide() before it runs; a non-privileged
  -- one is governed-but-ungranted either way). Its value is the posture — an
  -- OPTIONAL slug's control plane is not offered at the public browser door.
  --
  -- ✅ DUAL-WRITE PARTNER in the OTHER repo — LANDS WITH decision 41 (#33) and
  -- decision 56 (#347, 2026-09-18) TOGETHER, not separately. hugmesh-gateway's
  -- CanonicalSeed.fe() baked floor gains r(FE, "/bff/superadmin/**",
  -- "ROLE_SUPERADMIN") (decision 41), and decision 56 puts that SAME row in
  -- MFA_REQUIRED_FALLBACK_ROWS — so on the datastore-unreachable fallback the
  -- fe floor now agrees with this file on BOTH the DENY/header AND the MFA
  -- floor, not the DENY/header alone. Parity is ASSERTED, not merely noted, in
  -- tests/e2e/features/mined-governance/fallback-floor-parity.feature (both the
  -- pre-existing ALLOW/DENY parity scenario and the new MFA-parity one).
  --
  -- ⚠ REACHING A DATABASE THAT ALREADY EXISTS. This file is initdb-only on BOTH
  -- lanes: the cluster mounts it into /docker-entrypoint-initdb.d over a PVC
  -- (route-access/deployment.yaml, pvc.yaml; apps/06-route-access-db.yaml
  -- self-heals the ConfigMap in place and restarts nothing) and compose mounts
  -- the same file the same way over the route-access-pg named volume
  -- (tests/stack/compose.local.yaml). Postgres runs initdb ONCE, on an empty
  -- volume, so on a lane that existed before this row landed a re-probe of
  -- /bff/superadmin/… returns the BEFORE state above and looks like the row did
  -- nothing. Converge FIRST: re-apply this file against route-access-db
  -- (docs/MFA-ROLLOUT.md, "Seed the rules" — safe to re-run, the INSERT is ON
  -- CONFLICT DO NOTHING and the flip UPDATE is IS DISTINCT FROM true) or
  -- recreate the volume, and record which. A pre-existing property of every
  -- seed edit, stated here because the AFTER table above reads as immediate.
  ('hugmesh-fe-gateway',  '/bff/superadmin/**',    'ROLE_SUPERADMIN', true),  -- superadmin platform console, PUBLIC browser door (#244 ACCEPT; admin/superadmin still bypass decide())
  -- Same-origin role BFFs (fe-gateway proxies /bff/** subpaths to the dedicated
  -- BFFs in the backend ns). The /bff/mod/** + /bff/user/** prefixes are SIBLINGS
  -- of /bff/admin/** above (non-overlapping prefixes), each gated to its own role
  -- floor. /bff/mod/** pairs ROLE_ADMIN so admins (a superset the converter does
  -- NOT auto-grant ROLE_MOD/USER to) keep reaching the moderation BFF.
  ('hugmesh-fe-gateway',  '/bff/mod/**',           'ROLE_MOD',       true),  -- moderation BFF (mod floor)
  ('hugmesh-fe-gateway',  '/bff/mod/**',           'ROLE_ADMIN',     true),  -- (admins superset)
  ('hugmesh-fe-gateway',  '/bff/user/**',          'ROLE_USER',      true),  -- user self-service BFF
  -- ── SERVICE-ONLY INTERNAL INGEST SURFACES: explicit DENY ───────────────────
  -- `/bff/**` is Ant-matched, so a `**` floor row SUBSUMES every deeper path
  -- under it — including the service-to-service `/…/internal/**` receivers that
  -- three comments in this tree describe as "not gateway-routed". They ARE
  -- routed: apps/20-gateway-fe.yaml carries `/bff/user/**` -> user-bff,
  -- `/bff/mesh/**` -> mesh-bff and the `/bff/**` -> admin-bff catch-all, and
  -- Spring's AntPathMatcher happily matches /bff/user/internal/mesh-devices
  -- against /bff/user/**. Without these rows the DECIDING (longest-matching)
  -- rule for an internal path is the tier floor above, so:
  --   * any ROLE_USER  reaches user-bff's  /bff/user/internal/**  (mesh-device
  --     registry + the PENDING->ACTIVE character-moderation flip),
  --   * any ROLE_MESH  reaches mesh-bff's  /bff/mesh/internal/bridge-sync (the
  --     meshbridge node-directory / mesh-room ingest),
  --   * any AUTHENTICATED principal reaches admin-bff's /bff/internal/** — which
  --     has NO governing row at all today, so the gateway returns NO_RULE and
  --     FORWARDS on the coarse authenticated() floor, and admin-bff's own
  --     SecurityConfig permitAll()s that prefix (its InternalTokenWebFilter is the
  --     only wall, and it is inert when app.internal.token is unset).
  -- Each receiver is meant to be reached ONLY in-cluster (ROLE_SERVICE client-
  -- credentials JWT + cluster-CA mTLS + X-Internal-Token), never through a
  -- gateway. Deny-wins at the longest match, and `gateway_route_access` governs
  -- EXTERNAL traffic only, so these rows cannot touch the in-cluster legs
  -- (meshbridge -> user-bff/mesh-bff, gateway -> admin-bff session exchange).
  -- Same shape as the /attest/api/create-account DENY further down.
  ('hugmesh-fe-gateway',  '/bff/user/internal/**', 'ROLE_USER',      false), -- explicit DENY: SERVICE-only ingest (meshbridge/moderation)
  ('hugmesh-fe-gateway',  '/bff/mesh/internal/**', 'ROLE_USER',      false), -- explicit DENY: SERVICE-only bridge-sync ingest
  ('hugmesh-fe-gateway',  '/bff/internal/**',      'ROLE_USER',      false), -- explicit DENY: admin-bff internal API (permitAll app-side)
  -- Forum BFF (/bff/forum/** -> hugmesh-forum-bff-api), the SINGLE
  -- browser->phpBB path. SIBLING of /bff/mod/** + /bff/user/** above. Most-specific
  -- match wins, so the subpaths are gated tighter than the floor:
  --   /bff/forum/admin/**      = ROLE_ADMIN      (the admin-console seam admin-bff
  --                              calls; admins reach it via the bypass WITHOUT
  --                              ROLE_FORUM, so it is gated ROLE_ADMIN end-to-end)
  --   /bff/forum/moderation/** = ROLE_FORUM_MOD  (the DERIVED composite role =
  --                              ROLE_MOD intersect ROLE_FORUM, materialized in
  --                              Casdoor by the forum reconcile Job — the gateway's
  --                              OR-of-allow table cannot express MOD AND FORUM, so
  --                              this single derived-role row encodes the AND, like
  --                              ROLE_GAMES_ADMIN. A plain ROLE_MOD WITHOUT the
  --                              forum role is default-deny here.)
  --   /bff/forum/**            = ROLE_FORUM      (the forum-access floor)
  -- Do NOT pair ROLE_ADMIN on the ROLE_FORUM / ROLE_FORUM_MOD floor rows: the
  -- gateway admin-bypass already lets admins through, and the matrix/mastodon seed
  -- pairs only its non-admin floors (never ROLE_ADMIN). ROLE_ADMIN stays only on
  -- the genuinely admin-only /bff/forum/admin/** row.
  ('hugmesh-fe-gateway',  '/bff/forum/admin/**',       'ROLE_ADMIN',     true),  -- forum admin-console seam (admin-only, end-to-end)
  ('hugmesh-fe-gateway',  '/bff/forum/moderation/**',  'ROLE_FORUM_MOD', true),  -- forum moderation (derived MOD ∩ FORUM)
  ('hugmesh-fe-gateway',  '/bff/forum/**',             'ROLE_FORUM',     true),  -- forum BFF (forum-access floor)
  -- Wiki BFF (/bff/wiki/** -> hugmesh-wiki-bff-api), the SINGLE browser->wiki
  -- path. SIBLING of /bff/forum/** + /bff/mod/** above. Most-specific match wins:
  --   /bff/wiki/superadmin/** = ROLE_SUPERADMIN (superadmin-only seam; the wiki-bff
  --                         pins it hasRole('SUPERADMIN') in SecurityConfig.java,
  --                         declared BEFORE its admin + floor prefixes)
  --   /bff/wiki/admin/**  = ROLE_ADMIN  (admin-only seam: wiki-config, content-admin
  --                         ops; gated ROLE_ADMIN end-to-end — admins reach this
  --                         WITHOUT ROLE_WIKI, so DO NOT pair ROLE_WIKI here)
  --   /bff/wiki/**        = ROLE_WIKI   (wiki-access floor; granted by admin)
  -- Do NOT pair ROLE_ADMIN on the ROLE_WIKI floor row: the gateway admin-bypass
  -- already passes admins through; pairing ROLE_ADMIN would incorrectly expose
  -- every wiki-floor endpoint to admins who have not been granted wiki access.
  -- ⚠ #329 PREMISE CORRECTED (measured 2026-09-09, this tree). The issue reports
  -- the missing superadmin row as leaving /bff/wiki/superadmin/** on NO_RULE --
  -- "ungoverned and forwarded", the #244 shape. It did NOT. Spring's AntPathMatcher
  -- '**' crosses '/', so the /bff/wiki/** row below ALREADY matched
  -- /bff/wiki/superadmin/... and GatewayRouteAccessService.decide() governed the
  -- path at the ROLE_WIKI floor -- the same mechanic the SERVICE-ONLY INTERNAL
  -- INGEST block relies on when it says /bff/mesh/** matches /bff/mesh/internal/**.
  -- The real defect was a floor set too LOW: ANY ROLE_WIKI holder passed the front
  -- door onto the superadmin surface and the only refusal was app-side, so the 403
  -- carried no X-Route-Denied header and the door logged nothing.
  -- The row below raises the DECIDING pattern (longer => wins the longest-match) to
  -- ROLE_SUPERADMIN: a ROLE_WIKI-only principal now finds no granting row at that
  -- length => governed-but-ungranted => DENY at the door.
  -- RESIDUAL, unchanged and NOT closable by any row here: ROLE_ADMIN (own-domain)
  -- and ROLE_SUPERADMIN (cross-domain) short-circuit in GatewayRouteAccessFilter
  -- BEFORE decide() is consulted, so a plain ROLE_ADMIN still reaches wiki-bff and
  -- is refused there by hasRole('SUPERADMIN'). That is the #244 finding verbatim.
  ('hugmesh-fe-gateway',  '/bff/wiki/superadmin/**', 'ROLE_SUPERADMIN', true),  -- wiki superadmin seam (superadmin-only, end-to-end)
  ('hugmesh-fe-gateway',  '/bff/wiki/admin/**',  'ROLE_ADMIN', true),  -- wiki admin-console seam (admin-only, end-to-end)
  ('hugmesh-fe-gateway',  '/bff/wiki/**',        'ROLE_WIKI',  true),  -- wiki BFF (wiki-access floor)
  -- Mesh BFF (/bff/mesh/** -> hugmesh-mesh-bff-api): LoRa mesh node
  -- directory / rooms / my-devices. ROLE_MESH = "may use the mesh surfaces"
  -- (granted by admin, same grant model as ROLE_WIKI). Do NOT pair ROLE_ADMIN
  -- here: the gateway admin-bypass already passes admins through (the wiki-row
  -- rationale above applies verbatim). The internal bridge-sync surface
  -- (/bff/mesh/internal/**) IS matched by this `**` row, so it carries its own
  -- explicit DENY row above — see the "SERVICE-ONLY INTERNAL INGEST" block.
  ('hugmesh-fe-gateway',  '/bff/mesh/**',        'ROLE_MESH',  true),  -- mesh BFF (mesh-access floor)
  -- Character Forge BFF (/bff/character-forge/** -> hugmesh-character-forge-bff-
  -- api): saved 3D character configs + the VN→3D /map endpoint. Authenticated floor
  -- (ROLE_USER, matching the /character-forge/** UI-mount row above) — ownership is
  -- enforced in the BFF (owner = jwt subject; foreign id => 404), so no dedicated
  -- role is minted (character-studio precedent, not the granted-role tube/wiki
  -- shape). ⚠ gate_optional_services REMOVES this row when the character-forge slug
  -- is deselected (so a matched route to a pruned upstream cannot stale-grant / 502).
  ('hugmesh-fe-gateway',  '/bff/character-forge/**',  'ROLE_USER',  true),  -- character-forge BFF (authenticated floor)
  -- Owncast BFF (/bff/owncast/** -> hugmesh-owncast-bff-api). Admins reach
  -- /bff/owncast/admin/** for per-user broadcast grants; ROLE_OWNCAST holders
  -- (granted by admin) reach the user-facing console.
  ('hugmesh-fe-gateway',  '/bff/owncast/admin/**',  'ROLE_ADMIN',   true),  -- owncast admin grant surface
  ('hugmesh-fe-gateway',  '/bff/owncast/**',        'ROLE_OWNCAST', true),  -- owncast user console
  -- Tube BFF (/bff/tube/** -> hugmesh-tube-bff-api) + media serving
  -- (/tube/content/** -> tube-media Nginx, signed-URL-gated).
  -- ROLE_TUBE = "may use LocalTube" (granted by admin). The media row sits on
  -- be-gateway (same role) so the HMAC-signed URL check + owner two-wall in
  -- tube-bff are the domain enforcement; the gateway only checks role.
  ('hugmesh-fe-gateway',  '/bff/tube/**',          'ROLE_TUBE',    true),  -- tube BFF (tube-access floor)
  ('hugmesh-be-gateway',  '/tube/content/**',       'ROLE_TUBE',    true),  -- tube media serving (signed URL)
  -- Tube ADMIN write surfaces (tube-bff TubeAccessController + TubeStorageBudgetController,
  -- both under /bff/tube/admin/**, hasAnyRole('ADMIN','SUPERADMIN') in tube-bff's own
  -- SecurityConfig). Governed here at ROLE_ADMIN so a plain ROLE_TUBE holder -- who passes
  -- the /bff/tube/** floor above -- is refused AT THE DOOR (403 + X-Route-Denied) instead of
  -- one layer down in tube-bff. Both carry mfa_required=true via the blanket flip at the
  -- end of this file: its per-service console arm `LIKE '/bff/%/admin/%'` (operator
  -- decision 80b, hugmesh-generator#329) matches both patterns, so they need no
  -- row-scoped UPDATE of their own (operator decision 2026-10-15, hugmesh-tube-ui#19 /
  -- hugmesh-wiki-ui#25: the GATEWAY sends X-Step-Up-Required on the mfa_required deny).
  -- ⚠ HONEST SCOPE. ROLE_ADMIN and ROLE_SUPERADMIN return from GatewayRouteAccessFilter
  -- BEFORE decide() is consulted, so for the callers tube-bff actually admits these rows
  -- bite ONLY through the PRIVILEGED floor (app.mfa.enforce-privileged-floor), which reads
  -- isMfaRequiredSurface(). app.mfa.enabled alone gates nothing for an admin here. Both
  -- flags stay OFF on every cluster (docs/MFA-ROLLOUT.md); on a mesh with the floor ON, an
  -- admin without a fresh second factor gets 403 + X-Step-Up-Required (hugmesh-gateway),
  -- which hugmesh-tube-ui turns into the inline MFA challenge.
  -- `/**` (not `/*`) on purpose: AntPathMatcher's `*` is ONE segment, so `/access/*` would
  -- miss the DELETE revoke at /access/{type}/{user} and let it fall back to the ungated
  -- /bff/tube/** floor. `/storage-budget/**` also matches the bare path and fails closed on
  -- any sub-path or trailing-slash spelling.
  ('hugmesh-fe-gateway',  '/bff/tube/admin/access/**',          'ROLE_ADMIN',   true),  -- tube use-access overlay (grant/timeout/ban/revoke)
  ('hugmesh-fe-gateway',  '/bff/tube/admin/storage-budget/**',  'ROLE_ADMIN',   true),  -- tube per-user storage budget
  -- ── Wiki / Owncast / Tube UI MOUNT rows (pre-existing gap, filled here) ─────
  -- The wiki-ui/owncast-ui/tube-ui repos' own Dockerfiles document the intended
  -- gateway gate ("Serves on :8080 to MATCH the federation-api <slug> module
  -- registration... reachable only behind the gateway's /<slug>=ROLE_<SLUG>
  -- route-access gate") but no row for the UI's OWN mount path (as opposed to its
  -- BFF's /bff/<slug>/** path above) was ever added to this canonical seed — only
  -- the BFF rows existed. Congruent with the /admin/**, /mod/**, /user/**,
  -- /character-studio/** UI-mount rows above: same non-ROLE_ADMIN-paired floor
  -- convention as /social/forum/** (admins reach it via the gateway admin-bypass,
  -- so do NOT pair ROLE_ADMIN here either). Reuses the SAME roles already granted
  -- to the sibling /bff/wiki/**, /bff/owncast/**, /bff/tube/** rows above — no new
  -- role invented. Harmless additively in the cluster too: no SCG route currently
  -- points at /wiki/**, /owncast/**, /tube/** in apps/20-gateway-fe.yaml, so the
  -- row simply goes unmatched there until/unless such a route is added; it takes
  -- effect where the local compose gateway-routes/fe/application-routes.yml DOES
  -- add the matching direct-path route (mirroring the mod-ui/user-ui local
  -- convenience routes).
  ('hugmesh-fe-gateway',  '/wiki/**',              'ROLE_WIKI',    true),  -- wiki UI (wiki-access floor)
  ('hugmesh-fe-gateway',  '/owncast/**',           'ROLE_OWNCAST', true),  -- owncast UI (owncast-access floor)
  ('hugmesh-fe-gateway',  '/tube/**',              'ROLE_TUBE',    true),  -- tube UI (tube-access floor)
  -- ── SUPERADMIN APP-STORE — TAILNET-ONLY superadmin-gateway (hugmesh-superadmin-
  -- appstore design, V6) ──────────────────────────────────────────────────────────
  -- The superadmin infra control plane is served by its OWN gateway
  -- (hugmesh-superadmin-gateway, apps/22-gateway-superadmin.yaml) on the
  -- nginx-internal class on the pki node — TAILNET-ONLY, off every public-ingress
  -- gateway, with NO be-gateway forward of the superadmin host. These are the
  -- gateway-NAME-scoped ROLE_SUPERADMIN floor rows (lock #2 of the three tailnet
  -- locks: network NetworkPolicy + these rows + the Angular superadminGuard).
  --
  -- NOTE the existing be-gateway '/bff/superadmin/**' -> ROLE_SUPERADMIN row above
  -- is RETAINED (it also fronts the merged games-services superadmin surface
  -- /bff/superadmin/games-services/** and is itself ROLE_SUPERADMIN-gated); adding
  -- the superadmin-gateway is ADDITIVE — it does not remove that row. The NEW
  -- App-Store CONSOLE path is reachable ONLY via the tailnet superadmin-gateway.
  ('hugmesh-superadmin-gateway', '/bff/superadmin/**',        'ROLE_SUPERADMIN', true),  -- App-Store BFF control plane (tailnet)
  ('hugmesh-superadmin-gateway', '/superadmin/service-catalog/**', 'ROLE_SUPERADMIN', true),  -- service-catalog-ui federated remote (tailnet)
  ('hugmesh-superadmin-gateway', '/api/federation/**',        'ROLE_SUPERADMIN', true),  -- federation manifest/bundles for the superadmin shell (tailnet)
  -- ── Headwind MDM (managed phones) — DEFAULT-OFF optional-service `headwind`,
  -- rides the EXISTING tailnet superadmin-gateway (no gatewayHost of its own).
  -- Console = human JSP UI, gated ROLE_SUPERADMIN like every other row on this
  -- gateway. Check-in = device MQTT-push/REST surface: network-locked (this
  -- gateway is tailnet-only end-to-end) but role='PUBLIC' so the Casdoor JWT
  -- check is SKIPPED — Headwind's own per-device enrollment token is the real
  -- authenticator for this path.
  -- ⚠ THE ROW IS REQUIRED, BUT NOT FOR THE REASON THIS COMMENT USED TO GIVE. It
  -- said "a route with ZERO matching allow rows is default-deny". That is FALSE:
  -- GatewayRouteAccessService.decide() returns Decision.NO_RULE for an unmatched
  -- path and GatewayRouteAccessFilter rejects ONLY on Decision.DENY, so an
  -- ungoverned path is FORWARDED (see docs/ROUTE-ACCESS.md, "No matching row is
  -- NOT a denial"). Omitting the row would therefore NOT deny — it would leave the
  -- path ungoverned, which is a different and worse thing: the moment any BROADER
  -- pattern on this gateway comes to match /hmdm/**, the omitted row cannot lose
  -- to it because it does not exist, and the tier floor silently becomes the
  -- deciding rule. The explicit PUBLIC row states the intent AND holds the longest
  -- match. Keep it.
  -- ⚠ gate_optional_services REMOVES both rows when the headwind slug is
  -- deselected (see optional-services.yaml headwind.routeAccessRows).
  ('hugmesh-superadmin-gateway', '/hmdm/manage/**',           'ROLE_SUPERADMIN', true),  -- Headwind MDM human console (tailnet, JSP — no Angular guard)
  ('hugmesh-superadmin-gateway', '/hmdm/rest/**',              'PUBLIC',           true),  -- Headwind device check-in/push (network-locked; Headwind's own device token, not Casdoor)
  -- AttestationServer (GrapheneOS hardware-attestation verification) rows. All
  -- REQUIRED, for the reason corrected on the headwind rows above (NOT
  -- "default-deny" — an ungoverned path is FORWARDED; the explicit row is what
  -- holds the longest match and states the intent). /attest/api/status is device-facing despite the
  -- /api/ prefix, so it gets its own PUBLIC row; the gateway route ordering
  -- (apps/22-gateway-superadmin.yaml) must evaluate it before /attest/api/**.
  -- ⚠ gate_optional_services REMOVES all rows when the attestation-server
  -- slug is deselected (see optional-services.yaml attestation-server.routeAccessRows).
  ('hugmesh-superadmin-gateway', '/attest/auditor/**',         'PUBLIC',           true),  -- AttestationServer device/Auditor-app check-in (network-locked; no Casdoor)
  ('hugmesh-superadmin-gateway', '/attest/api/status',         'PUBLIC',           true),  -- device-facing despite /api/ prefix — must precede /attest/api/** below
  -- Explicit DENY, MORE SPECIFIC than the /attest/api/** console row below (so it
  -- wins the "most specific matching url_pattern wins" rule documented in this
  -- file's header comment). CreateAccountHandler (AttestationServer.java:1212-1239)
  -- has ZERO app-layer auth — no verifySession() call, unlike ChangePasswordHandler
  -- (line 1256) which has one. PostHandler's base checks are an Origin/Content-Type/
  -- Sec-Fetch-* CSRF-shape check, not authentication, so any ROLE_SUPERADMIN caller
  -- on the tailnet could otherwise self-mint a brand-new attestation-server account.
  -- Accounts are provisioned out-of-band by an operator via `kubectl exec` into the
  -- attestation-server pod + a loopback POST to /api/create-account (ClusterIP-only,
  -- not gateway-proxied).
  ('hugmesh-superadmin-gateway', '/attest/api/create-account', 'ROLE_SUPERADMIN', false), -- explicit DENY: no app-layer auth on this handler
  ('hugmesh-superadmin-gateway', '/attest/api/**',             'ROLE_SUPERADMIN', true)   -- AttestationServer human console (create-account explicitly excluded above)
-- Targets the uq_route_access_row expression index above (must match its
-- definition exactly — COALESCE/NULLIF/lower/trim included) so a genuine
-- repeat seed row is skipped instead of duplicated on a re-apply, while a
-- genuinely DOMAIN-SCOPED sibling row (per-domain MFA scope, §1.2a of
-- docs/MFA-ROLLOUT.md) keys differently and is accepted beside its unscoped
-- canonical twin.
ON CONFLICT (gateway, url_pattern, role, COALESCE(casdoor_user, ''), COALESCE(NULLIF(lower(trim(domain)), 'default'), '')) DO NOTHING;

-- ─────────────────────────────────────────────────────────────────────────────
-- D6/D8 MFA REQUIREMENT — the PRIVILEGED-SURFACE BLANKET.
--
-- Operator decision — the AUTHORISED SCOPE IS TWO PATH PREFIXES, blanket WITHIN
-- them: every allow row at or under `/bff/admin` and `/bff/superadmin`, on EVERY
-- gateway that governs those prefixes, requires a FRESH second factor. That is 10
-- rows today, across hugmesh-fe-gateway, hugmesh-be-gateway and
-- hugmesh-superadmin-gateway. It became 10 with #244's ACCEPT: the fe-gateway
-- `/bff/superadmin/**` browser-door row above is under the second prefix, so this
-- UPDATE picks it up — and that pickup IS the gain #244 was decided for, because
-- an UNGOVERNED path returns false from isMfaRequiredSurface() and the floor had
-- nothing at the public door to attach to before.
--
-- DECISION 80b = B (hugmesh-generator#329, answered 2026-09-23) WIDENED THAT
-- SCOPE by a second SHAPE: every allow row of the form `/bff/<service>/admin/…`
-- or `/bff/<service>/superadmin/…` — the per-service admin CONSOLE seams that live
-- behind their OWN service-BFF prefix — now carries the floor too, via
-- `LIKE '/bff/%/admin/%'` and `LIKE '/bff/%/superadmin/%'`. That is 4 more rows
-- (fe-gateway /bff/forum/admin/**, /bff/wiki/admin/**, /bff/wiki/superadmin/**,
-- /bff/owncast/admin/**), 14 in all. The operator chose this deliberately over
-- the narrower superadmin-only match, knowing it is the larger-lockout-risk
-- option: it enlarges the step-7 lockout blast radius in docs/MFA-ROLLOUT.md.
-- `%` in LIKE spans any characters, `/` included, so the shape also reaches a
-- deeper `/bff/a/b/admin/…` row added LATER — which is the intent (a future
-- per-service console row cannot silently re-open the hole), and the gate below
-- pins it. Neither new arm can match the two original prefixes (they need a
-- segment BETWEEN `/bff/` and `/admin/`), so the two shapes are disjoint.
--
-- ⚠ STILL NOT IN SCOPE — stated out loud, because "the whole admin surface" would
-- be a FALSE claim. THREE other admin-ish `/bff/` allow rows are deliberately left
-- mfa_required=false. tests/scripts/test-mfa-required-rules.sh enumerates admin-ish
-- surfaces INDEPENDENTLY of this predicate (path segment `admin`/`superadmin`, OR a
-- ROLE_SUPERADMIN/*_ADMIN role) and cross-checks them against exactly this list, so
-- a FOURTH one cannot appear unnoticed and a stale entry here fails the gate too:
--   hugmesh-fe-gateway  /bff/mod/**            ROLE_ADMIN
--       A MODERATION surface. ROLE_ADMIN is paired on it only as a superset of
--       ROLE_MOD, so gating it would gate moderation, not administration.
--   hugmesh-be-gateway  /bff/image-builds/arch/**         ROLE_SUPERADMIN
--   hugmesh-be-gateway  /bff/games-services/instances/**  ROLE_GAMES_SERVICES_ADMIN
--       Privileged by ROLE, not by path — a prefix predicate cannot express them at
--       all, and a role-based arm is likewise a NEW scope decision.
-- Widening to any of these ENLARGES the step-7 lockout blast radius in
-- docs/MFA-ROLLOUT.md, so it is the operator's call, not a drive-by edit. The
-- runbook carries the same list in §1.2a.
--
-- ⚠ WHY THIS IS AN `UPDATE` AND NOT EXTRA SEED ROWS. Three independent reasons —
-- all three must be understood before anyone "simplifies" this back into the
-- INSERT above:
--   1. `mfa_required` is NOT part of `uq_route_access_row` (gateway, url_pattern,
--      role, COALESCE(casdoor_user,''), COALESCE(NULLIF(lower(trim(domain)),
--      'default'),'')). A PARALLEL row that
--      differs ONLY in `mfa_required` collides on that 5-tuple and the INSERT's
--      `ON CONFLICT DO NOTHING` SILENTLY DROPS it — the seed would look right and
--      enforce nothing. The value has to be CHANGED on the existing row.
--   2. Even a separate 5-column `INSERT ... (…, mfa_required) VALUES (…, true)`
--      for just these rows is WRONG on an IN-PLACE upgrade (which this file's
--      header explicitly supports): the rows already exist, ON CONFLICT DO
--      NOTHING skips them, and `mfa_required` stays false forever. Only an UPDATE
--      converges for BOTH a fresh initdb and a re-apply.
--   3. The canonical INSERT is ONE statement with a shared 4-column list, and
--      tests/scripts/cluster_manifest_integrity.py's ROW_FULL_RE matches exactly
--      `('gw','pattern','role',true|false)`. Widening the column list to 5 values
--      would stop that regex matching and break the [internal-surface] check.
--
-- PREFIX-BASED, NOT a row list, and deliberately GATEWAY-BLIND:
--   * Matching is LONGEST-PATTERN-WINS. Flipping only the two `/**` floor rows
--     would leave every LONGER sub-path row (`/bff/admin/phone-fleet/**`,
--     `/bff/admin/workloads/**`, `/bff/superadmin/games-services/**`,
--     `/bff/superadmin/workloads/**`) as the DECIDING rule with mfa_required=false
--     — i.e. an MFA BYPASS on exactly the highest-value surfaces. A prefix
--     predicate covers them, and covers any sub-path row added LATER, so a future
--     row cannot silently re-open the hole.
--   * `/bff/superadmin/**` is served by BOTH hugmesh-superadmin-gateway (tailnet)
--     and hugmesh-be-gateway (retained on purpose — see the note above the
--     superadmin-gateway block). `/bff/admin/**` is served by hugmesh-fe-gateway,
--     with hugmesh-be-gateway carrying the longer /bff/admin/workloads/** row.
--     Scoping this UPDATE to one gateway name would leave the other gateway as an
--     un-MFA'd second door to the same paths, so it matches on pattern alone.
--   * `allow = true` only, AND THAT IS WHY THE ROW-SCOPED SEED ABOVE EXISTS.
--     This bullet used to end "a deny row denies at the longest match regardless
--     of MFA, so marking one would be noise", with a standing instruction to
--     re-read GatewayRouteAccessService.isMfaRequiredSurface() if a DENY row were
--     ever added under these prefixes. One now is — the fe
--     /bff/superadmin/games-services/** row (#347 decision 28 = D) — so that
--     re-read was done, and it found the sentence half wrong. decide()'s D8 floor
--     is grant-scoped, so a deny row cannot raise it and the true IS noise there.
--     isMfaRequiredSurface(), which is what the PRIVILEGED floor in
--     GatewayRouteAccessFilter actually calls, is allow-blind and role-blind: it
--     ORs mfaRequired across EVERY rule at the longest matching pattern. A deny
--     row that wins the longest match therefore DECIDES the floor for its whole
--     subtree, and leaving it false silently removes the floor there. This
--     blanket UPDATE deliberately still does not touch deny rows — widening it
--     would flip every deny row in the file, which is not what anyone asked for.
--     A deny row that must carry the floor gets a ROW-SCOPED UPDATE naming it,
--     directly above this one.
--   * `IS DISTINCT FROM true` makes a re-apply a genuine no-op instead of
--     rewriting every row.
--
-- SAFE TO SEED — these rows are INERT on a cluster today:
--   * The gateway consults `mfa_required` in GatewayRouteAccessService.decide()
--     ONLY when `app.mfa.enabled` is true (APP_MFA_ENABLED), and the hugmesh-gateway
--     IMAGE itself defaults that false (`app.mfa.enabled: ${APP_MFA_ENABLED:false}`
--     in that repo's application.yml).
--   * ⚠ AS OF THIS COMMIT nothing in THIS repo can even set it. The shared chart
--     specs/cluster/charts/hugmesh-gateway has no `mfa:` values block, no template
--     renders APP_MFA_ENABLED into a gateway pod, and tests/stack/compose.local.yaml
--     does not set it either (it carries only APP_MFA_FACTOR_KEY, for the admin-bff
--     step-up leg). That wiring is the COMPANION change on branch
--     `feat/gateway-mfa-env`. So these rows are not merely default-off — they are
--     UNREACHABLE until it lands. docs/MFA-ROLLOUT.md §0 carries the merge order.
--   * Conversely `enabled: true` ALONE is a NO-OP without these rows: nothing else
--     in the platform ever writes mfa_required=true, so the flag had nothing to
--     match on. This UPDATE is the missing data half. The two changes are two halves
--     of one feature and are only meaningful together.
--   * ⚠ `app.mfa.enforce-privileged-floor` (APP_MFA_ENFORCE_PRIVILEGED_FLOOR) is
--     NOT gated on `app.mfa.enabled` in GatewayRouteAccessFilter, and
--     isMfaRequiredSurface() has no enabled-check either. That sub-flag therefore
--     becomes live on its own once these rows exist AND something can set it — and
--     it is NOT exempt for SUPERADMIN and fails CLOSED with 503 while route-access
--     is still priming. The image defaults it OFF, nothing in this repo sets it, and
--     the companion change keeps it default-off on BOTH the cluster and the compose
--     side. It MUST stay off until operators have enrolled a second factor.
--     tests/scripts/test-mfa-required-rules.sh fails the build on any attempt to
--     turn either flag on from specs/cluster/apps/*.yaml or the chart defaults, and
--     docs/MFA-ROLLOUT.md is the runbook.
--
-- PER-DOMAIN MFA SCOPE (issue #47 × the casdoor-choice schema, PR #71). Several
-- local domains can sit behind the SAME gateways, and gateway_route_access rows
-- can carry a per-row `domain`. What that can and cannot express for MFA is
-- fixed by GatewayRouteAccessService.decide() (hugmesh-gateway) — verified, not
-- assumed: among the rows at the longest matching pattern, decide() ORs
-- mfa_required across EVERY row that grants the principal and domain-applies,
-- and an UNSCOPED row domain-applies to every domain. Three consequences,
-- mirrored in the runbook's §1.2a per-domain scope table:
--   * The blanket above is DOMAIN-BLIND exactly like it is gateway-blind: a
--     domain-scoped allow row under the blanket scope (the two prefixes or the
--     per-service shape) is flipped together with its unscoped siblings. Deliberately so, twice over. (1) A scoped
--     mfa_required=false row under the prefixes is a PHANTOM EXEMPTION — the
--     unscoped canonical row still applies to that domain and still pulls the
--     MFA floor up, so the false row exempts nothing; leaving it false would
--     only make the TABLE look exempted while the gateway enforces. Re-flipping
--     it true converges the data to the truth. (2) A scoped-ONLY allow row (a
--     per-domain admin surface with no unscoped twin) must not ship un-MFA'd
--     inside the blanket prefixes.
--   * Per-domain TIGHTENING is the direction rows CAN express: a domain-scoped
--     sibling row (same gateway/url_pattern/role, its own domain, allow=true,
--     mfa_required=true) OUTSIDE the two prefixes demands a second factor on
--     its own domain only — domainApplies() keeps it off every other domain.
--     Such rows are provisioning/CRUD data, not canonical seed rows. The
--     per-domain arm of the UPDATE below (the final OR) is their seed-side
--     CONVERGENCE list: list a url_pattern there and every DOMAIN-SCOPED row
--     carrying it is re-flipped true on each re-apply, exactly like the blanket
--     does for the prefixes, so a CRUD un-flip cannot silently survive. The
--     list is EMPTY today (the empty-string element matches no pattern) because
--     the reference mesh defines no per-domain tightening yet; widening it is a
--     one-line, reviewed edit of this predicate, and
--     tests/scripts/test-mfa-required-rules.sh cross-checks the list against
--     its own PER_DOMAIN_SCOPE set and runbook §1.2a in both directions.
--   * Per-domain EXEMPTION from the blanket is NOT expressible — not by a row
--     (see the phantom-exemption note) and not by this predicate (the blanket
--     rows are UNSCOPED, and unscoped rows apply to every domain). In
--     particular a domain that hosts its OWN Casdoor (Domain.idp=own, the
--     casdoor-choice schema) authenticates its principals against a
--     domain-local issuer: they can never carry MFA_SATISFIED, because
--     mfa_satisfied_at is a user Property in the SUPERDOMAIN's Casdoor. On a
--     shared-gateway mesh the §2.4 machine-caller caveat therefore extends to
--     that whole population — enumerate own-idp domains BEFORE flipping
--     app.mfa.enabled. docs/MFA-ROLLOUT.md §1.2a carries the full table.
--
-- OPERATOR CAVEAT: this converges the admin-managed table back to the canonical
-- posture on every re-apply, exactly like the INSERT above. A per-row exemption
-- made through the admin-bff CRUD under these prefixes — domain-scoped or not —
-- will be re-flipped to true if this file is re-applied, and so will any
-- domain-scoped row whose url_pattern is listed in the per-domain arm. Exempt a
-- surface by changing this predicate, not by hand-editing a row.
--
-- DUAL-WRITE PARTNERS (checked 2026-07-30; UPDATED 2026-09-18 for decision 56):
--   * hugmesh-gateway cache/CanonicalSeed.java — its `r()` helper used to
--     hard-code mfaRequired=false for EVERY baked row unconditionally. Decision
--     56 (hugmesh-generator#347, operator answer 2026-09-18: "a declared set of
--     privileged rows") NARROWED that: `r()` now looks each row up in the named
--     constant `MFA_REQUIRED_FALLBACK_ROWS`, which is DERIVED from the blanket
--     flip below (the intersection of "every ALLOW row this UPDATE touches" and
--     "the rows CanonicalSeed actually bakes") — see that constant's own doc
--     comment for the derivation and the full list. Every row OUTSIDE that
--     declared set still gets mfaRequired=false (D8's original reasoning still
--     applies to them: "a datastore-unreachable fallback can never accidentally
--     lock out a privileged surface nobody declared"). Consequence to know: in
--     a dual-DB outage the gateway falls back to that floor, and MFA
--     enforcement now SURVIVES for the declared rows (the fe/be
--     /bff/superadmin/** platform rows and the fe /bff/admin/** + phone-fleet
--     rows) but still DROPS for everything else under these two prefixes that
--     is NOT in the declared set — most notably the fe
--     /bff/superadmin/games-services/** DENY row below (decision 28), which
--     decision 56 was explicitly NOT authorised to mirror into the floor
--     (`deny()` still hard-codes mfaRequired=false unconditionally; the
--     declared-set mechanism only reaches rows built by `r()`).
--   * hugmesh-admin-bff-api db/changelog/001-gateway-route-access.xml — table DDL
--     ONLY (createTable + addColumn mfa_required); it contains ZERO <insert>
--     elements, so it is NOT a row-seed partner. Unaffected by decision 56.
-- ─────────────────────────────────────────────────────────────────────────────
-- ────────────────────────────────────────────────────────────────────────────
-- ROW-SCOPED mfa_required SEED — the ONE deny row that must carry the floor.
-- Operator decision 28 = D (#347, 2026-09-17). Everything about WHY is stated
-- beside the row itself, up in the INSERT; what matters here is the mechanics:
--   * It is an UPDATE, not a 5th value on the tuple, for the same three reasons
--     the blanket flip below is an UPDATE (uniqueness key, in-place re-apply,
--     and the 4-field row regexes every static model of this file uses).
--   * It runs BEFORE the blanket flip. Order is not load-bearing for the value
--     (the two statements touch disjoint rows: allow=false here, allow=true
--     there), but it IS load-bearing for the gates — docs/MFA-ROLLOUT.md's
--     `expect=identical-to-seed` block compares against the LAST
--     `SET mfa_required = true` statement in this file, which must stay the
--     blanket flip.
--   * It names the FULL row identity (gateway + url_pattern + role + allow) so
--     it can never widen into a second blanket. allow = false is part of the
--     predicate on purpose: if this row is ever changed to an ALLOW row, this
--     statement stops matching it and the blanket flip picks it up instead.
--   * `IS DISTINCT FROM true` keeps a re-apply a genuine no-op, exactly as the
--     blanket flip does.
-- tests/scripts/test-mfa-required-rules.sh classifies this statement explicitly
-- (it is neither the blanket flip nor the NULL repair, and an UNCLASSIFIED
-- mfa_required write fails that gate), asserts the tuple it names, and asserts
-- that the set of deny rows ending up mfa_required=true is EXACTLY this one.
-- ────────────────────────────────────────────────────────────────────────────
UPDATE gateway_route_access
   SET mfa_required = true
 WHERE gateway = 'hugmesh-fe-gateway'
   AND url_pattern = '/bff/superadmin/games-services/**'
   AND role = 'ROLE_SUPERADMIN'
   AND allow = false
   AND mfa_required IS DISTINCT FROM true;

UPDATE gateway_route_access
   SET mfa_required = true
 WHERE allow = true
   AND (url_pattern = '/bff/admin'
     OR url_pattern LIKE '/bff/admin/%'
     OR url_pattern LIKE '/bff/%/admin/%'
     OR url_pattern = '/bff/superadmin'
     OR url_pattern LIKE '/bff/superadmin/%'
     OR url_pattern LIKE '/bff/%/superadmin/%'
     OR (COALESCE(NULLIF(lower(trim(domain)), 'default'), '') <> ''
         AND url_pattern IN ('')))
   AND mfa_required IS DISTINCT FROM true;

-- ─────────────────────────────────────────────────────────────────────────────
-- Per-machine-user LEAST-PRIVILEGE grants. The login roles are created in
-- 10-roles.sh (which runs first in the CLUSTER initdb); the table exists now, so
-- grant exactly the privileges each consumer needs and nothing more:
--   admin-bff   = the ONLY writer (CRUD)          -> SELECT/INSERT/UPDATE/DELETE
--   *-gateway   = read-only rule loaders          -> SELECT
-- No role gets DDL/owner rights: the table is owned by the "gateway" owner role
-- (POSTGRES_USER), which the admin-bff uses for its DDL/migration path only.
--
-- GUARDED on role existence so this same file is reusable in the LOCAL DEV stack
-- (tests/stack/compose.local.yaml), which mounts ONLY this DDL and connects as the
-- owner `gateway` — the per-user roles do not exist there, so the grants are
-- simply skipped instead of erroring out initdb.
-- ─────────────────────────────────────────────────────────────────────────────
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'admin_bff') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON gateway_route_access TO admin_bff;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pki_gateway') THEN
    GRANT SELECT ON gateway_route_access TO pki_gateway;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'be_gateway') THEN
    GRANT SELECT ON gateway_route_access TO be_gateway;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'fe_gateway') THEN
    GRANT SELECT ON gateway_route_access TO fe_gateway;
  END IF;
  -- The TAILNET superadmin-gateway's own read-only rule loader.
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'superadmin_gateway') THEN
    GRANT SELECT ON gateway_route_access TO superadmin_gateway;
  END IF;
END
$$;

-- gen_random_uuid() default needs no sequence; there is no SERIAL column here, so
-- no sequence GRANTs are required. If a future migration adds a sequence, grant
-- USAGE on it to admin_bff (writer) explicitly.
