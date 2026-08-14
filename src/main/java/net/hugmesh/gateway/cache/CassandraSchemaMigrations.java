package net.hugmesh.gateway.cache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.cassandra.core.cql.ReactiveCqlOperations;
import reactor.core.publisher.Mono;

import jakarta.annotation.PostConstruct;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Versioned Cassandra schema migrations for the gateway's keyspace.
 *
 * <p>The earlier shape (RevocationListService /
 * UrlRegistryService / ResourceAuthorizationService each running
 * {@code CREATE TABLE IF NOT EXISTS} on boot) is fine for dev but
 * doesn't compose for prod:
 *
 * <ul>
 *   <li>No audit trail — there's no record of which schema version
 *       a given environment is on.</li>
 *   <li>No way to do destructive changes (add a column, rename a
 *       table) other than hand-editing each service's bootstrap.</li>
 *   <li>Multi-pod boots race the same {@code CREATE TABLE} — usually
 *       fine but a coordinated migration step removes the race
 *       entirely.</li>
 * </ul>
 *
 * <p>This class introduces a Liquibase-shaped pattern but native to
 * Cassandra: one {@code schema_migrations} table that records which
 * change-ids have applied. On boot, every change-id is replayed in
 * declaration order; ones already in {@code schema_migrations} are
 * skipped. New change-ids appended to {@link #MIGRATIONS} apply in
 * the next boot.
 *
 * <p>The cache services that previously called
 * {@code CREATE TABLE IF NOT EXISTS} in their own {@code @PostConstruct}
 * are now no-ops on that front — the schema is owned here.
 *
 * <p>Why not adopt the {@code cassandra-migration-tool} project?
 * It's a fine library but pulls in a heavier set of transitive deps
 * and we only need a handful of change-ids. Plain CQL string + a
 * 12-line registry stays portable across the platform's three
 * gateway instances without an external dependency.
 *
 * <p><strong>Registration:</strong> this is NOT a component-scanned
 * {@code @Component}. It is registered by
 * {@link net.hugmesh.autoconfigure.GatewayCassandraSchemaAutoConfiguration}
 * — a true {@code @AutoConfiguration} ordered AFTER Spring Boot's Cassandra
 * reactive auto-configuration — so the {@code @ConditionalOnBean(
 * ReactiveCassandraTemplate.class)} gate is evaluated only once the template /
 * {@link ReactiveCqlOperations} beans have (or have not) been contributed. The
 * earlier shape carried {@code @ConditionalOnBean(ReactiveCqlOperations.class)}
 * directly on a scanned {@code @Component}; component-scan registration happens
 * BEFORE auto-configuration, so that condition was deterministically FALSE and
 * this migration runner was silently absent from every real deployment —
 * migrations 006 (hs_tokens) and 007 (the multi-brand {@code domain} column)
 * never applied. A Cassandra-less deploy still boots clean: the auto-config
 * gate simply leaves this bean absent.
 */
public class CassandraSchemaMigrations {

    private static final Logger log = LoggerFactory.getLogger(CassandraSchemaMigrations.class);

    /**
     * Ordered map of {@code change_id → CQL}. New migrations APPEND
     * to this map only — never edit a previously-shipped entry or the
     * checksum in schema_migrations will mismatch.
     *
     * <p>Naming convention: {@code NNN-table-or-column} where N is a
     * zero-padded sequence number. Same shape as the hugmesh.games
     * BFF's Liquibase changelog files so readers don't have to
     * context-switch.
     */
    private static final Map<String, String> MIGRATIONS = new LinkedHashMap<>();
    static {
        MIGRATIONS.put("001-schema-migrations-table",
            "CREATE TABLE IF NOT EXISTS schema_migrations (" +
            "  change_id text PRIMARY KEY," +
            "  applied_at timestamp" +
            ")");

        // Revocation list — was bootstrapped in RevocationListService
        // pre-versioning. The CREATE IF NOT EXISTS is idempotent, so
        // adopting the table here doesn't break environments where
        // it already existed.
        MIGRATIONS.put("002-revocations-table",
            "CREATE TABLE IF NOT EXISTS revocations (" +
            "  revocation_key text PRIMARY KEY," +
            "  reason text," +
            "  revoked_at timestamp," +
            "  expires_at timestamp" +
            ") WITH default_time_to_live = 86400");

        // URL federation registry.
        MIGRATIONS.put("003-url-registry-table",
            "CREATE TABLE IF NOT EXISTS url_registry (" +
            "  path_prefix text PRIMARY KEY," +
            "  downstream_uri text," +
            "  service_name text," +
            "  registered_at timestamp," +
            "  required_role text" +
            ")");

        // Per-resource access cache (game/session/asset grants).
        MIGRATIONS.put("004-resource-access-table",
            "CREATE TABLE IF NOT EXISTS resource_access (" +
            "  grant_key text PRIMARY KEY," +
            "  resource_type text," +
            "  resource_id text," +
            "  subject_kind text," +
            "  subject_value text," +
            "  granted_by text," +
            "  granted_at timestamp" +
            ")");

        // Per-gateway external-access rules — admin-managed "which Casdoor role
        // (or pinned casdoor_user) may reach which URL pattern from outside this
        // gateway". READ-CACHE mirror of the admin-api's Postgres
        // gateway_route_access SOURCE OF TRUTH; column shape matches the
        // canonical contract (id, gateway, url_pattern, role, casdoor_user,
        // allow) so a Postgres row maps to a Cassandra row 1:1. Each gateway pod
        // loads its own gateway's rows from Postgres, write-through-mirrors them
        // here, and polls this table when Postgres is unreachable.
        // See GatewayRouteAccessService.
        MIGRATIONS.put("005-gateway-route-access-table",
            "CREATE TABLE IF NOT EXISTS gateway_route_access (" +
            "  id text PRIMARY KEY," +
            "  gateway text," +
            "  url_pattern text," +
            "  role text," +
            "  casdoor_user text," +
            "  allow boolean," +
            "  updated_at timestamp" +
            ")");

        // Homeserver-token registry (account-states PREREQ layer P0). Maps a
        // HASHED homeserver bearer (Matrix access_token / Mastodon OAuth token —
        // opaque, carrying NO localpart and NO Casdoor roles) to the identity the
        // HomeserverTokenRevocationFilter needs to evaluate the revocation list:
        //   token_hash      — sha-256(bearer), the PRIMARY KEY (we never store the
        //                      raw bearer; a leaked dump can't be replayed).
        //   localpart       — the homeserver-local username the token belongs to.
        //   platform        — 'matrix' | 'mastodon' (which homeserver minted it).
        //   kind            — 'brokered' (our-UI service mint, shared svc identity)
        //                      | 'personal' (a native client — Element/Tusky/Ivory).
        //                      The discriminator that lets external-client removal
        //                      spare the brokered our-UI token (filter checks the
        //                      external-client:* key for kind=personal only).
        //   app_or_device_id— the Matrix device_id / Mastodon app id, so a single
        //                      app/device can be revoked without the user's others.
        // The row is written at MINT time by the admin-bff (brokered) and user-bff
        // (personal) so the gateway resolves the bearer O(1) from its local cache
        // (refreshed on the RevocationListService poll) instead of round-tripping
        // the homeserver per request. TTL-bounded (mirrors revocations) so a row
        // disappears once the token's natural lifetime elapses; the mint side sets
        // a per-row TTL via `USING TTL` and this default is the backstop ceiling.
        MIGRATIONS.put("006-hs-tokens-table",
            "CREATE TABLE IF NOT EXISTS hs_tokens (" +
            "  token_hash text PRIMARY KEY," +
            "  localpart text," +
            "  platform text," +
            "  kind text," +
            "  app_or_device_id text," +
            "  minted_at timestamp" +
            ") WITH default_time_to_live = 2592000");

        // Per-row BRAND scope for the route-access read-cache (multi-brand
        // architecture tier). Mirrors the Postgres SOURCE OF TRUTH's new `domain`
        // column so the write-through INSERT (which now carries `domain`) and the
        // load SELECT round-trip 1:1. NULL/'default' = applies to any target
        // domain (back-compat; the canonical seed + single-tenant rows never set
        // it). Appended as a NEW change-id (the 005 CREATE TABLE is a shipped entry
        // and must not be edited); the schema_migrations gate makes the ALTER run
        // exactly once per environment.
        MIGRATIONS.put("007-gateway-route-access-domain-column",
            "ALTER TABLE gateway_route_access ADD domain text");

        // Per-route StripPrefix support for the DB-driven route-DEFINITION table.
        // Lets a url_registry row reproduce the static be-default route's
        // StripPrefix=1 filter (so the seeded /be/** DB route forwards
        // /be/api -> /api at the be-gateway, behaviourally IDENTICAL to the static
        // YAML route — closing the latent regression where the DB route emitted no
        // filter and, if it won Spring Cloud Gateway's route ordering over the
        // static StripPrefix=1 route, forwarded /be/api UNSTRIPPED). NULL/<=0 = no
        // strip (the back-compat default; self-registering apps and admin control
        // routes never strip). Appended as a NEW change-id (the 003 CREATE TABLE is
        // a shipped entry and must not be edited); the schema_migrations gate makes
        // the ALTER run exactly once per environment.
        MIGRATIONS.put("008-url-registry-strip-prefix-column",
            "ALTER TABLE url_registry ADD strip_prefix int");

        // Per-row OWNING BRAND scope for the revocation list (multi-brand
        // architecture tier — closes the cross-tenant revocation BFLA, CWE-639).
        // The revocations table was keyed ONLY on the free-form revocation_key, so
        // a domain ADMIN could write or lift ANY key — including one belonging to
        // another brand's subject (ban/un-ban a brand-Y user from brand-X). This
        // column records the VALIDATED-ISSUER domain of the admin who wrote the row
        // (mirrors gateway_route_access.domain, migration 007). The write surface
        // (GatewayRevocationController + RevocationListService.revoke/clear) stamps
        // it from Roles.domainOf(jwt, registry) and 403s any non-SUPERADMIN caller
        // trying to overwrite or clear a key owned by a DIFFERENT domain.
        // NULL/'default' = unscoped (single-tenant + pre-existing rows; back-compat).
        // Appended as a NEW change-id (the 002 CREATE TABLE is a shipped entry and
        // must not be edited); the schema_migrations gate makes the ALTER run
        // exactly once per environment.
        MIGRATIONS.put("009-revocations-domain-column",
            "ALTER TABLE revocations ADD domain text");

        // Per-row SECOND-FACTOR gate for the route-access read-cache (D8 gateway
        // MFA floor). Mirrors the Postgres SOURCE OF TRUTH's new `mfa_required`
        // column (gateway_route_access; the generator 20-schema.sql + admin-bff
        // 001-copy land it in lockstep) so the write-through INSERT (which now
        // carries `mfa_required`) and the load SELECT round-trip 1:1 — a column
        // missing from any of the three sites would silently never propagate via
        // swap(). When TRUE the deciding longest-pattern grant additionally
        // requires the principal's MFA_SATISFIED marker (decide() fail-closed);
        // NULL/false (the back-compat default — every pre-existing row, the
        // canonical seed, single-tenant rows) leaves behaviour byte-identical, and
        // the whole gate is inert unless app.mfa.enabled. Cassandra has no boolean
        // column default, so an un-set cell reads NULL -> Boolean.TRUE.equals(null)
        // = false (= the default-false intent). Appended as a NEW change-id (the
        // 005 CREATE TABLE is a shipped entry and must not be edited; next after
        // 009-revocations-domain-column); the schema_migrations gate makes the
        // ALTER run exactly once per environment.
        MIGRATIONS.put("010-gateway-route-access-mfa-required-column",
            "ALTER TABLE gateway_route_access ADD mfa_required boolean");
    }

    private final ReactiveCqlOperations cql;

    public CassandraSchemaMigrations(ReactiveCqlOperations cql) {
        this.cql = cql;
    }

    @PostConstruct
    void runOnce() {
        // Block on boot — migrations must finish before any service
        // tries to read or write the tables. The whole batch finishes
        // in milliseconds against a healthy cluster; a stalled
        // Cassandra fails fast here rather than letting the cache
        // services come up with a half-migrated schema.
        applyAll().block();
    }

    Mono<Void> applyAll() {
        // First migration ALWAYS runs (it creates schema_migrations
        // itself). Subsequent ones consult the table to see whether
        // they've applied. We can't use a single batch because each
        // CREATE TABLE may target a different keyspace partition and
        // the table-tracking insert must persist between steps.
        return Mono.from(cql.execute(MIGRATIONS.get("001-schema-migrations-table")))
            .then(applyRemaining())
            .doOnError(e -> log.error("[migrations] failed: {}", e.getMessage()))
            .then();
    }

    private Mono<Void> applyRemaining() {
        Mono<Void> chain = Mono.empty();
        for (Map.Entry<String, String> e : MIGRATIONS.entrySet()) {
            String id = e.getKey();
            if ("001-schema-migrations-table".equals(id)) continue;
            String cqlStmt = e.getValue();
            chain = chain.then(applyIfMissing(id, cqlStmt));
        }
        return chain;
    }

    private Mono<Void> applyIfMissing(String changeId, String cqlStmt) {
        return cql.queryForObject(
                "SELECT change_id FROM schema_migrations WHERE change_id = ?",
                String.class, changeId)
            .defaultIfEmpty("")
            .flatMap(found -> {
                if (!found.isBlank()) {
                    log.debug("[migrations] skip {} (already applied)", changeId);
                    return Mono.empty();
                }
                log.info("[migrations] applying {}", changeId);
                return Mono.from(cql.execute(cqlStmt))
                    .then(Mono.from(cql.execute(
                            "INSERT INTO schema_migrations (change_id, applied_at) VALUES (?, ?)",
                            changeId, Instant.now())))
                    .then();
            });
    }
}
