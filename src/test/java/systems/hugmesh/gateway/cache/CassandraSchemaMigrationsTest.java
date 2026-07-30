package systems.hugmesh.gateway.cache;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Sanity check on the migration registry shape. Wire-level coverage
 * (the actual CQL applies cleanly against a live Cassandra) lives in
 * an integration test that provisions a Testcontainers cluster — out
 * of scope for the unit-test gate.
 */
class CassandraSchemaMigrationsTest {

    /** Migrations must appear in stable declaration order so a peer
     *  reading the class can predict which one applies next.
     *  LinkedHashMap preserves insertion order; the test just pins
     *  that the FIRST entry is the schema_migrations table itself
     *  (otherwise we can't track which subsequent ones applied). */
    @Test
    void firstMigration_bootstrapsTheTrackingTable() throws Exception {
        var field = CassandraSchemaMigrations.class.getDeclaredField("MIGRATIONS");
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.LinkedHashMap<String, String> migrations =
                (java.util.LinkedHashMap<String, String>) field.get(null);

        String firstKey = migrations.keySet().iterator().next();
        assertThat(firstKey).isEqualTo("001-schema-migrations-table");
        assertThat(migrations.get(firstKey)).contains("CREATE TABLE IF NOT EXISTS schema_migrations");
    }

    @Test
    void migrationIds_areInZeroPaddedAscendingOrder() throws Exception {
        var field = CassandraSchemaMigrations.class.getDeclaredField("MIGRATIONS");
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.LinkedHashMap<String, String> migrations =
                (java.util.LinkedHashMap<String, String>) field.get(null);

        String prev = null;
        for (String id : migrations.keySet()) {
            if (prev != null) {
                assertThat(id.compareTo(prev))
                    .as("migration id %s should sort after %s", id, prev)
                    .isGreaterThan(0);
            }
            assertThat(id).matches("^[0-9]{3}-[a-z0-9-]+$");
            prev = id;
        }
    }

    @Test
    void coreTableMigrations_areAllPresent() throws Exception {
        var field = CassandraSchemaMigrations.class.getDeclaredField("MIGRATIONS");
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.LinkedHashMap<String, String> migrations =
                (java.util.LinkedHashMap<String, String>) field.get(null);

        assertThat(migrations).containsKeys(
                "001-schema-migrations-table",
                "002-revocations-table",
                "003-url-registry-table",
                "004-resource-access-table",
                "005-gateway-route-access-table",
                "006-hs-tokens-table");
    }

    /** The route-access read-cache gains a per-row {@code domain} column (the
     *  multi-brand BUG-1 fix) via an APPENDED change-id — the 005 CREATE TABLE is
     *  a shipped entry and must not be edited. The ALTER mirrors the Postgres
     *  source-of-truth column so the write-through INSERT round-trips. */
    @Test
    void gatewayRouteAccessDomainColumn_isAppendedAsAlter() throws Exception {
        var field = CassandraSchemaMigrations.class.getDeclaredField("MIGRATIONS");
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.LinkedHashMap<String, String> migrations =
                (java.util.LinkedHashMap<String, String>) field.get(null);

        assertThat(migrations).containsKey("007-gateway-route-access-domain-column");
        String cql = migrations.get("007-gateway-route-access-domain-column");
        assertThat(cql).contains("ALTER TABLE gateway_route_access ADD domain text");
        // The 005 CREATE TABLE entry is unchanged (no domain column smuggled in).
        assertThat(migrations.get("005-gateway-route-access-table"))
                .doesNotContain("domain");
    }

    /** The DB-driven route-DEFINITION table gains a per-row {@code strip_prefix int}
     *  column (the StripPrefix-faithfulness fix) via an APPENDED change-id — the 003
     *  CREATE TABLE is a shipped entry and must not be edited. The column lets the
     *  seeded /be/** route reproduce the static be-default route's StripPrefix=1. */
    @Test
    void urlRegistryStripPrefixColumn_isAppendedAsAlter() throws Exception {
        var field = CassandraSchemaMigrations.class.getDeclaredField("MIGRATIONS");
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.LinkedHashMap<String, String> migrations =
                (java.util.LinkedHashMap<String, String>) field.get(null);

        assertThat(migrations).containsKey("008-url-registry-strip-prefix-column");
        String cql = migrations.get("008-url-registry-strip-prefix-column");
        assertThat(cql).contains("ALTER TABLE url_registry ADD strip_prefix int");
        // The 003 CREATE TABLE entry is unchanged (no strip_prefix column smuggled in).
        assertThat(migrations.get("003-url-registry-table"))
                .doesNotContain("strip_prefix");
    }

    /** The revocation list gains a per-row OWNING {@code domain} column (the
     *  cross-tenant revocation BFLA fix, CWE-639) via an APPENDED change-id — the
     *  002 CREATE TABLE is a shipped entry and must not be edited. The ALTER lets a
     *  revocation row record the validated-issuer brand of the admin who wrote it so
     *  the write surface can 403 a cross-domain clear/overwrite. */
    @Test
    void revocationsDomainColumn_isAppendedAsAlter() throws Exception {
        var field = CassandraSchemaMigrations.class.getDeclaredField("MIGRATIONS");
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.LinkedHashMap<String, String> migrations =
                (java.util.LinkedHashMap<String, String>) field.get(null);

        assertThat(migrations).containsKey("009-revocations-domain-column");
        String cql = migrations.get("009-revocations-domain-column");
        assertThat(cql).contains("ALTER TABLE revocations ADD domain text");
        // The 002 CREATE TABLE entry is unchanged (no domain column smuggled in).
        assertThat(migrations.get("002-revocations-table"))
                .doesNotContain("domain");
    }

    /** D8: the route-access read-cache gains a per-row {@code mfa_required boolean}
     *  column via an APPENDED change-id (010, next after 009) — the 005 CREATE TABLE
     *  is a shipped entry and must not be edited. The ALTER mirrors the Postgres
     *  source-of-truth column so the write-through INSERT round-trips 1:1. */
    @Test
    void gatewayRouteAccessMfaRequiredColumn_isAppendedAsAlter() throws Exception {
        var field = CassandraSchemaMigrations.class.getDeclaredField("MIGRATIONS");
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.LinkedHashMap<String, String> migrations =
                (java.util.LinkedHashMap<String, String>) field.get(null);

        assertThat(migrations).containsKey("010-gateway-route-access-mfa-required-column");
        String cql = migrations.get("010-gateway-route-access-mfa-required-column");
        assertThat(cql).contains("ALTER TABLE gateway_route_access ADD mfa_required boolean");
        // 010 is the LAST (newest) change-id — never inserted before a shipped one.
        assertThat(migrations.keySet()).last().isEqualTo("010-gateway-route-access-mfa-required-column");
        // The 005 CREATE TABLE entry is unchanged (no mfa_required smuggled in).
        assertThat(migrations.get("005-gateway-route-access-table"))
                .doesNotContain("mfa_required");
    }

    /** The account-states PREREQ table (P0) maps a HASHED homeserver bearer
     *  to {localpart, platform, kind, app/device id} and is TTL-bounded like
     *  the revocations table so stale token rows self-expire. We never store
     *  the raw bearer — the primary key is token_hash. */
    @Test
    void hsTokensMigration_isHashKeyedAndTtlBounded() throws Exception {
        var field = CassandraSchemaMigrations.class.getDeclaredField("MIGRATIONS");
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.LinkedHashMap<String, String> migrations =
                (java.util.LinkedHashMap<String, String>) field.get(null);

        String cql = migrations.get("006-hs-tokens-table");
        assertThat(cql).contains("CREATE TABLE IF NOT EXISTS hs_tokens");
        assertThat(cql).contains("token_hash text PRIMARY KEY");
        assertThat(cql).contains("localpart");
        assertThat(cql).contains("platform");
        assertThat(cql).contains("kind");
        assertThat(cql).contains("app_or_device_id");
        assertThat(cql).contains("default_time_to_live");
    }
}
