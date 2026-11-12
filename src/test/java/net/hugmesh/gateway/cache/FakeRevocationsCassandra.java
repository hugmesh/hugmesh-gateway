package net.hugmesh.gateway.cache;

import com.datastax.oss.driver.api.core.cql.Row;
import org.mockito.invocation.InvocationOnMock;
import org.springframework.data.cassandra.core.ReactiveCassandraTemplate;
import org.springframework.data.cassandra.core.cql.ReactiveCqlOperations;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * An in-memory {@code revocations} table that answers the statements
 * {@link RevocationListService} sends the way Cassandra does, lightweight transactions
 * included: {@code INSERT … IF NOT EXISTS} returns the existing row when it does not
 * apply, and {@code UPDATE … IF expires_at = ?} applies only when the stored value equals
 * the bound one (null matches a missing value).
 *
 * <p>It also accepts the UNCONDITIONAL forms (plain {@code INSERT … USING TTL}, plain
 * {@code UPDATE}, plain {@code DELETE}) and applies them as Cassandra would — last write
 * wins. That way a regression back to an unconditional write is caught by what ends up in
 * the row, not merely by an unknown statement. Anything else fails the test.
 *
 * <p>Time does not pass here: a row's {@code ttl} is the TTL it was last written with.
 * {@link #beforeUpdate} runs just before each UPDATE is evaluated,
 * standing in for another gateway pod that changes the same key between this pod's read
 * and its compare-and-set.
 */
final class FakeRevocationsCassandra {

    /** One stored row; {@code ttl} null = no TTL on the cells (never expires). */
    record StoredRow(String reason, Instant revokedAt, Instant expiresAt, String domain, Integer ttl) {}

    final Map<String, StoredRow> rows = Collections.synchronizedMap(new HashMap<>());
    /** Every statement in the order received. */
    final List<String> statements = Collections.synchronizedList(new ArrayList<>());
    /** Called with the key just before an UPDATE is evaluated; null = nothing. */
    volatile Consumer<String> beforeUpdate;
    /** Called with the key just before the remaining-TTL read; null = nothing. */
    volatile Consumer<String> beforeTtlRead;

    private static final Pattern INSERT = Pattern.compile(
            "INSERT INTO revocations \\(revocation_key, reason, revoked_at, expires_at, domain\\) "
            + "VALUES \\(\\?, \\?, \\?, \\?, \\?\\)( IF NOT EXISTS)?( USING TTL (\\d+))?");
    private static final Pattern UPDATE = Pattern.compile(
            "UPDATE revocations USING TTL (\\d+) SET reason = \\?, revoked_at = \\?, expires_at = \\?, "
            + "domain = \\? WHERE revocation_key = \\?( IF expires_at = \\?)?");
    private static final Pattern DELETE = Pattern.compile(
            "DELETE FROM revocations WHERE revocation_key = \\?( IF EXISTS)?");

    private final ReactiveCassandraTemplate template;

    FakeRevocationsCassandra() {
        ReactiveCqlOperations cql = mock(ReactiveCqlOperations.class);
        when(cql.queryForRows(anyString(), any(Object[].class))).thenAnswer(this::query);
        when(cql.execute(anyString(), any(Object[].class))).thenAnswer(this::execute);
        template = mock(ReactiveCassandraTemplate.class);
        when(template.getReactiveCqlOperations()).thenReturn(cql);
    }

    ReactiveCassandraTemplate template() {
        return template;
    }

    StoredRow row(String key) {
        return rows.get(key);
    }

    /** Statements that change the table. */
    List<String> writes() {
        synchronized (statements) {
            return statements.stream()
                    .filter(s -> s.startsWith("INSERT") || s.startsWith("UPDATE") || s.startsWith("DELETE"))
                    .toList();
        }
    }

    // ── statement dispatch ──────────────────────────────────────────────────────

    private Flux<Row> query(InvocationOnMock inv) {
        String stmt = inv.getArgument(0);
        Object[] a = args(inv);
        statements.add(stmt);
        Matcher ins = INSERT.matcher(stmt);
        if (ins.matches()) {
            String key = (String) a[0];
            Integer ttl = ins.group(3) == null ? null : Integer.valueOf(ins.group(3));
            StoredRow incoming = new StoredRow((String) a[1], (Instant) a[2], (Instant) a[3], (String) a[4], ttl);
            synchronized (rows) {
                StoredRow existing = rows.get(key);
                if (ins.group(1) != null && existing != null) {
                    Map<String, Object> cols = new HashMap<>();
                    cols.put(RevocationListService.APPLIED, false);
                    cols.put("revocation_key", key);
                    cols.put("reason", existing.reason());
                    cols.put("revoked_at", existing.revokedAt());
                    cols.put("expires_at", existing.expiresAt());
                    cols.put("domain", existing.domain());
                    return Flux.just(resultRow(cols));
                }
                rows.put(key, incoming);
            }
            return ins.group(1) != null
                    ? Flux.just(resultRow(Map.of(RevocationListService.APPLIED, true)))
                    : Flux.empty();
        }
        if (stmt.equals(RevocationListService.SELECT_REMAINING_TTL)) {
            if (beforeTtlRead != null) beforeTtlRead.accept((String) a[0]);
            StoredRow existing = rows.get((String) a[0]);
            if (existing == null) return Flux.empty();
            Map<String, Object> cols = new HashMap<>();
            cols.put("ttl_left", existing.ttl());
            return Flux.just(resultRow(cols));
        }
        if (stmt.equals("SELECT revocation_key, reason, domain FROM revocations")) {
            List<Row> out = new ArrayList<>();
            synchronized (rows) {
                rows.forEach((k, r) -> {
                    Map<String, Object> cols = new HashMap<>();
                    cols.put("revocation_key", k);
                    cols.put("reason", r.reason());
                    cols.put("domain", r.domain());
                    out.add(resultRow(cols));
                });
            }
            return Flux.fromIterable(out);
        }
        if (stmt.startsWith("SELECT token_hash")) {
            return Flux.empty();
        }
        throw new AssertionError("unexpected CQL query: " + stmt);
    }

    private Mono<Boolean> execute(InvocationOnMock inv) {
        String stmt = inv.getArgument(0);
        Object[] a = args(inv);
        statements.add(stmt);
        Matcher upd = UPDATE.matcher(stmt);
        if (upd.matches()) {
            String key = (String) a[4];
            boolean conditional = upd.group(2) != null;
            // Another writer may get in between this pod's read and its write whatever shape
            // the write has; only a conditional one notices.
            if (beforeUpdate != null) beforeUpdate.accept(key);
            StoredRow incoming = new StoredRow((String) a[0], (Instant) a[1], (Instant) a[2], (String) a[3],
                    Integer.valueOf(upd.group(1)));
            synchronized (rows) {
                StoredRow existing = rows.get(key);
                if (conditional && (existing == null || !Objects.equals(existing.expiresAt(), a[5]))) {
                    return Mono.just(false);
                }
                rows.put(key, incoming);
            }
            return Mono.just(true);
        }
        Matcher del = DELETE.matcher(stmt);
        if (del.matches()) {
            StoredRow removed = rows.remove((String) a[0]);
            return Mono.just(del.group(1) == null || removed != null);
        }
        Matcher ins = INSERT.matcher(stmt);
        if (ins.matches() && ins.group(1) == null) {
            // The pre-fix shape went through execute(): an unconditional upsert.
            Integer ttl = ins.group(3) == null ? null : Integer.valueOf(ins.group(3));
            rows.put((String) a[0], new StoredRow((String) a[1], (Instant) a[2], (Instant) a[3], (String) a[4], ttl));
            return Mono.just(true);
        }
        throw new AssertionError("unexpected CQL statement: " + stmt);
    }

    /** The bind values whether Mockito hands the varargs over expanded or as one array. */
    private static Object[] args(InvocationOnMock inv) {
        Object[] all = inv.getArguments();
        if (all.length == 2 && all[1] instanceof Object[] arr) return arr;
        return Arrays.copyOfRange(all, 1, all.length);
    }

    private static Row resultRow(Map<String, Object> cols) {
        Map<String, Object> copy = new HashMap<>(cols);
        Row row = mock(Row.class);
        when(row.getString(anyString())).thenAnswer(inv -> (String) copy.get(inv.<String>getArgument(0)));
        when(row.getInstant(anyString())).thenAnswer(inv -> (Instant) copy.get(inv.<String>getArgument(0)));
        when(row.getBoolean(anyString())).thenAnswer(inv -> {
            Object v = copy.get(inv.<String>getArgument(0));
            if (v == null) throw new AssertionError("no boolean column " + inv.getArgument(0));
            return (Boolean) v;
        });
        when(row.isNull(anyString())).thenAnswer(inv -> copy.get(inv.<String>getArgument(0)) == null);
        when(row.getInt(anyString())).thenAnswer(inv -> {
            Object v = copy.get(inv.<String>getArgument(0));
            return v == null ? 0 : (Integer) v;
        });
        return row;
    }
}
