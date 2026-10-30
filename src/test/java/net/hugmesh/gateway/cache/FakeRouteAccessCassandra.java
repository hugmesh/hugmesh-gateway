package net.hugmesh.gateway.cache;

import com.datastax.oss.driver.api.core.cql.Row;
import org.mockito.invocation.InvocationOnMock;
import org.springframework.data.cassandra.core.ReactiveCassandraTemplate;
import org.springframework.data.cassandra.core.cql.ReactiveCqlOperations;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import net.hugmesh.gateway.cache.GatewayRouteAccessService.Rule;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * An in-memory stand-in for the two route-access cache tables
 * ({@code gateway_route_access_gen} + {@code gateway_route_access_current}),
 * answering exactly the CQL statements {@link GatewayRouteAccessService} issues
 * through {@code queryForRows(String, Object...)} and {@code execute(String, Object...)}.
 * Any other statement fails the test loudly instead of silently returning null.
 *
 * <p>Failure hooks: {@link #failGenerationInsertsAfter} makes the n+1-th row INSERT
 * of a mirror error (a timeout or a pod kill part-way through), and
 * {@link #throwSynchronouslyOnNextQueries} makes the next queries THROW from the
 * driver call itself rather than return an error signal.
 */
final class FakeRouteAccessCassandra {

    /** gateway -> {generation, row_count, content_hash}. */
    final Map<String, Map<String, Object>> markers = new ConcurrentHashMap<>();
    /** "gateway|generation" -> id -> row columns. */
    final Map<String, Map<String, Map<String, Object>>> generations = new ConcurrentHashMap<>();

    final AtomicInteger markerReads = new AtomicInteger();
    final AtomicInteger generationReads = new AtomicInteger();
    final AtomicInteger rowInserts = new AtomicInteger();
    final AtomicInteger markerWrites = new AtomicInteger();
    final AtomicInteger generationDeletes = new AtomicInteger();

    /** Row INSERTs allowed before every further one errors; {@code -1} = never fail. */
    volatile int failGenerationInsertsAfter = -1;
    /** How many upcoming {@code queryForRows} calls throw synchronously. */
    final AtomicInteger throwSynchronouslyOnNextQueries = new AtomicInteger();

    private final ReactiveCassandraTemplate template;

    FakeRouteAccessCassandra() {
        ReactiveCqlOperations cql = mock(ReactiveCqlOperations.class);
        when(cql.queryForRows(anyString(), any(Object[].class))).thenAnswer(this::query);
        when(cql.execute(anyString(), any(Object[].class))).thenAnswer(this::execute);
        template = mock(ReactiveCassandraTemplate.class);
        when(template.getReactiveCqlOperations()).thenReturn(cql);
    }

    ReactiveCassandraTemplate template() {
        return template;
    }

    // ── direct state set-up ─────────────────────────────────────────────────────

    /** A COMPLETE generation for {@code gateway}, marked current, exactly as the
     *  service's own mirror would leave it. */
    void putCompleteGeneration(String gateway, String generation, List<Rule> rules) {
        putRows(gateway, generation, rules);
        mark(gateway, generation, rules.size(), GatewayRouteAccessService.contentHash(rules));
    }

    void putRows(String gateway, String generation, List<Rule> rules) {
        Map<String, Map<String, Object>> rows = generations.computeIfAbsent(key(gateway, generation),
                k -> new ConcurrentHashMap<>());
        for (Rule r : rules) {
            Map<String, Object> cols = new HashMap<>();
            cols.put("id", r.id());
            cols.put("gateway", r.gateway());
            cols.put("url_pattern", r.urlPattern());
            cols.put("role", r.role());
            cols.put("casdoor_user", r.casdoorUser());
            cols.put("allow", r.allow());
            cols.put("domain", r.domain());
            cols.put("mfa_required", r.mfaRequired());
            rows.put(r.id(), cols);
        }
    }

    void mark(String gateway, String generation, int rowCount, String contentHash) {
        Map<String, Object> m = new HashMap<>();
        m.put("generation", generation);
        m.put("row_count", rowCount);
        m.put("content_hash", contentHash);
        markers.put(gateway, m);
    }

    /** Lose every cache row and marker (a rebuilt Cassandra). */
    void clear() {
        markers.clear();
        generations.clear();
    }

    String currentGeneration(String gateway) {
        Map<String, Object> m = markers.get(gateway);
        return m == null ? null : (String) m.get("generation");
    }

    List<String> generationIds(String gateway) {
        List<String> out = new ArrayList<>();
        for (String k : generations.keySet()) {
            if (k.startsWith(gateway + "|")) out.add(k.substring(gateway.length() + 1));
        }
        return out;
    }

    int rowsIn(String gateway, String generation) {
        Map<String, Map<String, Object>> rows = generations.get(key(gateway, generation));
        return rows == null ? 0 : rows.size();
    }

    // ── statement dispatch ──────────────────────────────────────────────────────

    private Flux<Row> query(InvocationOnMock inv) {
        String stmt = inv.getArgument(0);
        Object[] args = args(inv);
        if (throwSynchronouslyOnNextQueries.getAndUpdate(n -> n > 0 ? n - 1 : 0) > 0) {
            throw new IllegalStateException("driver threw synchronously building: " + stmt);
        }
        if (stmt.equals(GatewayRouteAccessService.SELECT_MARKER)) {
            markerReads.incrementAndGet();
            Map<String, Object> m = markers.get((String) args[0]);
            return m == null ? Flux.empty() : Flux.just(row(m));
        }
        if (stmt.equals(GatewayRouteAccessService.SELECT_GENERATION)) {
            generationReads.incrementAndGet();
            Map<String, Map<String, Object>> rows = generations.get(key((String) args[0], (String) args[1]));
            if (rows == null) return Flux.empty();
            return Flux.fromIterable(new ArrayList<>(rows.values())).map(FakeRouteAccessCassandra::row);
        }
        throw new AssertionError("unexpected CQL query: " + stmt);
    }

    private Mono<Boolean> execute(InvocationOnMock inv) {
        String stmt = inv.getArgument(0);
        Object[] a = args(inv);
        if (stmt.equals(GatewayRouteAccessService.INSERT_GENERATION_ROW)) {
            int n = rowInserts.incrementAndGet();
            int limit = failGenerationInsertsAfter;
            if (limit >= 0 && n > limit) {
                return Mono.error(new RuntimeException("Query timed out after PT2S (simulated)"));
            }
            Map<String, Object> cols = new HashMap<>();
            cols.put("gateway", a[0]);
            cols.put("id", a[2]);
            cols.put("url_pattern", a[3]);
            cols.put("role", a[4]);
            cols.put("casdoor_user", a[5]);
            cols.put("allow", a[6]);
            cols.put("domain", a[7]);
            cols.put("mfa_required", a[8]);
            generations.computeIfAbsent(key((String) a[0], (String) a[1]), k -> new ConcurrentHashMap<>())
                    .put((String) a[2], cols);
            return Mono.just(true);
        }
        if (stmt.equals(GatewayRouteAccessService.UPSERT_MARKER)) {
            markerWrites.incrementAndGet();
            mark((String) a[0], (String) a[1], (Integer) a[2], (String) a[3]);
            return Mono.just(true);
        }
        if (stmt.equals(GatewayRouteAccessService.DELETE_GENERATION)) {
            generationDeletes.incrementAndGet();
            generations.remove(key((String) a[0], (String) a[1]));
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

    private static String key(String gateway, String generation) {
        return gateway + "|" + generation;
    }

    private static Row row(Map<String, Object> cols) {
        Map<String, Object> copy = new LinkedHashMap<>(cols);
        Row row = mock(Row.class);
        when(row.getString(anyString())).thenAnswer(inv -> (String) copy.get(inv.<String>getArgument(0)));
        when(row.getBoolean(anyString())).thenAnswer(inv -> {
            Object v = copy.get(inv.<String>getArgument(0));
            return v != null && (Boolean) v;
        });
        when(row.getInt(anyString())).thenAnswer(inv -> {
            Object v = copy.get(inv.<String>getArgument(0));
            return v == null ? 0 : (Integer) v;
        });
        return row;
    }
}
