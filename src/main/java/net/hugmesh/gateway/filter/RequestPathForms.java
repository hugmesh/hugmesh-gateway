package net.hugmesh.gateway.filter;

import org.springframework.util.AntPathMatcher;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Every spelling of a request path that a downstream hop could act on.
 *
 * <p>{@code ServerHttpRequest#getPath().value()} is the RAW path. Spring's
 * {@code PathPattern}, which the gateway's {@code Path} route predicate uses,
 * matches on the percent-DECODED segments with path parameters stripped (pinned
 * in {@code RequestPathFormsTest}), and the homeserver behind the gateway decodes
 * again. A filter that matches its pattern on the raw string alone is therefore
 * walked around by an encoded or parameterised spelling of the prefix itself
 * ({@code /%5Fmatrix/...}, {@code /_matrix;x/...}); dot segments, doubled
 * slashes and letter case are not normalised by the router, but a homeserver may
 * normalise them. This class computes the set of forms such a request can take,
 * so a caller decides on the whole set instead of one spelling.
 *
 * <p>Forms produced, for the raw path and for each percent-decode round (up to
 * {@value #MAX_DECODE_ROUNDS}): the verbatim string, a lexical form (path
 * parameters stripped, {@code \} read as {@code /}, empty segments and the
 * trailing slash dropped) and the dot-normalised form of that.
 *
 * <p>Two questions, with opposite polarity so that every doubt resolves to the
 * stricter answer:
 * <ul>
 *   <li>{@link #anyMatches(String...)}: does ANY form match one of the
 *       patterns, ignoring case? Used to decide that a path is protected.</li>
 *   <li>{@link #allMatch(String...)}: does EVERY form match one of the patterns,
 *       case-sensitively? Used to decide that a path is exempt.</li>
 * </ul>
 *
 * <p>{@link #isAmbiguous()} is true when the path cannot be given one reading: a
 * malformed escape in the raw path, an encoded NUL, bytes that are not UTF-8, or
 * encoding nested deeper than {@value #MAX_DECODE_ROUNDS} rounds
 * ({@link #isNestedTooDeep()}). A caller that guards something should refuse
 * such a path on the guarded surface rather than guess.
 */
public final class RequestPathForms {

    /** Decode rounds applied. Three covers {@code %25252e}; deeper is ambiguous. */
    static final int MAX_DECODE_ROUNDS = 3;

    private static final AntPathMatcher SENSITIVE = new AntPathMatcher();
    private static final AntPathMatcher INSENSITIVE = new AntPathMatcher();
    static {
        INSENSITIVE.setCaseSensitive(false);
    }

    private final List<String> forms;
    private final boolean ambiguous;
    private final boolean tooDeep;

    private RequestPathForms(List<String> forms, boolean ambiguous, boolean tooDeep) {
        this.forms = Collections.unmodifiableList(forms);
        this.ambiguous = ambiguous;
        this.tooDeep = tooDeep;
    }

    public static RequestPathForms of(String rawPath) {
        String raw = rawPath == null ? "" : rawPath;
        Set<String> out = new LinkedHashSet<>();
        out.add(raw);
        addNormalised(out, raw);

        boolean ambiguous = false;
        String level = raw;
        for (int round = 0; round < MAX_DECODE_ROUNDS; round++) {
            Decoded d = decode(level, round == 0);
            ambiguous |= d.flagged;
            if (d.text.equals(level)) break;
            level = d.text;
            out.add(level);
            addNormalised(out, level);
        }
        // Still changing after the last round: the nesting is deeper than we follow.
        Decoded rest = decode(level, false);
        boolean tooDeep = !rest.text.equals(level);
        if (tooDeep || rest.flagged) ambiguous = true;
        return new RequestPathForms(new ArrayList<>(out), ambiguous, tooDeep);
    }

    public List<String> forms() {
        return forms;
    }

    public boolean isAmbiguous() {
        return ambiguous;
    }

    /**
     * True when the encoding is nested deeper than {@value #MAX_DECODE_ROUNDS}
     * rounds, so the forms cannot show what the path finally decodes to. Unlike
     * the other kinds of ambiguity, this means a "not under prefix X" answer from
     * {@link #anyMatches} cannot be trusted either.
     */
    public boolean isNestedTooDeep() {
        return tooDeep;
    }

    /** True if any form matches any pattern, ignoring case. */
    public boolean anyMatches(String... patterns) {
        for (String form : forms) {
            for (String p : patterns) {
                if (INSENSITIVE.match(p, form)) return true;
            }
        }
        return false;
    }

    /** True only if every form matches some pattern, case-sensitively. */
    public boolean allMatch(String... patterns) {
        for (String form : forms) {
            boolean hit = false;
            for (String p : patterns) {
                if (SENSITIVE.match(p, form)) {
                    hit = true;
                    break;
                }
            }
            if (!hit) return false;
        }
        return true;
    }

    // ── normalisation ─────────────────────────────────────────────────────────

    private static void addNormalised(Set<String> out, String path) {
        List<String> segments = lexicalSegments(path);
        out.add("/" + String.join("/", segments));
        List<String> dotted = new ArrayList<>();
        for (String s : segments) {
            if (s.equals(".")) continue;
            if (s.equals("..")) {
                if (!dotted.isEmpty()) dotted.remove(dotted.size() - 1);
                continue;
            }
            dotted.add(s);
        }
        out.add("/" + String.join("/", dotted));
    }

    private static List<String> lexicalSegments(String path) {
        List<String> segments = new ArrayList<>();
        for (String s : path.replace('\\', '/').split("/", -1)) {
            int semi = s.indexOf(';');
            if (semi >= 0) s = s.substring(0, semi);
            if (!s.isEmpty()) segments.add(s);
        }
        return segments;
    }

    // ── percent decoding ──────────────────────────────────────────────────────

    private record Decoded(String text, boolean flagged) {}

    /**
     * One decode round. {@code flagged} is set for an encoded NUL, bytes that are
     * not UTF-8 and, when {@code strictEscapes} (the raw path), a {@code %} that
     * does not start a valid escape. In later rounds a bare {@code %} is just the
     * decoded form of {@code %25} and is kept literally.
     */
    private static Decoded decode(String in, boolean strictEscapes) {
        if (in.indexOf('%') < 0) {
            return new Decoded(in, in.indexOf('\0') >= 0);
        }
        boolean flagged = false;
        StringBuilder sb = new StringBuilder(in.length());
        ByteArrayOutputStream run = new ByteArrayOutputStream();
        int i = 0;
        int n = in.length();
        while (i < n) {
            char c = in.charAt(i);
            if (c == '%' && i + 2 < n && hex(in.charAt(i + 1)) >= 0 && hex(in.charAt(i + 2)) >= 0) {
                run.write(hex(in.charAt(i + 1)) * 16 + hex(in.charAt(i + 2)));
                i += 3;
                continue;
            }
            if (run.size() > 0) {
                flagged |= flush(run, sb);
            }
            if (c == '%' && strictEscapes) flagged = true;
            sb.append(c);
            i++;
        }
        if (run.size() > 0) flagged |= flush(run, sb);
        String text = sb.toString();
        if (text.indexOf('\0') >= 0) flagged = true;
        return new Decoded(text, flagged);
    }

    /** Append the pending escaped bytes as UTF-8; true if they are not valid UTF-8. */
    private static boolean flush(ByteArrayOutputStream run, StringBuilder sb) {
        byte[] bytes = run.toByteArray();
        run.reset();
        try {
            sb.append(StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)));
            return false;
        } catch (CharacterCodingException e) {
            // ASCII bytes decode identically in Latin-1, so matching still sees them.
            sb.append(new String(bytes, StandardCharsets.ISO_8859_1));
            return true;
        }
    }

    private static int hex(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }
}
