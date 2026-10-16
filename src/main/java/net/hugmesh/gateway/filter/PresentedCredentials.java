package net.hugmesh.gateway.filter;

import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.ObjectReadContext;
import tools.jackson.core.json.JsonFactory;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Every homeserver bearer a request presents, from every channel a homeserver reads one
 * from: each {@code Authorization} header line (and each comma-joined entry within a
 * line), the {@code access_token} / {@code bearer_token} query parameters, and the same
 * parameters in a form or JSON body. A downstream picks ONE of these by its own rule
 * (first header, last parameter, parameter before header); the revocation filter does
 * not guess which, it refuses the request unless every one of them passes.
 *
 * <p>A credential that cannot be read unambiguously (a malformed escape in a
 * token-named parameter, a body that does not parse as its declared type) makes the
 * set {@link #malformed() malformed}: the caller refuses it rather than forward a
 * request whose token it could not see.
 */
final class PresentedCredentials {

    /** Parameter names homeservers accept a bearer under: the Matrix query parameter
     *  and the OAuth access_token parameter (RFC 6750 s2.2/2.3), plus Doorkeeper's
     *  bearer_token. Compared case-insensitively so a case-folding parser is covered. */
    private static final Set<String> TOKEN_PARAMS = Set.of("access_token", "bearer_token");

    /** {@code Bearer <t>}, {@code bearer:<t>}, any whitespace run between them. */
    private static final Pattern BEARER = Pattern.compile("(?i)^bearer(?::\\s*|\\s+)(.*)$", Pattern.DOTALL);

    private final Set<String> tokens = new LinkedHashSet<>();
    private boolean malformed;

    Set<String> tokens() { return tokens; }

    boolean malformed() { return malformed; }

    boolean isEmpty() { return tokens.isEmpty() && !malformed; }

    /** Header lines and query string. */
    static PresentedCredentials of(ServerHttpRequest request) {
        PresentedCredentials c = new PresentedCredentials();
        List<String> auth = request.getHeaders().get(HttpHeaders.AUTHORIZATION);
        if (auth != null) {
            for (String line : auth) c.addAuthorization(line);
        }
        c.addFormEncoded(request.getURI().getRawQuery(), true);
        return c;
    }

    void addAuthorization(String line) {
        if (line == null) return;
        for (String part : line.split(",")) {
            Matcher m = BEARER.matcher(part.strip());
            if (m.matches()) add(m.group(1).strip());
        }
    }

    /** {@code application/x-www-form-urlencoded} pairs, which is also the query-string
     *  grammar. {@code ;} is accepted as a separator as older parsers do. */
    void addFormEncoded(String raw, boolean query) {
        if (raw == null || raw.isEmpty()) return;
        for (String pair : raw.split("[&;]")) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            String rawName = eq < 0 ? pair : pair.substring(0, eq);
            String rawValue = eq < 0 ? "" : pair.substring(eq + 1);
            String name = decode(rawName, true);
            if (name == null) {
                // A name we cannot read could be a token parameter to a laxer parser.
                if (rawName.toLowerCase(Locale.ROOT).contains("token")) malformed = true;
                continue;
            }
            if (!isTokenParam(name)) continue;
            String plusAsSpace = decode(rawValue, true);
            String plusLiteral = decode(rawValue, false);
            if (plusAsSpace == null || plusLiteral == null) {
                malformed = true;
                continue;
            }
            // Both readings of '+': a parser that keeps it literal sees a different token.
            add(plusAsSpace.strip());
            add(plusLiteral.strip());
        }
    }

    /** Top-level string members of a JSON object body named like a token parameter. */
    void addJson(byte[] body) {
        if (body.length == 0) return;
        try (JsonParser p = new JsonFactory().createParser(ObjectReadContext.empty(), body)) {
            JsonToken first = p.nextToken();
            if (first != JsonToken.START_OBJECT) {
                // Not an object: no named members to carry a token. Still read it
                // through so a body that does not parse is refused like any other.
                if (first != null) p.skipChildren();
                while (p.nextToken() != null) { /* drain */ }
                return;
            }
            JsonToken t;
            while ((t = p.nextToken()) == JsonToken.PROPERTY_NAME) {
                String name = p.currentName();
                JsonToken v = p.nextToken();
                if (isTokenParam(name)) {
                    if (v == JsonToken.VALUE_STRING) {
                        add(p.getString().strip());
                    } else if (v != JsonToken.VALUE_NULL) {
                        // a token parameter whose value is not a string has no single reading
                        malformed = true;
                    }
                }
                p.skipChildren();
            }
            if (t != JsonToken.END_OBJECT || p.nextToken() != null) malformed = true;
        } catch (RuntimeException e) {
            malformed = true;
        }
    }

    void markMalformed() { malformed = true; }

    private void add(String token) {
        if (!token.isEmpty()) tokens.add(token);
    }

    private static boolean isTokenParam(String name) {
        return TOKEN_PARAMS.contains(name.strip().toLowerCase(Locale.ROOT));
    }

    /** Strict UTF-8 percent-decoding; {@code null} on a malformed escape or bad bytes. */
    static String decode(String raw, boolean plusAsSpace) {
        if (raw.indexOf('%') < 0 && (!plusAsSpace || raw.indexOf('+') < 0)) return raw;
        byte[] in = raw.getBytes(StandardCharsets.UTF_8);
        ByteBuffer out = ByteBuffer.allocate(in.length);
        for (int i = 0; i < in.length; i++) {
            byte b = in[i];
            if (b == '+' && plusAsSpace) {
                out.put((byte) ' ');
            } else if (b == '%') {
                if (i + 2 >= in.length) return null;
                int hi = Character.digit(in[i + 1], 16);
                int lo = Character.digit(in[i + 2], 16);
                if (hi < 0 || lo < 0) return null;
                out.put((byte) ((hi << 4) | lo));
                i += 2;
            } else {
                out.put(b);
            }
        }
        out.flip();
        try {
            CharBuffer chars = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(out);
            return chars.toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }
}
