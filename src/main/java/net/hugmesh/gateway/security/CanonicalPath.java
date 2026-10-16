package net.hugmesh.gateway.security;

import org.springframework.http.server.reactive.ServerHttpRequest;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * The ONE view of a request path that every path-keyed authorization decision in the
 * gateway matches on: the same view Spring Cloud Gateway's {@code Path} predicates and
 * Spring Security's {@code pathMatchers} route on (the path split into segments
 * <i>before</i> percent-decoding, then each segment decoded, path parameters
 * ({@code ;x=y}) dropped), with the ambiguities a downstream could resolve differently
 * removed.
 *
 * <p><b>Why this exists.</b> {@code ServerHttpRequest#getPath().value()} is the RAW,
 * still percent-encoded string. The route-access table, the MFA step-up surface, the
 * per-resource grant and the homeserver-token revocation gate all key on
 * {@code AntPathMatcher} patterns written in the decoded spelling
 * ({@code /bff/mesh/internal/**}). Matched against the raw string,
 * {@code /bff/mesh/%69nternal/x} matched NOTHING (so the decision was
 * {@code NO_RULE}, which forwards any authenticated caller) while routing — which does
 * decode — still sent it to the very same handler.
 *
 * <p><b>The canonical form</b> ({@link #of}) is {@code "/" + segments joined by "/"}:
 * <ul>
 *   <li>every segment percent-decoded once (UTF-8);</li>
 *   <li>path parameters ({@code ;...}) removed from each segment, as routing does;</li>
 *   <li>{@code .} segments dropped and {@code ..} segments resolved, after decoding
 *       (so {@code %2e%2e} and {@code ..;x} are dot segments too);</li>
 *   <li>repeated and trailing slashes collapsed, so an exact-match row governs
 *       {@code /x}, {@code /x/} and {@code //x} alike.</li>
 * </ul>
 *
 * <p><b>Fail closed.</b> A path whose meaning a downstream could read differently is
 * not canonicalised, it is refused ({@link Optional#empty()}):
 * <ul>
 *   <li>a malformed percent escape, or bytes that are not valid UTF-8;</li>
 *   <li>a decoded segment containing {@code /} ({@code %2f}), {@code \} ({@code %5c}
 *       or a literal backslash), NUL or any other control character;</li>
 *   <li>a decoded segment that still holds a percent escape ({@code %2569} decodes to
 *       {@code %69}): a double-decoding downstream would read it as {@code i};</li>
 *   <li>a {@code ..} that climbs above the root.</li>
 * </ul>
 * Callers must treat the empty result as a request to REJECT, never as "no rule".
 */
public final class CanonicalPath {

    private CanonicalPath() {}

    /** Canonical form of the request path (within the application), or empty when the
     *  path is ambiguous and must be refused. */
    public static Optional<String> of(ServerHttpRequest request) {
        return of(request.getPath().pathWithinApplication().value());
    }

    /** Canonical form of a raw (still percent-encoded) path string. The string is split
     *  on {@code /} BEFORE any decoding, exactly as {@code PathContainer} does, so an
     *  encoded slash can never act as a separator here. */
    public static Optional<String> of(String rawPath) {
        List<String> out = new ArrayList<>();
        for (String raw : rawPath.split("/", -1)) {
            int params = raw.indexOf(';');
            if (params >= 0) {
                raw = raw.substring(0, params);   // routing matches on the segment sans ;params
            }
            String decoded = decode(raw);
            if (decoded == null || isAmbiguous(decoded)) {
                return Optional.empty();
            }
            if (decoded.isEmpty() || decoded.equals(".")) {
                continue;                         // // and a trailing / collapse; . is a no-op
            }
            if (decoded.equals("..")) {
                if (out.isEmpty()) {
                    return Optional.empty();      // climbs above the root
                }
                out.remove(out.size() - 1);
                continue;
            }
            out.add(decoded);
        }
        return Optional.of(out.isEmpty() ? "/" : "/" + String.join("/", out));
    }

    /** One strict percent-decode of a single segment; {@code null} when malformed. */
    private static String decode(String raw) {
        if (raw.indexOf('%') < 0) {
            return raw;
        }
        byte[] bytes = raw.getBytes(StandardCharsets.UTF_8);
        ByteBuffer decoded = ByteBuffer.allocate(bytes.length);
        for (int i = 0; i < bytes.length; i++) {
            byte b = bytes[i];
            if (b != '%') {
                decoded.put(b);
                continue;
            }
            if (i + 2 >= bytes.length) {
                return null;                      // truncated escape
            }
            int hi = Character.digit(bytes[i + 1], 16);
            int lo = Character.digit(bytes[i + 2], 16);
            if (hi < 0 || lo < 0) {
                return null;                      // not two hex digits
            }
            decoded.put((byte) ((hi << 4) | lo));
            i += 2;
        }
        decoded.flip();
        try {
            CharBuffer chars = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(decoded);
            return chars.toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }

    private static boolean isAmbiguous(String decoded) {
        for (int i = 0; i < decoded.length(); i++) {
            char c = decoded.charAt(i);
            if (c == '/' || c == '\\' || c < 0x20 || c == 0x7f) {
                return true;
            }
            if (c == '%' && i + 2 < decoded.length()
                    && Character.digit(decoded.charAt(i + 1), 16) >= 0
                    && Character.digit(decoded.charAt(i + 2), 16) >= 0) {
                return true;                      // residual escape: double encoding
            }
        }
        return false;
    }
}
