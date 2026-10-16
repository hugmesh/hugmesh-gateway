package net.hugmesh.gateway.security;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The canonical form every path-keyed authorization decision matches on. Parsed with
 * the raw-string entry point (which, unlike {@code URI}, accepts the malformed spellings a
 * hostile client can put on the wire).
 */
class CanonicalPathTest {

    private static Optional<String> of(String raw) {
        return CanonicalPath.of(raw);
    }

    private static void assertCanonical(String raw, String expected) {
        assertThat(of(raw)).as("canonical form of %s", raw).contains(expected);
    }

    private static void assertRefused(String raw) {
        assertThat(of(raw)).as("%s has no single meaning and must be refused", raw).isEmpty();
    }

    @Test
    void plainPath_isUnchanged() {
        assertCanonical("/bff/mesh/internal/x", "/bff/mesh/internal/x");
        assertCanonical("/", "/");
        assertCanonical("", "/");
    }

    @Test
    void percentEncodedSegments_areDecodedOnce() {
        assertCanonical("/bff/mesh/%69nternal/x", "/bff/mesh/internal/x");
        assertCanonical("/bff/%6Desh/%69nternal/x", "/bff/mesh/internal/x");
        assertCanonical("/bff/%6desh/internal/x", "/bff/mesh/internal/x");
        assertCanonical("/%62%66%66/%6d%65%73%68", "/bff/mesh");
        assertCanonical("/_matrix/client/v3/rooms/%21abc%3Aserver/send", "/_matrix/client/v3/rooms/!abc:server/send");
        assertCanonical("/a/caf%C3%A9", "/a/café");
    }

    @Test
    void dotSegments_areResolvedAfterDecoding() {
        assertCanonical("/bff/mesh/x/../internal", "/bff/mesh/internal");
        assertCanonical("/bff/mesh/./internal", "/bff/mesh/internal");
        assertCanonical("/bff/mesh/x/%2e%2e/internal", "/bff/mesh/internal");
        assertCanonical("/bff/mesh/x/%2E%2E/internal", "/bff/mesh/internal");
        assertCanonical("/bff/mesh/%2e/internal", "/bff/mesh/internal");
        assertCanonical("/bff/mesh/..;/mesh/internal", "/bff/mesh/internal");
    }

    @Test
    void repeatedAndTrailingSlashes_collapse() {
        assertCanonical("//bff//mesh///internal", "/bff/mesh/internal");
        assertCanonical("/bff/mesh/internal/", "/bff/mesh/internal");
        assertCanonical("/bff/mesh/internal//", "/bff/mesh/internal");
    }

    @Test
    void pathParameters_areDropped() {
        assertCanonical("/bff/mesh/internal;a=b/x", "/bff/mesh/internal/x");
        assertCanonical("/bff/mesh;x/internal/x;jsessionid=1", "/bff/mesh/internal/x");
        // an ENCODED semicolon is not a parameter delimiter: routing keeps it in the segment
        assertCanonical("/a/b%3Bc", "/a/b;c");
    }

    @Test
    void caseIsNotFolded() {
        // the router matches case-sensitively; the gate must agree, not be looser or stricter
        assertCanonical("/BFF/Mesh/Internal", "/BFF/Mesh/Internal");
    }

    @Test
    void doubleEncoding_isRefused() {
        assertRefused("/bff/mesh/%2569nternal/x");     // decodes to %69nternal
        assertRefused("/a/%252e%252e/b");
        assertRefused("/a/%2541");
    }

    @Test
    void aPercentThatIsNotAnEscape_isKept() {
        // %25 followed by a non-hex pair decodes to a literal percent that no one can re-read
        assertCanonical("/a/100%25", "/a/100%");
        assertCanonical("/a/50%25zz", "/a/50%zz");
    }

    @Test
    void encodedSlashAndBackslash_areRefused() {
        assertRefused("/bff/mesh%2Finternal/x");
        assertRefused("/bff/mesh%2finternal/x");
        assertRefused("/bff/mesh%5Cinternal/x");
        assertRefused("/bff/mesh%5cinternal/x");
        assertRefused("/bff/mesh\\internal/x");
    }

    @Test
    void nulAndControlCharacters_areRefused() {
        assertRefused("/bff/internal%00/x");
        assertRefused("/bff/internal%0d%0a/x");
        assertRefused("/bff/internal%09/x");
        assertRefused("/bff/internal%7f/x");
    }

    @Test
    void malformedEscapesAndInvalidUtf8_areRefused() {
        assertRefused("/a/%zz");
        assertRefused("/a/%");
        assertRefused("/a/%4");
        assertRefused("/a/b%");
        assertRefused("/a/%c3");          // truncated UTF-8 sequence
        assertRefused("/a/%ff%fe");       // not UTF-8
    }

    @Test
    void climbingAboveTheRoot_isRefused() {
        assertRefused("/..");
        assertRefused("/../bff");
        assertRefused("/a/../../bff");
        assertRefused("/%2e%2e/bff");
    }
}
