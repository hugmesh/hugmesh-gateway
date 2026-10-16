package net.hugmesh.gateway.filter;

import org.junit.jupiter.api.Test;
import org.springframework.http.server.PathContainer;
import org.springframework.web.util.pattern.PathPatternParser;

import static org.assertj.core.api.Assertions.assertThat;

class RequestPathFormsTest {

    @Test
    void plainPath_hasOneReading() {
        var f = RequestPathForms.of("/_matrix/client/v3/sync");
        assertThat(f.isAmbiguous()).isFalse();
        assertThat(f.forms()).containsExactly("/_matrix/client/v3/sync");
    }

    @Test
    void encodedSegment_isDecoded() {
        assertThat(RequestPathForms.of("/_matrix/client/%76r0/sync").forms())
                .contains("/_matrix/client/vr0/sync");
    }

    @Test
    void doubleEncoding_isFollowedToTheEnd() {
        assertThat(RequestPathForms.of("/%25255Fmatrix/x").forms()).contains("/_matrix/x");
    }

    @Test
    void dotSegmentsAndParams_areResolvedAndTheLiteralFormIsKept() {
        var f = RequestPathForms.of("/.well-known/../_matrix;a=b/x");
        assertThat(f.forms()).contains("/_matrix/x", "/.well-known/../_matrix/x");
        assertThat(f.anyMatches("/_matrix/**")).isTrue();
        assertThat(f.allMatch("/.well-known/**")).isFalse();
    }

    @Test
    void anyMatches_ignoresCase_butAllMatch_doesNot() {
        var f = RequestPathForms.of("/_MATRIX/client/versions");
        assertThat(f.anyMatches("/_matrix/**")).isTrue();
        assertThat(f.allMatch("/_matrix/client/versions")).isFalse();
    }

    @Test
    void ambiguity_isFlaggedForNulBadUtf8MalformedEscapeAndDeepNesting() {
        assertThat(RequestPathForms.of("/a%00").isAmbiguous()).isTrue();
        assertThat(RequestPathForms.of("/a%ff").isAmbiguous()).isTrue();
        assertThat(RequestPathForms.of("/a%zz").isAmbiguous()).isTrue();
        assertThat(RequestPathForms.of("/a%").isAmbiguous()).isTrue();
        assertThat(RequestPathForms.of("/%2525252575").isAmbiguous()).isTrue();
        assertThat(RequestPathForms.of("/%252575").isAmbiguous()).isFalse();
    }

    @Test
    void aLiteralPercentEncodedOnce_isNotAmbiguous() {
        assertThat(RequestPathForms.of("/a%25b").isAmbiguous()).isFalse();
    }

    @Test
    void nullAndEmpty_areHandled() {
        assertThat(RequestPathForms.of(null).forms()).contains("", "/");
        assertThat(RequestPathForms.of("").isAmbiguous()).isFalse();
    }

    @Test
    void nestedTooDeep_isReportedSeparately() {
        assertThat(RequestPathForms.of("/%2525252575").isNestedTooDeep()).isTrue();
        assertThat(RequestPathForms.of("/%252575").isNestedTooDeep()).isFalse();
        assertThat(RequestPathForms.of("/a%00").isNestedTooDeep()).isFalse();
    }

    @Test
    void springPathPattern_matchesOnDecodedSegmentsWithParamsStripped() {
        // The primitive the gateway's Path route predicate is built on: the raw-path
        // string "/%5Fmatrix/..." is routed as /_matrix/..., which is why a raw-string
        // gate can be walked around.
        var pattern = PathPatternParser.defaultInstance.parse("/_matrix/**");
        assertThat(pattern.matches(PathContainer.parsePath("/_matrix/client/v3/sync"))).isTrue();
        assertThat(pattern.matches(PathContainer.parsePath("/%5Fmatrix/client/v3/sync"))).isTrue();
        assertThat(pattern.matches(PathContainer.parsePath("/_matrix;a=b/client/v3/sync"))).isTrue();
        assertThat(pattern.matches(PathContainer.parsePath("/_matrixx/client"))).isFalse();
    }
}
