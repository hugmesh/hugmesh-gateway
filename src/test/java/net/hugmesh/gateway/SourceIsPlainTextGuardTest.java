package net.hugmesh.gateway;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * GREPPABILITY GUARD (Tier-1 meta-test) &mdash; every source file under {@code src/} must be
 * plain text, i.e. contain no NUL (0x00) byte.
 *
 * <p><b>Why this guard exists.</b> {@code BffJwtExchangeWebFilter.java} &mdash; the
 * platform's fail-closed {@code bff_} to custody-JWT swap filter &mdash; shipped for two
 * rounds with two RAW NUL bytes inside its {@code REJECT} sentinel literal. That is legal
 * Java and compiles to exactly the same constant, but it reclassifies the file:
 * {@code file(1)} calls it {@code data}, and GNU {@code grep} then SKIPS THE ENTIRE FILE
 * while exiting 1 &mdash; the same exit code as "searched it, found nothing". Every audit,
 * CI guard, review script or agent that greps this tree for a property key, constant or
 * annotation therefore got a confident clean answer over a file it never read. It happened
 * during this filter's own review: a repo-wide {@code grep -rn 'request-timeout-ms'}
 * reported the key absent from the whole repository while it sat in that constructor. A
 * guard that cannot see its subject reports PASS, which is the worst failure mode a guard
 * has.
 *
 * <p>Fixing the one file is not enough &mdash; the hazard returns with any future literal
 * (a sentinel, a test fixture, a separator) written as a raw control byte instead of an
 * escape. So this pins the property for the whole tree. The fix is never to delete the
 * character: write it as a Java escape, which keeps the compiled value identical and the
 * file readable by every tool.
 */
class SourceIsPlainTextGuardTest {

    /** The module root, resolved the way Surefire hands it over. */
    private static Path moduleRoot() {
        String base = System.getProperty("basedir", System.getProperty("user.dir"));
        Path root = Path.of(base);
        // FAIL, never skip: a guard that cannot locate its subject must say so loudly
        // rather than pass vacuously (the exact failure mode it exists to prevent).
        assertThat(root.resolve("src/main/java"))
                .as("cannot locate the module's sources from basedir/user.dir=%s - this "
                        + "guard must fail rather than pass over an empty file set", base)
                .isDirectory();
        return root;
    }

    @Test
    void noSourceFileUnderSrc_containsARawNulByte() throws IOException {
        Path src = moduleRoot().resolve("src");
        List<Path> scanned = new ArrayList<>();
        List<String> offenders = new ArrayList<>();

        try (Stream<Path> tree = Files.walk(src)) {
            for (Path p : tree.filter(Files::isRegularFile).toList()) {
                scanned.add(p);
                for (byte b : Files.readAllBytes(p)) {
                    if (b == 0) {
                        offenders.add(src.getParent().relativize(p).toString());
                        break;
                    }
                }
            }
        }

        assertThat(scanned)
                .as("the scan must actually have read files - an empty walk would make "
                        + "this guard pass vacuously")
                .hasSizeGreaterThan(50);
        assertThat(offenders)
                .as("these sources contain a raw NUL byte, so file(1) calls them 'data' and "
                        + "a plain grep silently SKIPS them (exit 1, no output) - write the "
                        + "character as a Java escape instead; the compiled value is "
                        + "identical and the file stays greppable")
                .isEmpty();
    }

    @Test
    void theSwapFiltersRejectSentinel_stillDelimitsWithRealNulCharacters() throws Exception {
        // The de-NUL fix changed the SOURCE ENCODING only. This pins the compiled constant:
        // the escape must still decode to the same NUL-delimited sentinel, which is what
        // makes it impossible for a real custody JWT to equal it.
        var field = net.hugmesh.gateway.filter.BffJwtExchangeWebFilter.class
                .getDeclaredField("REJECT");
        field.setAccessible(true);
        String reject = (String) field.get(null);

        assertThat(reject)
                .as("the sentinel must stay NUL-delimited - a JWT can never contain 0x00, "
                        + "which is precisely why it can never collide with this value")
                .isEqualTo("\0bff-exchange-reject\0");
        assertThat(reject.charAt(0)).isEqualTo('\0');
        assertThat(reject.charAt(reject.length() - 1)).isEqualTo('\0');
    }
}
