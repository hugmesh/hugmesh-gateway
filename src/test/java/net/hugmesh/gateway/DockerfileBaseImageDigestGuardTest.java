package net.hugmesh.gateway;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * SUPPLY-CHAIN GUARD (Tier-1 meta-test) &mdash; every {@code FROM} in a Dockerfile of this
 * repo that names an external image must pin it by {@code @sha256:<64 hex>} digest.
 *
 * <p>A tag such as {@code eclipse-temurin:25-jre} is a moving pointer: the same line builds
 * different bytes on different days, and whoever controls the tag controls the base of the
 * gateway image that every be/fe/pki overlay inherits. A digest names exactly one image.
 *
 * <p>Exempt: {@code FROM scratch} and a {@code FROM} that names an earlier build stage
 * ({@code FROM build}). An image reference built from a build argument
 * ({@code FROM ${BASE}}) is NOT exempt, because its value is unknown here.
 *
 * <p>The guard fails, rather than passing vacuously, when it finds no Dockerfile or no
 * external {@code FROM} to check.
 */
class DockerfileBaseImageDigestGuardTest {

    private static final Pattern FROM = Pattern.compile(
            "^\\s*FROM\\s+(?:--\\S+\\s+)*(\\S+)(?:\\s+AS\\s+(\\S+))?\\s*$",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern DIGEST = Pattern.compile("@sha256:[0-9a-f]{64}$");

    /** Result of scanning one Dockerfile: external references seen, and the unpinned ones. */
    record Scan(List<String> external, List<String> unpinned) { }

    static Scan scan(List<String> lines) {
        Set<String> stages = new HashSet<>();
        List<String> external = new ArrayList<>();
        List<String> unpinned = new ArrayList<>();
        for (String line : lines) {
            Matcher m = FROM.matcher(line);
            if (!m.matches()) {
                continue;
            }
            String ref = m.group(1);
            String lower = ref.toLowerCase(Locale.ROOT);
            boolean exempt = lower.equals("scratch") || stages.contains(lower);
            if (m.group(2) != null) {
                stages.add(m.group(2).toLowerCase(Locale.ROOT));
            }
            if (exempt) {
                continue;
            }
            external.add(ref);
            if (!DIGEST.matcher(ref).find()) {
                unpinned.add(ref);
            }
        }
        return new Scan(external, unpinned);
    }

    private static final String SHA = "@sha256:" + "ab".repeat(32);

    @Test
    void scan_flagsATagOnlyFrom() {
        Scan s = scan(List.of("FROM eclipse-temurin:25-jre", "FROM eclipse-temurin:25-jdk AS build"));
        assertThat(s.unpinned()).containsExactly("eclipse-temurin:25-jre", "eclipse-temurin:25-jdk");
    }

    @Test
    void scan_acceptsADigestPinnedFromAndFlagsAShortOrMalformedOne() {
        assertThat(scan(List.of("FROM eclipse-temurin:25-jre" + SHA)).unpinned()).isEmpty();
        assertThat(scan(List.of("FROM x@sha256:abc")).unpinned()).containsExactly("x@sha256:abc");
        assertThat(scan(List.of("FROM x@sha256:" + "AB".repeat(32))).unpinned())
                .as("the digest is lowercase hex").hasSize(1);
        assertThat(scan(List.of("FROM x" + SHA + "extra")).unpinned()).hasSize(1);
    }

    @Test
    void scan_exemptsScratchAndAnEarlierStage_butNotABuildArgReference() {
        Scan s = scan(List.of(
                "FROM eclipse-temurin:25-jdk" + SHA + " AS build",
                "FROM scratch",
                "FROM build",
                "FROM build AS final",
                "FROM --platform=linux/amd64 ${BASE_IMAGE}"));
        assertThat(s.unpinned()).containsExactly("${BASE_IMAGE}");
    }

    @Test
    void scan_readsFlagsAndIgnoresCommentsAndOtherInstructions() {
        Scan s = scan(List.of(
                "# FROM eclipse-temurin:25-jre",
                "RUN echo FROM eclipse-temurin:25-jre",
                "from --platform=linux/arm64 alpine:3.20 as tools"));
        assertThat(s.external()).containsExactly("alpine:3.20");
        assertThat(s.unpinned()).containsExactly("alpine:3.20");
    }

    @Test
    void everyExternalFromInEveryDockerfileIsPinnedByDigest() throws IOException {
        String base = System.getProperty("basedir", System.getProperty("user.dir"));
        Path root = Path.of(base);
        // FAIL, never skip: a guard that cannot locate its subject must say so loudly.
        assertThat(root.resolve("src/main/java")).as("module root from %s", base).isDirectory();

        List<Path> dockerfiles;
        try (Stream<Path> tree = Files.walk(root)) {
            dockerfiles = tree.filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().startsWith("Dockerfile"))
                    .filter(p -> {
                        String rel = root.relativize(p).toString();
                        return !rel.startsWith("target") && !rel.startsWith(".git") && !rel.contains("node_modules");
                    })
                    .toList();
        }
        assertThat(dockerfiles).as("no Dockerfile found under %s", root).isNotEmpty();

        int externalFroms = 0;
        List<String> offenders = new ArrayList<>();
        for (Path df : dockerfiles) {
            Scan s = scan(Files.readAllLines(df));
            externalFroms += s.external().size();
            for (String ref : s.unpinned()) {
                offenders.add(root.relativize(df) + ": FROM " + ref);
            }
        }
        assertThat(externalFroms).as("no external FROM found to check").isGreaterThan(0);
        assertThat(offenders)
                .as("FROM lines that name an image without an @sha256:<64 hex> digest")
                .isEmpty();
    }
}
