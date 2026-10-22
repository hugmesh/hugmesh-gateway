package net.hugmesh.gateway;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the signed publish job of {@code .github/workflows/release.yml}.
 *
 * <ul>
 *   <li>The job that builds and pushes the image ({@code image}) runs on the GitHub-hosted
 *       {@code ubuntu-latest}, written literally: a published image is never built on the
 *       self-hosted runner, whatever {@code vars.RUNS_ON_PUBLISH} says.</li>
 *   <li>It holds exactly {@code contents: read}, {@code packages: write}, {@code id-token: write}
 *       and {@code attestations: write}; no other job, and not the workflow, holds
 *       {@code id-token} or {@code attestations}.</li>
 *   <li>After the build it resolves the pushed repository and DIGEST (refusing a non-sha256
 *       digest and a pushed {@code latest} tag), signs that digest with cosign keyless, and pushes
 *       a build-provenance and an SBOM attestation for it to the registry.</li>
 *   <li>{@code notify-site} runs hosted, with no permissions, only for {@code v*} tags, after the
 *       GitHub Release.</li>
 * </ul>
 *
 * <p>Whole-line comments are dropped first, so prose cannot satisfy or defeat a check.
 */
class ReleaseSignedImageGuardTest {

    private static final String IMAGE_JOB = "image";

    private static String workflowCode() throws IOException {
        String base = System.getProperty("basedir", System.getProperty("user.dir"));
        Path wf = Path.of(base).resolve(".github/workflows/release.yml");
        assertThat(wf).as("the release workflow must exist").isRegularFile();
        StringBuilder out = new StringBuilder();
        for (String line : Files.readString(wf, StandardCharsets.UTF_8).split("\n", -1)) {
            if (!line.stripLeading().startsWith("#")) {
                out.append(line).append('\n');
            }
        }
        return out.toString();
    }

    /** Top-level jobs of the workflow, name to body, in file order. */
    private static Map<String, String> jobs(String code) {
        Map<String, String> jobs = new LinkedHashMap<>();
        String current = null;
        boolean inJobs = false;
        StringBuilder body = new StringBuilder();
        for (String line : code.split("\n", -1)) {
            if (line.equals("jobs:")) {
                inJobs = true;
                continue;
            }
            if (!inJobs) {
                continue;
            }
            Matcher m = Pattern.compile("^  ([A-Za-z0-9_-]+):\\s*$").matcher(line);
            if (m.matches()) {
                if (current != null) {
                    jobs.put(current, body.toString());
                }
                current = m.group(1);
                body = new StringBuilder();
            } else if (!line.isEmpty() && !line.startsWith(" ")) {
                break;
            } else if (current != null) {
                body.append(line).append('\n');
            }
        }
        if (current != null) {
            jobs.put(current, body.toString());
        }
        return jobs;
    }

    private static int count(String haystack, String needle) {
        int n = 0;
        for (int i = haystack.indexOf(needle); i >= 0; i = haystack.indexOf(needle, i + needle.length())) {
            n++;
        }
        return n;
    }

    @Test
    @DisplayName("the image job runs on literal hosted ubuntu-latest with exactly the signing permissions")
    void imageJobIsHostedWithSigningPermissions() throws IOException {
        String code = workflowCode();
        Map<String, String> jobs = jobs(code);
        String image = jobs.get(IMAGE_JOB);
        assertThat(image).as("job %s", IMAGE_JOB).isNotNull();
        assertThat(image.lines().filter(l -> l.startsWith("    runs-on:")).toList())
                .as("runs-on of the signed publish job").containsExactly("    runs-on: ubuntu-latest");
        assertThat(image).as("permissions of the signed publish job").contains(
                "    permissions:\n      contents: read\n      packages: write\n"
                        + "      id-token: write\n      attestations: write\n    ");
        jobs.forEach((name, body) -> {
            if (!name.equals(IMAGE_JOB)) {
                assertThat(body).as("job %s must not hold id-token or attestations", name)
                        .doesNotContainPattern("(?m)^\\s+(id-token|attestations):");
            }
        });
        String top = code.substring(0, code.indexOf("\njobs:\n"));
        assertThat(top).as("workflow-level permissions")
                .doesNotContainPattern("(?m)^\\s+(id-token|attestations):");
    }

    @Test
    @DisplayName("the image job signs its pushed digest with cosign keyless and pushes provenance and SBOM attestations")
    void imageJobSignsAndAttestsThePushedDigest() throws IOException {
        String image = jobs(workflowCode()).get(IMAGE_JOB);
        assertThat(image).as("job %s", IMAGE_JOB).isNotNull();
        int build = image.indexOf("id: build\n");
        int signref = image.indexOf("id: signref\n");
        assertThat(build).as("the build step has id build").isNotNegative();
        assertThat(signref).as("the digest is resolved after the build").isGreaterThan(build);
        assertThat(image.indexOf("docker/build-push-action@")).as("build-push-action precedes signing")
                .isNotNegative().isLessThan(signref);
        String after = image.substring(signref);
        assertThat(after).as("the digest comes from the build step")
                .contains("if: steps.build.outcome == 'success'")
                .contains("DIGEST: ${{ steps.build.outputs.digest }}");
        assertThat(after).as("a non-sha256 digest is refused").contains("sha256:[0-9a-f]{64}");
        assertThat(after).as("a pushed latest tag is refused").contains("\"latest\" in tags");
        assertThat(after).as("cosign keyless signs the pushed digest")
                .contains("REF: ${{ steps.signref.outputs.repo }}@${{ steps.signref.outputs.digest }}")
                .contains("run: cosign sign --yes \"$REF\"");
        assertThat(after).as("provenance and SBOM attestations, pushed to the registry")
                .contains("uses: actions/attest-build-provenance@")
                .contains("uses: actions/attest-sbom@")
                .doesNotContain("push-to-registry: false");
        assertThat(count(after, "subject-digest: ${{ steps.signref.outputs.digest }}"))
                .as("both attestations name the pushed digest").isEqualTo(2);
        assertThat(count(after, "push-to-registry: true"))
                .as("both attestations are pushed to the registry").isEqualTo(2);
    }

    @Test
    @DisplayName("notify-site runs hosted, with no permissions, only for v* tags after the GitHub Release")
    void notifySiteIsHostedWithoutPermissions() throws IOException {
        String note = jobs(workflowCode()).get("notify-site");
        assertThat(note).as("job notify-site").isNotNull();
        assertThat(note.lines().filter(l -> l.startsWith("    runs-on:")).toList())
                .containsExactly("    runs-on: ubuntu-latest");
        assertThat(note)
                .contains("    permissions: {}\n")
                .doesNotContainPattern("(?m)^    permissions:\\s*$")
                .contains("    if: startsWith(github.ref, 'refs/tags/v')\n")
                .contains("    needs: [github-release]\n");
    }
}
