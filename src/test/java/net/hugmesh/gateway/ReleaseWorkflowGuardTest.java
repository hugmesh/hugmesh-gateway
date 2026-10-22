package net.hugmesh.gateway;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import javax.xml.parsers.DocumentBuilderFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * RELEASE GUARD (Tier-1 meta-test) &mdash; pins the publish rules of
 * {@code .github/workflows/release.yml} and the version it publishes.
 *
 * <ul>
 *   <li>The workflow has no {@code pull_request} / {@code pull_request_target} trigger. Its
 *       jobs may run on the self-hosted runner, and a pull request (above all one from a
 *       fork of a public repository) must never reach that runner through this file.</li>
 *   <li>Every job takes its runner from the guarded publish expression: the self-hosted
 *       labels in {@code vars.RUNS_ON_PUBLISH} only for {@code main} and {@code v*} tags,
 *       hosted {@code ubuntu-latest} otherwise. The older {@code vars.RUNS_ON} variable,
 *       which pull-request jobs elsewhere also read, is never read here.</li>
 *   <li>The pom's own {@code <project><version>} is a published-style SemVer: never a
 *       SNAPSHOT and never {@code +build} metadata (OCI tags reject {@code +}). The
 *       workflow refuses a {@code v*} tag that does not equal it, so this is what an image
 *       tag will say.</li>
 *   <li>The {@code net.hugmesh:hugmesh-commons} dependency is pinned to a literal,
 *       published-style version (no SNAPSHOT, no property, no range): the image is built
 *       from GitHub Packages, where only published coordinates exist.</li>
 * </ul>
 *
 * <p>Each assertion fails rather than skips when its subject is missing.
 */
class ReleaseWorkflowGuardTest {

    private static final String PUBLISH_RUNS_ON = "${{ fromJSON(github.event_name != 'pull_request'"
            + " && github.event_name != 'pull_request_target'"
            + " && (github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v')"
            + " || startsWith(github.ref, 'refs/tags/studio-v'))"
            + " && vars.RUNS_ON_PUBLISH || '\"ubuntu-latest\"') }}";

    private static final Pattern SEMVER_NO_BUILD = Pattern.compile(
            "^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(-[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?$");

    /** {@code vars.RUNS_ON} as a whole name, not the {@code RUNS_ON_PUBLISH} prefix. */
    private static final Pattern READS_RUNS_ON = Pattern.compile("vars\\.RUNS_ON(?![A-Za-z0-9_])");

    private static Path moduleRoot() {
        String base = System.getProperty("basedir", System.getProperty("user.dir"));
        Path root = Path.of(base);
        assertThat(root.resolve("pom.xml"))
                .as("cannot locate pom.xml from basedir/user.dir=%s", base)
                .isRegularFile();
        return root;
    }

    private static Path releaseWorkflow() {
        Path wf = moduleRoot().resolve(".github/workflows/release.yml");
        assertThat(wf).as("the release workflow must exist").isRegularFile();
        return wf;
    }

    @SuppressWarnings("unchecked")
    private static Map<Object, Object> workflow() throws Exception {
        Object doc = new Yaml(new SafeConstructor(new LoaderOptions()))
                .load(Files.readString(releaseWorkflow()));
        assertThat(doc).as("release.yml must parse to a mapping").isInstanceOf(Map.class);
        return (Map<Object, Object>) doc;
    }

    @Test
    void releaseWorkflow_hasNoPullRequestTrigger() throws Exception {
        Map<Object, Object> wf = workflow();
        // YAML 1.1 (snakeyaml) reads a bare `on:` key as Boolean.TRUE.
        Object on = wf.containsKey("on") ? wf.get("on") : wf.get(Boolean.TRUE);
        assertThat(on).as("release.yml must declare its triggers").isInstanceOf(Map.class);
        assertThat(((Map<?, ?>) on).keySet().stream().map(String::valueOf).toList())
                .as("a publish workflow must never run for a pull request")
                .doesNotContain("pull_request", "pull_request_target")
                .contains("push", "workflow_dispatch");
    }

    @Test
    void everyReleaseJob_usesTheGuardedPublishRunner_andNeverReadsRunsOn() throws Exception {
        Map<?, ?> jobs = (Map<?, ?>) workflow().get("jobs");
        assertThat(jobs).as("release.yml must have jobs").isNotEmpty();
        jobs.forEach((name, job) -> assertThat(((Map<?, ?>) job).get("runs-on"))
                .as("job '%s' must take its runner from the guarded publish expression", name)
                .isEqualTo(PUBLISH_RUNS_ON));
        assertThat(READS_RUNS_ON.matcher(Files.readString(releaseWorkflow())).find())
                .as("release.yml must not read vars.RUNS_ON (pull-request jobs elsewhere use it)")
                .isFalse();
    }

    private static Element pomProject() throws Exception {
        var factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return factory.newDocumentBuilder()
                .parse(moduleRoot().resolve("pom.xml").toFile()).getDocumentElement();
    }

    private static String childText(Element parent, String tag) {
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element e && tag.equals(e.getTagName())) {
                return e.getTextContent().trim();
            }
        }
        return null;
    }

    @Test
    void commonsDependency_isPinnedToALiteralPublishedVersion() throws Exception {
        Element project = pomProject();
        String pinned = null;
        int found = 0;
        for (Node n = project.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (!(n instanceof Element deps) || !"dependencies".equals(deps.getTagName())) {
                continue;
            }
            for (Node d = deps.getFirstChild(); d != null; d = d.getNextSibling()) {
                if (d instanceof Element dep
                        && "net.hugmesh".equals(childText(dep, "groupId"))
                        && "hugmesh-commons".equals(childText(dep, "artifactId"))) {
                    found++;
                    pinned = childText(dep, "version");
                }
            }
        }
        assertThat(found).as("pom.xml must declare net.hugmesh:hugmesh-commons exactly once").isEqualTo(1);
        assertThat(pinned).as("the hugmesh-commons dependency must carry its own <version>").isNotBlank();
        assertThat(pinned).as("hugmesh-commons must never be a SNAPSHOT pin").doesNotContain("SNAPSHOT");
        assertThat(pinned)
                .as("hugmesh-commons must be pinned to a literal MAJOR.MINOR.PATCH[-pre], not a property or range")
                .matches(SEMVER_NO_BUILD);
    }

    @Test
    void pomVersion_isPublishableSemver_notSnapshot() throws Exception {
        Element project = pomProject();
        String version = null;
        // Direct child only: <parent><version> is spring-boot-starter-parent's, not ours.
        for (Node n = project.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element e && "version".equals(e.getTagName())) {
                version = e.getTextContent().trim();
            }
        }
        assertThat(version).as("pom.xml must declare <project><version>").isNotBlank();
        assertThat(version).as("published versions are never SNAPSHOTs").doesNotContain("SNAPSHOT");
        assertThat(version)
                .as("pom.xml version must be MAJOR.MINOR.PATCH[-pre] with no +build part")
                .matches(SEMVER_NO_BUILD);
    }
}
