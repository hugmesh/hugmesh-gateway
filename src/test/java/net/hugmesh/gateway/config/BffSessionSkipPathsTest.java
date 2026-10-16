package net.hugmesh.gateway.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.io.ClassPathResource;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The bff_ introspection skip list ({@code app.bff-session.skip-paths}) has two
 * spellings: the Java default in {@link BffSessionProperties} and the shipped
 * {@code application.yml}. They must agree, and neither may name
 * {@code /_remotes/banned/**}: that prefix is added at runtime only by
 * {@link BannedRemotePermit} (one switch for this list and the coarse permit), so an
 * operator who overrides {@code skip-paths} cannot silently drop or keep it.
 */
class BffSessionSkipPathsTest {

    private static final String BANNED = "/_remotes/banned/**";

    @Test
    void javaDefaultNamesNoBannedRemote() {
        assertThat(new BffSessionProperties().getSkipPaths())
                .doesNotContain(BANNED)
                .noneMatch(p -> p.contains("banned"));
    }

    @Test
    void applicationYmlSkipListMatchesTheJavaDefault() {
        YamlPropertiesFactoryBean yaml = new YamlPropertiesFactoryBean();
        yaml.setResources(new ClassPathResource("application.yml"));
        Properties props = yaml.getObject();
        assertThat(props).isNotNull();

        List<String> fromYml = new ArrayList<>();
        for (int i = 0; ; i++) {
            String v = props.getProperty("app.bff-session.skip-paths[" + i + "]");
            if (v == null) break;
            fromYml.add(v);
        }
        assertThat(fromYml).isNotEmpty().doesNotContain(BANNED);
        assertThat(fromYml).containsExactlyElementsOf(new BffSessionProperties().getSkipPaths());
    }

    @Test
    void theSwitchIsShippedOffInApplicationYml() {
        YamlPropertiesFactoryBean yaml = new YamlPropertiesFactoryBean();
        yaml.setResources(new ClassPathResource("application.yml"));
        Properties props = yaml.getObject();
        assertThat(props).isNotNull();
        assertThat(props.getProperty(BannedRemotePermit.PROPERTY))
                .isEqualTo("${APP_SECURITY_BANNED_REMOTE_PUBLIC:false}");
    }

    @Test
    void bannedRemotePermit_parsingAndListsAreFailClosed() {
        for (String raw : java.util.Arrays.asList(null, "", " ", "false", "yes", "1", "on", "tru")) {
            assertThat(BannedRemotePermit.enabled(raw)).as("raw=%s", raw).isFalse();
        }
        for (String raw : List.of("true", "TRUE", " True ")) {
            assertThat(BannedRemotePermit.enabled(raw)).as("raw=%s", raw).isTrue();
        }
        List<String> base = new BffSessionProperties().getSkipPaths();
        assertThat(BannedRemotePermit.skipPaths(base, false)).containsExactlyElementsOf(base);
        assertThat(BannedRemotePermit.skipPaths(base, true)).containsAll(base).contains(BANNED)
                .hasSize(base.size() + 1);
        assertThat(BannedRemotePermit.skipPaths(BannedRemotePermit.skipPaths(base, true), true))
                .hasSize(base.size() + 1);
    }
}
