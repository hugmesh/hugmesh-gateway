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
 * {@code /_remotes/banned/**} — nothing is served there, so a skip entry is dead
 * surface (and the matching coarse permit in {@code SecurityConfig.PUBLIC_PATHS}
 * is pinned absent by {@code SecurityConfigPathGateSliceTest}).
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
}
