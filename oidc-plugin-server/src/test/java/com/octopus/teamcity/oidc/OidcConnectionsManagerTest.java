package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.serverSide.SProject;
import jetbrains.buildServer.serverSide.oauth.OAuthConnectionDescriptor;
import jetbrains.buildServer.serverSide.oauth.OAuthConnectionsManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class OidcConnectionsManagerTest {

    static final String TYPE = OidcConnectionProvider.TYPE;

    @Mock OAuthConnectionsManager teamcityOAuth;
    @Mock SProject project;
    @Mock SBuildServer buildServer;

    @TempDir File tempDir;

    private OidcConnectionsManager manager;

    @BeforeEach
    void setUp() {
        lenient().when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");
        final var issuerUrlProvider = new OidcIssuerUrlProvider(buildServer, new OidcSettingsManager(tempDir));
        final var settingsManager = new OidcSettingsManager(tempDir);
        manager = new OidcConnectionsManager(teamcityOAuth, issuerUrlProvider, settingsManager);
    }

    private OAuthConnectionDescriptor connection(final String id, final String projectId, final String name,
                                                 final Map<String, String> params) {
        final var c = mock(OAuthConnectionDescriptor.class);
        lenient().when(c.getId()).thenReturn(id);
        lenient().when(c.getProjectId()).thenReturn(projectId);
        lenient().when(c.getConnectionDisplayName()).thenReturn(name);
        lenient().when(c.getParameters()).thenReturn(params);
        return c;
    }

    @Test
    public void listAvailableReturnsAllOidcConnectionsForProject() {
        // Create descriptors before the when() call — creating mocks inside thenReturn()
        // arguments confuses Mockito's stubbing state machine.
        final var first = connection("c1", "P1", "First", Map.of("audience", "api://one"));
        final var second = connection("c2", "P1", "Second", Map.of("audience", "api://two"));
        when(teamcityOAuth.getAvailableConnectionsOfType(project, TYPE)).thenReturn(List.of(first, second));

        final var result = manager.listAvailable(project);

        assertThat(result).hasSize(2);
        assertThat(result.get(0).displayName()).isEqualTo("First");
        assertThat(result.get(0).settings().audience()).isEqualTo("api://one");
        assertThat(result.get(1).displayName()).isEqualTo("Second");
    }

    @Test
    public void resolveReturnsConnectionWhenFound() {
        final var descriptor = connection("c1", "P1", "First", Map.of("audience", "api://one"));
        when(teamcityOAuth.findConnectionById(project, "c1")).thenReturn(descriptor);

        final var result = manager.resolve(project, "c1");

        assertThat(result).isPresent();
        assertThat(result.get().id()).isEqualTo("c1");
        assertThat(result.get().settings().audience()).isEqualTo("api://one");
    }

    @Test
    public void resolveReturnsEmptyWhenIdUnknown() {
        when(teamcityOAuth.findConnectionById(project, "missing")).thenReturn(null);

        assertThat(manager.resolve(project, "missing")).isEmpty();
    }

    @Test
    public void resolveReturnsEmptyWhenConnectionIdIsNullOrBlank() {
        assertThat(manager.resolve(project, null)).isEmpty();
        assertThat(manager.resolve(project, "")).isEmpty();
        assertThat(manager.resolve(project, "   ")).isEmpty();
    }
}
