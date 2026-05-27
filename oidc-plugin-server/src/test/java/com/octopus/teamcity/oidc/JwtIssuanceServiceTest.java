package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.SBuildFeatureDescriptor;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.serverSide.SRunningBuild;
import jetbrains.buildServer.serverSide.ServerPaths;
import jetbrains.buildServer.serverSide.TriggeredBy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class JwtIssuanceServiceTest {

    @Mock ServerPaths serverPaths;
    @Mock SRunningBuild runningBuild;
    @Mock SBuildFeatureDescriptor featureDescriptor;
    @Mock OidcConnectionsManager connectionsManager;

    @TempDir File tempDir;

    private JwtIssuanceService service;

    @BeforeEach
    void setUp() {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        final var keyManager = TestJwtKeyManagerFactory.create(serverPaths);
        final var server = mock(SBuildServer.class);
        lenient().when(server.getRootUrl()).thenReturn("https://teamcity.example.com");
        service = new JwtIssuanceService(
                new OidcIssuerUrlProvider(server, new OidcSettingsManager(tempDir)),
                keyManager,
                new OidcSettingsManager(tempDir),
                connectionsManager);
    }

    /** Wires the JWT build feature into the build with default params. */
    private void enableFeature() {
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(featureDescriptor));
        when(featureDescriptor.getParameters()).thenReturn(Map.of());
        when(runningBuild.getTriggeredBy()).thenReturn(mock(TriggeredBy.class));
    }

    @Test
    public void returnsEmptyWhenBuildHasNoJwtFeature() {
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(Collections.emptyList());

        assertThat(service.issueOrGet(runningBuild)).isEmpty();
    }

    @Test
    public void issuesAndCachesPerBuildId() {
        enableFeature();
        when(runningBuild.getBuildId()).thenReturn(42L);

        final var first = service.issueOrGet(runningBuild);
        final var second = service.issueOrGet(runningBuild);

        assertThat(first).isPresent();
        assertThat(second).isPresent();
        assertThat(second).isEqualTo(first);
    }

    @Test
    public void differentBuildsGetDifferentTokens() {
        enableFeature();
        when(runningBuild.getBuildId()).thenReturn(42L);
        final var firstBuildToken = service.issueOrGet(runningBuild).orElseThrow();

        // Re-stub to make the same mock represent a different build id.
        // computeIfAbsent treats this as a new key, so a fresh token is issued.
        when(runningBuild.getBuildId()).thenReturn(43L);
        final var secondBuildToken = service.issueOrGet(runningBuild).orElseThrow();

        assertThat(secondBuildToken).isNotEqualTo(firstBuildToken);
    }

    @Test
    public void evictDropsCachedTokenSoNextCallIssuesAFreshOne() {
        enableFeature();
        when(runningBuild.getBuildId()).thenReturn(42L);

        final var first = service.issueOrGet(runningBuild).orElseThrow();
        service.evict(42L);
        final var second = service.issueOrGet(runningBuild).orElseThrow();

        assertThat(second).isNotEqualTo(first);
    }

    @Test
    public void returnsEmptyWhenIssuerUrlIsNotHttps() {
        // The non-HTTPS short-circuit returns before the trigger metadata is read,
        // so we only stub the feature presence here.
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(featureDescriptor));
        when(featureDescriptor.getParameters()).thenReturn(Map.of());

        final var keyManager = TestJwtKeyManagerFactory.create(serverPaths);
        final var server = mock(SBuildServer.class);
        when(server.getRootUrl()).thenReturn("http://teamcity.example.com");
        final var insecureService = new JwtIssuanceService(
                new OidcIssuerUrlProvider(server, new OidcSettingsManager(tempDir)),
                keyManager,
                new OidcSettingsManager(tempDir),
                mock(OidcConnectionsManager.class));

        assertThat(insecureService.issueOrGet(runningBuild)).isEmpty();
    }

    @Test
    public void usesConnectionSettingsWhenConnectionIdSet() throws Exception {
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(featureDescriptor));
        when(featureDescriptor.getParameters()).thenReturn(Map.of("connection_id", "c1"));
        when(runningBuild.getBuildId()).thenReturn(42L);
        when(runningBuild.getTriggeredBy()).thenReturn(mock(TriggeredBy.class));
        final var project = mock(jetbrains.buildServer.serverSide.SProject.class);
        final var buildType = mock(jetbrains.buildServer.serverSide.SBuildType.class);
        when(runningBuild.getBuildType()).thenReturn(buildType);
        when(buildType.getProject()).thenReturn(project);
        when(connectionsManager.resolve(project, "c1")).thenReturn(java.util.Optional.of(
                new OidcConnection("c1", "p1", "Test",
                        new IssuanceSettings("api://from-connection", 15, "ES256", java.util.Set.of()))));

        final var token = service.issueOrGet(runningBuild).orElseThrow();
        final var parsed = com.nimbusds.jwt.SignedJWT.parse(token).getJWTClaimsSet();

        assertThat(parsed.getAudience()).containsExactly("api://from-connection");
    }

    @Test
    public void throwsWhenConnectionIdReferencesMissingConnection() {
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(featureDescriptor));
        when(featureDescriptor.getParameters()).thenReturn(Map.of("connection_id", "missing"));
        when(runningBuild.getBuildId()).thenReturn(43L);
        final var project = mock(jetbrains.buildServer.serverSide.SProject.class);
        final var buildType = mock(jetbrains.buildServer.serverSide.SBuildType.class);
        when(runningBuild.getBuildType()).thenReturn(buildType);
        when(buildType.getProject()).thenReturn(project);
        when(connectionsManager.resolve(project, "missing")).thenReturn(java.util.Optional.empty());

        assertThatThrownBy(() -> service.issueOrGet(runningBuild))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("connection 'missing' could not be found");
    }

    @Test
    public void usesInlineSettingsWhenNoConnectionIdSet() throws Exception {
        enableFeature();
        when(featureDescriptor.getParameters()).thenReturn(Map.of("audience", "api://inline"));
        when(runningBuild.getBuildId()).thenReturn(44L);

        final var token = service.issueOrGet(runningBuild).orElseThrow();
        final var parsed = com.nimbusds.jwt.SignedJWT.parse(token).getJWTClaimsSet();

        assertThat(parsed.getAudience()).containsExactly("api://inline");
    }
}
