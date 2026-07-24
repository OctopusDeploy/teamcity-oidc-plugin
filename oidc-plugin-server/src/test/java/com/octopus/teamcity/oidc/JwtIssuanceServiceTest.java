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
import java.time.Duration;
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

    private static final String CONNECTION_ID = "octopus-prod-connection";
    private static final String CONNECTION_PROJECT_ID = "OctopusProject";

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
        assertThat(service.tokensFor(runningBuild)).isEmpty();
    }

    @Test
    public void issuesOneTokenUnderDefaultVariableNameAndCachesPerBuildId() {
        enableFeature();
        when(runningBuild.getBuildId()).thenReturn(42L);

        final var first = service.tokensFor(runningBuild);
        final var second = service.tokensFor(runningBuild);

        assertThat(first).containsOnlyKeys("jwt.token");
        assertThat(second).isEqualTo(first); // cached: identical token value
    }

    @Test
    public void differentBuildsGetDifferentTokens() {
        enableFeature();
        when(runningBuild.getBuildId()).thenReturn(42L);
        final var firstBuildToken = service.tokensFor(runningBuild).get("jwt.token");

        when(runningBuild.getBuildId()).thenReturn(43L);
        final var secondBuildToken = service.tokensFor(runningBuild).get("jwt.token");

        assertThat(secondBuildToken).isNotEqualTo(firstBuildToken);
    }

    @Test
    public void evictDropsCachedTokenSoNextCallIssuesAFreshOne() {
        enableFeature();
        when(runningBuild.getBuildId()).thenReturn(42L);

        final var first = service.tokensFor(runningBuild).get("jwt.token");
        service.evict(42L);
        final var second = service.tokensFor(runningBuild).get("jwt.token");

        assertThat(second).isNotEqualTo(first);
    }

    @Test
    public void returnsEmptyWhenIssuerUrlIsNotHttps() {
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(featureDescriptor));
        lenient().when(featureDescriptor.getParameters()).thenReturn(Map.of());

        final var keyManager = TestJwtKeyManagerFactory.create(serverPaths);
        final var server = mock(SBuildServer.class);
        when(server.getRootUrl()).thenReturn("http://teamcity.example.com");
        final var insecureService = new JwtIssuanceService(
                new OidcIssuerUrlProvider(server, new OidcSettingsManager(tempDir)),
                keyManager,
                new OidcSettingsManager(tempDir),
                mock(OidcConnectionsManager.class));

        assertThat(insecureService.tokensFor(runningBuild)).isEmpty();
    }

    @Test
    public void usesConnectionSettingsWhenConnectionIdSet() throws Exception {
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(featureDescriptor));
        when(featureDescriptor.getParameters()).thenReturn(Map.of("connection_id", CONNECTION_ID));
        when(runningBuild.getBuildId()).thenReturn(42L);
        when(runningBuild.getTriggeredBy()).thenReturn(mock(TriggeredBy.class));
        final var project = mock(jetbrains.buildServer.serverSide.SProject.class);
        final var buildType = mock(jetbrains.buildServer.serverSide.SBuildType.class);
        when(runningBuild.getBuildType()).thenReturn(buildType);
        when(buildType.getProject()).thenReturn(project);
        when(connectionsManager.resolve(project, CONNECTION_ID)).thenReturn(java.util.Optional.of(
                new OidcConnection(CONNECTION_ID, CONNECTION_PROJECT_ID, "Test",
                        new IssuanceSettings("api://from-connection", 15, "ES256", java.util.Set.of()), "conn.token")));

        final var tokens = service.tokensFor(runningBuild);

        assertThat(tokens).containsOnlyKeys("conn.token");
        final var parsed = com.nimbusds.jwt.SignedJWT.parse(tokens.get("conn.token")).getJWTClaimsSet();
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

        assertThatThrownBy(() -> service.tokensFor(runningBuild))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("connection 'missing' could not be found");
    }

    @Test
    public void usesInlineSettingsWhenNoConnectionIdSet() throws Exception {
        enableFeature();
        when(featureDescriptor.getParameters()).thenReturn(Map.of("audience", "api://inline"));
        when(runningBuild.getBuildId()).thenReturn(44L);

        final var tokens = service.tokensFor(runningBuild);

        assertThat(tokens).containsOnlyKeys("jwt.token");
        final var parsed = com.nimbusds.jwt.SignedJWT.parse(tokens.get("jwt.token")).getJWTClaimsSet();
        assertThat(parsed.getAudience()).containsExactly("api://inline");
    }

    @Test
    public void issuesOneTokenPerFeatureUnderDistinctVariableNames() throws Exception {
        final var f1 = mock(SBuildFeatureDescriptor.class);
        final var f2 = mock(SBuildFeatureDescriptor.class);
        when(f1.getParameters()).thenReturn(Map.of("audience", "api://one"));
        when(f2.getParameters()).thenReturn(Map.of("audience", "api://two", "token_variable_name", "second.token"));
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(f1, f2));
        when(runningBuild.getBuildId()).thenReturn(50L);
        when(runningBuild.getTriggeredBy()).thenReturn(mock(TriggeredBy.class));

        final var tokens = service.tokensFor(runningBuild);

        assertThat(tokens).containsOnlyKeys("jwt.token", "second.token");
        assertThat(com.nimbusds.jwt.SignedJWT.parse(tokens.get("jwt.token")).getJWTClaimsSet().getAudience())
                .containsExactly("api://one");
        assertThat(com.nimbusds.jwt.SignedJWT.parse(tokens.get("second.token")).getJWTClaimsSet().getAudience())
                .containsExactly("api://two");
    }

    @Test
    public void duplicateVariableNamesKeepFirstTokenAndSkipRest() throws Exception {
        final var f1 = mock(SBuildFeatureDescriptor.class);
        final var f2 = mock(SBuildFeatureDescriptor.class);
        when(f1.getParameters()).thenReturn(Map.of("audience", "api://first"));
        when(f2.getParameters()).thenReturn(Map.of("audience", "api://second")); // both resolve to jwt.token
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(f1, f2));
        when(runningBuild.getBuildId()).thenReturn(51L);
        when(runningBuild.getTriggeredBy()).thenReturn(mock(TriggeredBy.class));

        final var tokens = service.tokensFor(runningBuild);

        assertThat(tokens).containsOnlyKeys("jwt.token");
        assertThat(com.nimbusds.jwt.SignedJWT.parse(tokens.get("jwt.token")).getJWTClaimsSet().getAudience())
                .containsExactly("api://first");
    }

    @Test
    public void variableNamesForReturnsEffectiveNamesWithoutIssuing() {
        final var f1 = mock(SBuildFeatureDescriptor.class);
        final var f2 = mock(SBuildFeatureDescriptor.class);
        when(f1.getParameters()).thenReturn(Map.of());
        when(f2.getParameters()).thenReturn(Map.of("token_variable_name", "second.token"));
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(f1, f2));

        assertThat(service.variableNamesFor(runningBuild)).containsExactly("jwt.token", "second.token");
    }

    @Test
    public void featureTtlOverridesConnectionTtl() throws Exception {
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(featureDescriptor));
        when(featureDescriptor.getParameters()).thenReturn(Map.of("connection_id", CONNECTION_ID, "ttl_minutes", "5"));
        when(runningBuild.getBuildId()).thenReturn(60L);
        when(runningBuild.getTriggeredBy()).thenReturn(mock(TriggeredBy.class));
        final var project = mock(jetbrains.buildServer.serverSide.SProject.class);
        final var buildType = mock(jetbrains.buildServer.serverSide.SBuildType.class);
        when(runningBuild.getBuildType()).thenReturn(buildType);
        when(buildType.getProject()).thenReturn(project);
        when(connectionsManager.resolve(project, CONNECTION_ID)).thenReturn(java.util.Optional.of(
                new OidcConnection(CONNECTION_ID, CONNECTION_PROJECT_ID, "Test",
                        new IssuanceSettings("api://from-connection", 15, "ES256", java.util.Set.of()), "conn.token")));

        final var parsed = com.nimbusds.jwt.SignedJWT.parse(
                service.tokensFor(runningBuild).get("conn.token")).getJWTClaimsSet();

        // TTL comes from the feature (5), audience still from the connection.
        assertThat(Duration.between(parsed.getIssueTime().toInstant(), parsed.getExpirationTime().toInstant()).toMinutes())
                .isEqualTo(5);
        assertThat(parsed.getAudience()).containsExactly("api://from-connection");
    }

    @Test
    public void blankFeatureTtlInheritsConnectionTtl() throws Exception {
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(featureDescriptor));
        when(featureDescriptor.getParameters()).thenReturn(Map.of("connection_id", CONNECTION_ID, "ttl_minutes", "  "));
        when(runningBuild.getBuildId()).thenReturn(61L);
        when(runningBuild.getTriggeredBy()).thenReturn(mock(TriggeredBy.class));
        final var project = mock(jetbrains.buildServer.serverSide.SProject.class);
        final var buildType = mock(jetbrains.buildServer.serverSide.SBuildType.class);
        when(runningBuild.getBuildType()).thenReturn(buildType);
        when(buildType.getProject()).thenReturn(project);
        when(connectionsManager.resolve(project, CONNECTION_ID)).thenReturn(java.util.Optional.of(
                new OidcConnection(CONNECTION_ID, CONNECTION_PROJECT_ID, "Test",
                        new IssuanceSettings("api://from-connection", 15, "RS256", java.util.Set.of()), "conn.token")));

        final var parsed = com.nimbusds.jwt.SignedJWT.parse(
                service.tokensFor(runningBuild).get("conn.token")).getJWTClaimsSet();

        assertThat(Duration.between(parsed.getIssueTime().toInstant(), parsed.getExpirationTime().toInstant()).toMinutes())
                .isEqualTo(15);
    }

    @Test
    public void audienceAndAlgorithmAlwaysComeFromConnectionEvenIfFeatureSetsThem() throws Exception {
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(featureDescriptor));
        when(featureDescriptor.getParameters()).thenReturn(Map.of(
                "connection_id", CONNECTION_ID, "audience", "api://from-feature", "algorithm", "RS256"));
        when(runningBuild.getBuildId()).thenReturn(62L);
        when(runningBuild.getTriggeredBy()).thenReturn(mock(TriggeredBy.class));
        final var project = mock(jetbrains.buildServer.serverSide.SProject.class);
        final var buildType = mock(jetbrains.buildServer.serverSide.SBuildType.class);
        when(runningBuild.getBuildType()).thenReturn(buildType);
        when(buildType.getProject()).thenReturn(project);
        when(connectionsManager.resolve(project, CONNECTION_ID)).thenReturn(java.util.Optional.of(
                new OidcConnection(CONNECTION_ID, CONNECTION_PROJECT_ID, "Test",
                        new IssuanceSettings("api://from-connection", 15, "ES256", java.util.Set.of()), "conn.token")));

        final var signed = com.nimbusds.jwt.SignedJWT.parse(service.tokensFor(runningBuild).get("conn.token"));

        // audience ignores the feature's value; algorithm header is the connection's ES256.
        assertThat(signed.getJWTClaimsSet().getAudience()).containsExactly("api://from-connection");
        assertThat(signed.getHeader().getAlgorithm().getName()).isEqualTo("ES256");
    }

    @Test
    public void malformedFeatureTtlInheritsConnectionTtl() throws Exception {
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(featureDescriptor));
        when(featureDescriptor.getParameters()).thenReturn(Map.of("connection_id", CONNECTION_ID, "ttl_minutes", "abc"));
        when(runningBuild.getBuildId()).thenReturn(63L);
        when(runningBuild.getTriggeredBy()).thenReturn(mock(TriggeredBy.class));
        final var project = mock(jetbrains.buildServer.serverSide.SProject.class);
        final var buildType = mock(jetbrains.buildServer.serverSide.SBuildType.class);
        when(runningBuild.getBuildType()).thenReturn(buildType);
        when(buildType.getProject()).thenReturn(project);
        when(connectionsManager.resolve(project, CONNECTION_ID)).thenReturn(java.util.Optional.of(
                new OidcConnection(CONNECTION_ID, CONNECTION_PROJECT_ID, "Test",
                        new IssuanceSettings("api://from-connection", 15, "RS256", java.util.Set.of()), "conn.token")));

        final var parsed = com.nimbusds.jwt.SignedJWT.parse(
                service.tokensFor(runningBuild).get("conn.token")).getJWTClaimsSet();

        assertThat(Duration.between(parsed.getIssueTime().toInstant(), parsed.getExpirationTime().toInstant()).toMinutes())
                .isEqualTo(15);
    }

    @Test
    public void outOfRangeFeatureTtlIsClampedToServerMax() throws Exception {
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(featureDescriptor));
        when(featureDescriptor.getParameters()).thenReturn(Map.of("connection_id", CONNECTION_ID, "ttl_minutes", "9999"));
        when(runningBuild.getBuildId()).thenReturn(64L);
        when(runningBuild.getTriggeredBy()).thenReturn(mock(TriggeredBy.class));
        final var project = mock(jetbrains.buildServer.serverSide.SProject.class);
        final var buildType = mock(jetbrains.buildServer.serverSide.SBuildType.class);
        when(runningBuild.getBuildType()).thenReturn(buildType);
        when(buildType.getProject()).thenReturn(project);
        when(connectionsManager.resolve(project, CONNECTION_ID)).thenReturn(java.util.Optional.of(
                new OidcConnection(CONNECTION_ID, CONNECTION_PROJECT_ID, "Test",
                        new IssuanceSettings("api://from-connection", 15, "RS256", java.util.Set.of()), "conn.token")));

        final var parsed = com.nimbusds.jwt.SignedJWT.parse(
                service.tokensFor(runningBuild).get("conn.token")).getJWTClaimsSet();

        assertThat(Duration.between(parsed.getIssueTime().toInstant(), parsed.getExpirationTime().toInstant()).toMinutes())
                .isEqualTo(OidcSettings.DEFAULT_MAX_TOKEN_LIFETIME_MINUTES);
    }
}
