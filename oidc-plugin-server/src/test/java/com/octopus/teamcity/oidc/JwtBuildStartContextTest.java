package com.octopus.teamcity.oidc;

import com.nimbusds.jwt.SignedJWT;
import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.*;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.users.SUser;
import org.assertj.core.api.AssertionsForClassTypes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class JwtBuildStartContextTest {

    @Mock
    ExtensionHolder extensionHolder;

    @Mock
    SBuildServer buildServer;

    @Mock
    SRunningBuild runningBuild;

    @Mock
    BuildStartContext buildStartContext;

    @Mock
    SBuildFeatureDescriptor jwtBuildFeatureBuildFeatureDescriptor;

    @Mock
    private ServerPaths serverPaths;

    @Mock
    private PluginDescriptor pluginDescriptor;

    @TempDir
    private File tempDir;

    @Test
    public void doesNotCrashWhenGetBuildFeatureReturnsNull() {
        JwtBuildStartContext jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer);
        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getBuildFeature()).thenReturn(null);

        AssertionsForClassTypes.assertThatNoException()
                .isThrownBy(() -> jwtBuildStartContext.updateParameters(buildStartContext));
        verify(buildStartContext, never()).addSharedParameter(any(), any());
    }

    @Test
    public void testRegister() {
        JwtBuildStartContext jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer);
        jwtBuildStartContext.register();

        verify(extensionHolder, times(1)).registerExtension(any(), any(), any());
    }

    @Test
    public void doNotUpdateParametersWhenBuildFeatureDisabled() {
        JwtBuildStartContext jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer);
        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(Collections.emptyList());
        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext, never()).addSharedParameter(any(), any());
    }

    @Test
    public void doesNotThrowWhenBuildIsTriggeredAutomaticallyWithNoUser() throws NoSuchAlgorithmException, IOException, ParseException, com.nimbusds.jose.JOSEException {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        JwtBuildStartContext jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getBuildFeature()).thenReturn(jwtBuildFeature);

        TriggeredBy triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);
        when(triggeredBy.getUser()).thenReturn(null); // automated trigger — no user
        when(triggeredBy.getAsString()).thenReturn("Schedule Trigger");

        // Should succeed and inject JWT even when no user triggered the build
        AssertionsForClassTypes.assertThatNoException().isThrownBy(() -> jwtBuildStartContext.updateParameters(buildStartContext));
        verify(buildStartContext, times(1)).addSharedParameter(eq("jwt.token"), any());
    }

    @Test
    public void branchClaimIsTheBranchNameNotAnObjectReference() throws NoSuchAlgorithmException, IOException, ParseException, com.nimbusds.jose.JOSEException {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        JwtBuildStartContext jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getBuildFeature()).thenReturn(jwtBuildFeature);

        Branch branch = mock(Branch.class);
        when(branch.getName()).thenReturn("refs/heads/main");
        when(runningBuild.getBranch()).thenReturn(branch);

        TriggeredBy triggeredBy = mock(TriggeredBy.class);
        SUser user = mock(SUser.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);
        when(triggeredBy.getUser()).thenReturn(user);

        ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        SignedJWT jwt = SignedJWT.parse(jwtCaptor.getValue());
        assertThat(jwt.getJWTClaimsSet().getStringClaim("branch")).isEqualTo("refs/heads/main");
    }

    @Test
    public void tokenTtlIsReadFromBuildFeatureParameters() throws NoSuchAlgorithmException, IOException, ParseException, com.nimbusds.jose.JOSEException {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        JwtBuildStartContext jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getBuildFeature()).thenReturn(jwtBuildFeature);
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(Map.of("ttl_minutes", "5"));

        TriggeredBy triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);
        when(triggeredBy.getUser()).thenReturn(mock(SUser.class));

        ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        SignedJWT jwt = SignedJWT.parse(jwtCaptor.getValue());
        long expirySeconds = jwt.getJWTClaimsSet().getExpirationTime().getTime() / 1000;
        long issuedAtSeconds = jwt.getJWTClaimsSet().getIssueTime().getTime() / 1000;
        assertThat(expirySeconds - issuedAtSeconds).isEqualTo(5 * 60);
    }

    @Test
    public void tokenTtlDefaultsTo10MinutesWhenNotConfigured() throws NoSuchAlgorithmException, IOException, ParseException, com.nimbusds.jose.JOSEException {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        JwtBuildStartContext jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getBuildFeature()).thenReturn(jwtBuildFeature);
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(Map.of());

        TriggeredBy triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);
        when(triggeredBy.getUser()).thenReturn(mock(SUser.class));

        ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        SignedJWT jwt = SignedJWT.parse(jwtCaptor.getValue());
        long expirySeconds = jwt.getJWTClaimsSet().getExpirationTime().getTime() / 1000;
        long issuedAtSeconds = jwt.getJWTClaimsSet().getIssueTime().getTime() / 1000;
        assertThat(expirySeconds - issuedAtSeconds).isEqualTo(10 * 60);
    }

    @Test
    public void doesNotInjectTokenWhenRootUrlIsNotHttps() throws NoSuchAlgorithmException, IOException, ParseException, com.nimbusds.jose.JOSEException {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        when(buildServer.getRootUrl()).thenReturn("http://localhost:8111");
        JwtBuildStartContext jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getBuildFeature()).thenReturn(jwtBuildFeature);

        // Should log a warning and skip token injection rather than crashing the build
        AssertionsForClassTypes.assertThatNoException()
                .isThrownBy(() -> jwtBuildStartContext.updateParameters(buildStartContext));
        verify(buildStartContext, never()).addSharedParameter(any(), any());
    }

    @Test
    public void updateParametersWhenBuildFeatureEnabled() throws NoSuchAlgorithmException, IOException, ParseException, com.nimbusds.jose.JOSEException {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        JwtBuildStartContext jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getBuildFeature()).thenReturn(jwtBuildFeature);

        TriggeredBy triggeredByMock = mock(TriggeredBy.class);
        SUser userMock = mock(SUser.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredByMock);
        when(triggeredByMock.getUser()).thenReturn(userMock);

        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext, times(1)).addSharedParameter(eq("jwt.token"), any());
    }

    @Test
    public void audienceIsConfigurablePerBuildFeature() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        JwtBuildStartContext jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getBuildFeature()).thenReturn(jwtBuildFeature);
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(Map.of("audience", "my-cloud-audience"));

        TriggeredBy triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);

        ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        SignedJWT jwt = SignedJWT.parse(jwtCaptor.getValue());
        assertThat(jwt.getJWTClaimsSet().getAudience()).containsExactly("my-cloud-audience");
    }

    @Test
    public void audienceDefaultsToServerRootUrlWhenNotConfigured() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        JwtBuildStartContext jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getBuildFeature()).thenReturn(jwtBuildFeature);
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(Map.of());

        TriggeredBy triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);

        ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        SignedJWT jwt = SignedJWT.parse(jwtCaptor.getValue());
        assertThat(jwt.getJWTClaimsSet().getAudience()).containsExactly("https://localhost:8111");
    }

    @Test
    public void onlyConfiguredClaimsAreIncluded() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        JwtBuildStartContext jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getBuildFeature()).thenReturn(jwtBuildFeature);
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(Map.of("claims", "branch"));

        Branch branch = mock(Branch.class);
        when(branch.getName()).thenReturn("refs/heads/main");
        when(runningBuild.getBranch()).thenReturn(branch);

        TriggeredBy triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);

        ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        SignedJWT jwt = SignedJWT.parse(jwtCaptor.getValue());
        assertThat(jwt.getJWTClaimsSet().getStringClaim("branch")).isEqualTo("refs/heads/main");
        assertThat(jwt.getJWTClaimsSet().getClaim("project_external_id")).isNull();
        assertThat(jwt.getJWTClaimsSet().getClaim("triggered_by")).isNull();
        assertThat(jwt.getJWTClaimsSet().getClaim("build_number")).isNull();
    }

    @Test
    public void claimsWithWhitespaceAroundCommasAreAllIncluded() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        JwtBuildStartContext jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getBuildFeature()).thenReturn(jwtBuildFeature);
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(Map.of("claims", "branch, build_number"));

        Branch branch = mock(Branch.class);
        when(branch.getName()).thenReturn("refs/heads/main");
        when(runningBuild.getBranch()).thenReturn(branch);
        when(runningBuild.getBuildNumber()).thenReturn("42");

        TriggeredBy triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);

        ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        SignedJWT jwt = SignedJWT.parse(jwtCaptor.getValue());
        assertThat(jwt.getJWTClaimsSet().getStringClaim("branch")).isEqualTo("refs/heads/main");
        assertThat(jwt.getJWTClaimsSet().getStringClaim("build_number")).isEqualTo("42");
        assertThat(jwt.getJWTClaimsSet().getClaim("project_external_id")).isNull();
    }

    @Test
    public void allClaimsIncludedWhenClaimsParamAbsent() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        JwtBuildStartContext jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getBuildFeature()).thenReturn(jwtBuildFeature);
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(Map.of());

        when(runningBuild.getBuildTypeExternalId()).thenReturn("BuildType_1");
        when(runningBuild.getProjectExternalId()).thenReturn("Project_1");
        when(runningBuild.getBuildNumber()).thenReturn("42");

        TriggeredBy triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);
        when(triggeredBy.getAsString()).thenReturn("User Trigger");

        ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        SignedJWT jwt = SignedJWT.parse(jwtCaptor.getValue());
        assertThat(jwt.getJWTClaimsSet().getClaims()).containsKeys(
                "branch", "build_type_external_id", "project_external_id",
                "triggered_by", "build_number");
    }

    @Test
    public void jtiClaimIsUniquePerToken() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        JwtBuildStartContext jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getBuildFeature()).thenReturn(jwtBuildFeature);
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(Map.of());
        when(runningBuild.getBuildId()).thenReturn(42L);

        TriggeredBy triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);

        ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);

        jwtBuildStartContext.updateParameters(buildStartContext);
        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext, times(2)).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        List<String> tokens = jwtCaptor.getAllValues();
        String jti1 = SignedJWT.parse(tokens.get(0)).getJWTClaimsSet().getJWTID();
        String jti2 = SignedJWT.parse(tokens.get(1)).getJWTClaimsSet().getJWTID();

        assertThat(jti1).startsWith("42-");
        assertThat(jti2).startsWith("42-");
        assertThat(jti1).isNotEqualTo(jti2);
    }
}
