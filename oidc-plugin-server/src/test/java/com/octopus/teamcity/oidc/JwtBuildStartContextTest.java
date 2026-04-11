package com.octopus.teamcity.oidc;

import com.nimbusds.jwt.SignedJWT;
import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.*;
import jetbrains.buildServer.serverSide.ServerPaths;
import jetbrains.buildServer.users.SUser;
import org.assertj.core.api.AssertionsForClassTypes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class JwtBuildStartContextTest {

    @Mock ExtensionHolder extensionHolder;
    @Mock SBuildServer buildServer;
    @Mock SRunningBuild runningBuild;
    @Mock BuildStartContext buildStartContext;
    @Mock SBuildFeatureDescriptor jwtBuildFeatureBuildFeatureDescriptor;
    @Mock ServerPaths serverPaths;

    @TempDir File tempDir;

    @Test
    public void testRegister() {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        final var  keyManager = new JwtKeyManager(serverPaths);
        final var  jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer, keyManager);
        jwtBuildStartContext.register();
        verify(extensionHolder, times(1)).registerExtension(any(), any(), any());
    }

    @Test
    public void doNotUpdateParametersWhenBuildFeatureDisabled() {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        final var  keyManager = new JwtKeyManager(serverPaths);
        final var  jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer, keyManager);
        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(Collections.emptyList());
        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext, never()).addSharedParameter(any(), any());
    }

    @Test
    public void doesNotThrowWhenBuildIsTriggeredAutomaticallyWithNoUser() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        final var  keyManager = new JwtKeyManager(serverPaths);
        final var  jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer, keyManager);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(Map.of());

        final var  triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);
        when(triggeredBy.getUser()).thenReturn(null);
        when(triggeredBy.getAsString()).thenReturn("Schedule Trigger");

        AssertionsForClassTypes.assertThatNoException()
                .isThrownBy(() -> jwtBuildStartContext.updateParameters(buildStartContext));
        verify(buildStartContext, times(1)).addSharedParameter(eq("jwt.token"), any());
    }

    @Test
    public void branchClaimIsTheBranchNameNotAnObjectReference() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        final var keyManager = new JwtKeyManager(serverPaths);
        final var jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer, keyManager);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(Map.of());

        final var branch = mock(Branch.class);
        when(branch.getName()).thenReturn("refs/heads/main");
        when(runningBuild.getBranch()).thenReturn(branch);

        final var  triggeredBy = mock(TriggeredBy.class);
        final var  user = mock(SUser.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);
        when(triggeredBy.getUser()).thenReturn(user);

        final var jwtCaptor = ArgumentCaptor.forClass(String.class);
        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        final var jwt = SignedJWT.parse(jwtCaptor.getValue());
        assertThat(jwt.getJWTClaimsSet().getStringClaim("branch")).isEqualTo("refs/heads/main");
    }

    @Test
    public void tokenTtlIsReadFromBuildFeatureParameters() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        final var keyManager = new JwtKeyManager(serverPaths);
        final var jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer, keyManager);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(Map.of("ttl_minutes", "5"));

        final var  triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);
        when(triggeredBy.getUser()).thenReturn(mock(SUser.class));

        final var jwtCaptor = ArgumentCaptor.forClass(String.class);
        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        final var jwt = SignedJWT.parse(jwtCaptor.getValue());
        final var expirySeconds = jwt.getJWTClaimsSet().getExpirationTime().getTime() / 1000;
        final var issuedAtSeconds = jwt.getJWTClaimsSet().getIssueTime().getTime() / 1000;
        assertThat(expirySeconds - issuedAtSeconds).isEqualTo(5 * 60);
    }

    @Test
    public void tokenTtlDefaultsTo10MinutesWhenNotConfigured() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        final var keyManager = new JwtKeyManager(serverPaths);
        final var jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer, keyManager);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(Map.of());

        final var triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);
        when(triggeredBy.getUser()).thenReturn(mock(SUser.class));

        final var jwtCaptor = ArgumentCaptor.forClass(String.class);
        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        final var jwt = SignedJWT.parse(jwtCaptor.getValue());
        final var expirySeconds = jwt.getJWTClaimsSet().getExpirationTime().getTime() / 1000;
        final var issuedAtSeconds = jwt.getJWTClaimsSet().getIssueTime().getTime() / 1000;
        assertThat(expirySeconds - issuedAtSeconds).isEqualTo(10 * 60);
    }

    @Test
    public void doesNotInjectTokenWhenRootUrlIsNotHttps() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("http://localhost:8111");
        final var keyManager = new JwtKeyManager(serverPaths);
        final var jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer, keyManager);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(Map.of());

        AssertionsForClassTypes.assertThatNoException()
                .isThrownBy(() -> jwtBuildStartContext.updateParameters(buildStartContext));
        verify(buildStartContext, never()).addSharedParameter(any(), any());
    }

    @Test
    public void updateParametersWhenBuildFeatureEnabled() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        final var keyManager = new JwtKeyManager(serverPaths);
        final var jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer, keyManager);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(Map.of());

        final var triggeredByMock = mock(TriggeredBy.class);
        final var userMock = mock(SUser.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredByMock);
        when(triggeredByMock.getUser()).thenReturn(userMock);

        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext, times(1)).addSharedParameter(eq("jwt.token"), any());
    }

    @Test
    public void audienceIsConfigurablePerBuildFeature() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        final var keyManager = new JwtKeyManager(serverPaths);
        final var jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer, keyManager);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(Map.of("audience", "my-cloud-audience"));

        final var triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);

        final var jwtCaptor = ArgumentCaptor.forClass(String.class);
        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        final var jwt = SignedJWT.parse(jwtCaptor.getValue());
        assertThat(jwt.getJWTClaimsSet().getAudience()).containsExactly("my-cloud-audience");
    }

    @Test
    public void audienceDefaultsToServerRootUrlWhenNotConfigured() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        final var keyManager = new JwtKeyManager(serverPaths);
        final var jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer, keyManager);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(Map.of());

        final var triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);

        final var jwtCaptor = ArgumentCaptor.forClass(String.class);
        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        final var jwt = SignedJWT.parse(jwtCaptor.getValue());
        assertThat(jwt.getJWTClaimsSet().getAudience()).containsExactly("https://localhost:8111");
    }

    @Test
    public void audienceDefaultsToServerRootUrlWhenAudienceParamIsBlank() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        final var keyManager = new JwtKeyManager(serverPaths);
        final var jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer, keyManager);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(Map.of("audience", ""));

        final var triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);

        final var jwtCaptor = ArgumentCaptor.forClass(String.class);
        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        final var jwt = SignedJWT.parse(jwtCaptor.getValue());
        assertThat(jwt.getJWTClaimsSet().getAudience()).containsExactly("https://localhost:8111");
    }

    @Test
    public void triggeredByIdClaimIncludedWhenUserIsAvailable() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        final var keyManager = new JwtKeyManager(serverPaths);
        final var jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer, keyManager);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(Map.of());

        final var triggeredBy = mock(TriggeredBy.class);
        final var user = mock(SUser.class);
        when(user.getId()).thenReturn(42L);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);
        when(triggeredBy.getUser()).thenReturn(user);

        final var jwtCaptor = ArgumentCaptor.forClass(String.class);
        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        final var jwt = SignedJWT.parse(jwtCaptor.getValue());
        assertThat(jwt.getJWTClaimsSet().getLongClaim("triggered_by_id")).isEqualTo(42L);
    }

    @Test
    public void onlyConfiguredClaimsAreIncluded() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        final var keyManager = new JwtKeyManager(serverPaths);
        final var jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer, keyManager);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(Map.of("claims", "branch"));

        final var branch = mock(Branch.class);
        when(branch.getName()).thenReturn("refs/heads/main");
        when(runningBuild.getBranch()).thenReturn(branch);

        final var triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);

        final var jwtCaptor = ArgumentCaptor.forClass(String.class);
        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        final var jwt = SignedJWT.parse(jwtCaptor.getValue());
        assertThat(jwt.getJWTClaimsSet().getStringClaim("branch")).isEqualTo("refs/heads/main");
        assertThat(jwt.getJWTClaimsSet().getClaim("project_external_id")).isNull();
        assertThat(jwt.getJWTClaimsSet().getClaim("triggered_by")).isNull();
        assertThat(jwt.getJWTClaimsSet().getClaim("build_number")).isNull();
    }

    @Test
    public void claimsWithWhitespaceAroundCommasAreAllIncluded() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        final var keyManager = new JwtKeyManager(serverPaths);
        final var jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer, keyManager);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(Map.of("claims", "branch, build_number"));

        final var branch = mock(Branch.class);
        when(branch.getName()).thenReturn("refs/heads/main");
        when(runningBuild.getBranch()).thenReturn(branch);
        when(runningBuild.getBuildNumber()).thenReturn("42");

        final var triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);

        final var jwtCaptor = ArgumentCaptor.forClass(String.class);
        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        final var jwt = SignedJWT.parse(jwtCaptor.getValue());
        assertThat(jwt.getJWTClaimsSet().getStringClaim("branch")).isEqualTo("refs/heads/main");
        assertThat(jwt.getJWTClaimsSet().getStringClaim("build_number")).isEqualTo("42");
        assertThat(jwt.getJWTClaimsSet().getClaim("project_external_id")).isNull();
    }

    @Test
    public void allClaimsIncludedWhenClaimsParamAbsent() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        final var keyManager = new JwtKeyManager(serverPaths);
        final var jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer, keyManager);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(Map.of());

        when(runningBuild.getBuildTypeExternalId()).thenReturn("BuildType_1");
        when(runningBuild.getProjectExternalId()).thenReturn("Project_1");
        when(runningBuild.getBuildNumber()).thenReturn("42");

        final var triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);
        when(triggeredBy.getAsString()).thenReturn("User Trigger");

        final var jwtCaptor = ArgumentCaptor.forClass(String.class);
        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        final var jwt = SignedJWT.parse(jwtCaptor.getValue());
        assertThat(jwt.getJWTClaimsSet().getClaims()).containsKeys(
                "branch", "build_type_external_id", "project_external_id",
                "triggered_by", "build_number");
    }

    @Test
    public void issuerClaimHasTrailingSlashStripped() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111/");
        final var keyManager = new JwtKeyManager(serverPaths);
        final var jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer, keyManager);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(Map.of());

        final var triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);

        final var jwtCaptor = ArgumentCaptor.forClass(String.class);
        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        final var issuer = SignedJWT.parse(jwtCaptor.getValue()).getJWTClaimsSet().getIssuer();
        assertThat(issuer).isEqualTo("https://localhost:8111");
    }

    @Test
    public void jtiClaimIsUniquePerToken() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        final var keyManager = new JwtKeyManager(serverPaths);
        final var jwtBuildStartContext = new JwtBuildStartContext(extensionHolder, buildServer, keyManager);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(Map.of());
        when(runningBuild.getBuildId()).thenReturn(42L);

        final var triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);

        final var jwtCaptor = ArgumentCaptor.forClass(String.class);

        jwtBuildStartContext.updateParameters(buildStartContext);
        jwtBuildStartContext.updateParameters(buildStartContext);
        verify(buildStartContext, times(2)).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        final var tokens = jwtCaptor.getAllValues();
        final var jti1 = SignedJWT.parse(tokens.get(0)).getJWTClaimsSet().getJWTID();
        final var jti2 = SignedJWT.parse(tokens.get(1)).getJWTClaimsSet().getJWTID();

        assertThat(jti1).startsWith("42-");
        assertThat(jti2).startsWith("42-");
        assertThat(jti1).isNotEqualTo(jti2);
    }
}
