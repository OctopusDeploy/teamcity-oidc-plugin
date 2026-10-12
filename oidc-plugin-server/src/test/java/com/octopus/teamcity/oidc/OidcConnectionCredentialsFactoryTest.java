package com.octopus.teamcity.oidc;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.ProjectManager;
import jetbrains.buildServer.serverSide.SBuildFeatureDescriptor;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.serverSide.SBuildType;
import jetbrains.buildServer.serverSide.SProject;
import jetbrains.buildServer.serverSide.SRunningBuild;
import jetbrains.buildServer.serverSide.ServerPaths;
import jetbrains.buildServer.serverSide.TriggeredBy;
import jetbrains.buildServer.serverSide.auth.AuthorityHolder;
import jetbrains.buildServer.serverSide.auth.Permission;
import jetbrains.buildServer.serverSide.auth.SecurityContext;
import jetbrains.buildServer.serverSide.connections.ConnectionDescriptor;
import jetbrains.buildServer.serverSide.connections.credentials.ConnectionCredentials;
import jetbrains.buildServer.serverSide.connections.credentials.ConnectionCredentialsException;
import jetbrains.buildServer.serverSide.connections.credentials.ConnectionCredentialsFactory;
import jetbrains.buildServer.users.SUser;
import jetbrains.buildServer.users.User;
import org.jetbrains.annotations.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OidcConnectionCredentialsFactoryTest {

    private static final String CONNECTION_ID = "octopus-oidc";
    private static final String CONNECTION_PROJECT_ID = "project3";
    private static final String BUILD_TYPE_EXTERNAL_ID = "Deployments_Release";

    @Mock ServerPaths serverPaths;
    @Mock ExtensionHolder extensionHolder;
    @Mock OidcConnectionsManager connectionsManager;
    @Mock ProjectManager projectManager;
    @Mock SecurityContext securityContext;
    @Mock AuthorityHolder authorityHolder;
    @Mock User user;
    @Mock SProject project;
    @Mock SBuildType buildType;
    @Mock ConnectionDescriptor descriptor;

    @TempDir File tempDir;

    private JwtKeyManager keyManager;
    private OidcIssuerUrlProvider issuerUrlProvider;
    private OidcConnectionCredentialsFactory factory;

    @BeforeEach
    void setUp() {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        keyManager = TestJwtKeyManagerFactory.create(serverPaths);
        final var server = mock(SBuildServer.class);
        lenient().when(server.getRootUrl()).thenReturn("https://teamcity.example.com");
        issuerUrlProvider = new OidcIssuerUrlProvider(server, new OidcSettingsManager(tempDir));
        factory = new OidcConnectionCredentialsFactory(
                extensionHolder, connectionsManager, keyManager, issuerUrlProvider, projectManager, securityContext);

        lenient().when(securityContext.getAuthorityHolder()).thenReturn(authorityHolder);
        lenient().when(authorityHolder.getAssociatedUser()).thenReturn(user);
        lenient().when(user.getUsername()).thenReturn("alice");
        lenient().when(authorityHolder.isPermissionGrantedForProject("project7", Permission.EDIT_PROJECT)).thenReturn(true);
        lenient().when(descriptor.getId()).thenReturn(CONNECTION_ID);
        lenient().when(project.getProjectId()).thenReturn("project7");
        lenient().when(project.getExternalId()).thenReturn("Deployments");
        lenient().when(buildType.getProject()).thenReturn(project);
        lenient().when(buildType.getProjectId()).thenReturn("project7");
        lenient().when(buildType.getInternalId()).thenReturn("bt42");
        lenient().when(buildType.getExternalId()).thenReturn(BUILD_TYPE_EXTERNAL_ID);
        lenient().when(projectManager.findBuildTypeByExternalId(BUILD_TYPE_EXTERNAL_ID)).thenReturn(buildType);
    }

    private void connectionWithDimensions(final Set<String> dimensions) {
        lenient().when(connectionsManager.resolve(project, CONNECTION_ID)).thenReturn(Optional.of(
                new OidcConnection(CONNECTION_ID, CONNECTION_PROJECT_ID, "Octopus",
                        new IssuanceSettings("api://octopus", 30, "RS256", dimensions), "jwt.token")));
    }

    private void requestFor(@Nullable final String buildTypeId) {
        lenient().when(descriptor.getParameters()).thenReturn(buildTypeId == null
                ? Map.of()
                : Map.of(OidcConnectionCredentialsFactory.BUILD_TYPE_ID_PARAM, buildTypeId));
    }

    private static JWTClaimsSet claimsOf(final ConnectionCredentials credentials) throws Exception {
        return SignedJWT.parse(credentials.getProperties().get(OidcConnectionCredentialsFactory.ID_TOKEN))
                .getJWTClaimsSet();
    }

    @Test
    void registersAsTheCredentialsFactoryForOidcConnections() {
        factory.register();

        verify(extensionHolder).registerExtension(
                ConnectionCredentialsFactory.class, OidcConnectionCredentialsFactory.class.getName(), factory);
        assertThat(factory.getType()).isEqualTo("oidc-identity-token");
    }

    @Test
    void tokenForABuildConfigurationCarriesThatBuildConfigurationsSubject() throws Exception {
        connectionWithDimensions(Set.of("connection", "trigger_type"));
        requestFor(BUILD_TYPE_EXTERNAL_ID);

        final var credentials = factory.requestCredentials(project, descriptor);

        final var expected = "connection_project:project3:connection:octopus-oidc:project:project7:build_type:bt42:trigger_type:user";
        assertThat(credentials.getProviderType()).isEqualTo("oidc-identity-token");
        assertThat(credentials.getProperties().get(OidcConnectionCredentialsFactory.SUBJECT)).isEqualTo(expected);
        final var claims = claimsOf(credentials);
        assertThat(claims.getSubject()).isEqualTo(expected);
        assertThat(claims.getAudience()).containsExactly("api://octopus");
        assertThat(claims.getIssuer()).isEqualTo(issuerUrlProvider.getIssuerUrl());
        assertThat(claims.getStringClaim("build_type_external_id")).isEqualTo(BUILD_TYPE_EXTERNAL_ID);
        assertThat(claims.getStringClaim("build_type_internal_id")).isEqualTo("bt42");
        assertThat(claims.getStringClaim("project_external_id")).isEqualTo("Deployments");
        assertThat(claims.getStringClaim("project_internal_id")).isEqualTo("project7");
        assertThat(claims.getStringClaim("trigger_type")).isEqualTo("user");
    }

    static Stream<Set<String>> dimensionSets() {
        return Stream.of(Set.of(), Set.of("connection"), Set.of("trigger_type"),
                Set.of("connection", "branch", "trigger_type"));
    }

    @ParameterizedTest
    @MethodSource("dimensionSets")
    void subjectMatchesAManuallyTriggeredBuildOfTheSameBuildConfiguration(final Set<String> dimensions) throws Exception {
        connectionWithDimensions(dimensions);
        requestFor(BUILD_TYPE_EXTERNAL_ID);

        final var build = mock(SRunningBuild.class);
        final var feature = mock(SBuildFeatureDescriptor.class);
        final var triggeredBy = mock(TriggeredBy.class);
        when(build.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(feature));
        when(feature.getParameters()).thenReturn(Map.of("connection_id", CONNECTION_ID));
        when(build.getTriggeredBy()).thenReturn(triggeredBy);
        when(triggeredBy.getUser()).thenReturn(mock(SUser.class));
        when(build.getBuildType()).thenReturn(buildType);
        when(build.getProjectId()).thenReturn("project7");
        when(build.getBuildTypeId()).thenReturn("bt42");
        final var issuanceService = new JwtIssuanceService(
                issuerUrlProvider, keyManager, new OidcSettingsManager(tempDir), connectionsManager);
        final var buildSubject = SignedJWT.parse(issuanceService.tokensFor(build).get("jwt.token"))
                .getJWTClaimsSet().getSubject();

        final var editTimeSubject = claimsOf(factory.requestCredentials(project, descriptor)).getSubject();

        assertThat(editTimeSubject).isEqualTo(buildSubject);
    }

    @Test
    void projectScopedTokenUsesTheConnectionPrefixAndNoBuildType() throws Exception {
        connectionWithDimensions(Set.of("connection"));
        requestFor(null);

        final var claims = claimsOf(factory.requestCredentials(project, descriptor));

        assertThat(claims.getSubject()).isEqualTo("connection_project:project3:connection:octopus-oidc:project:project7");
        assertThat(claims.getStringClaim("project_external_id")).isEqualTo("Deployments");
        assertThat(claims.getClaim("build_type_internal_id")).isNull();
    }

    @Test
    void tokenLastsOneMinuteAndEachCallGetsAFreshJti() throws Exception {
        connectionWithDimensions(Set.of());
        requestFor(BUILD_TYPE_EXTERNAL_ID);

        final var first = factory.requestCredentials(project, descriptor);
        final var second = factory.requestCredentials(project, descriptor);

        final var claims = claimsOf(first);
        assertThat(Duration.between(claims.getIssueTime().toInstant(), claims.getExpirationTime().toInstant()))
                .isEqualTo(Duration.ofMinutes(1));
        assertThat(first.getProperties().get(OidcConnectionCredentialsFactory.EXPIRES_AT))
                .isEqualTo(String.valueOf(claims.getExpirationTime().toInstant().getEpochSecond()));
        assertThat(claimsOf(second).getJWTID()).isNotEqualTo(claims.getJWTID());
    }

    @Test
    void refusedWithoutASignedInUser() {
        connectionWithDimensions(Set.of());
        requestFor(BUILD_TYPE_EXTERNAL_ID);
        when(authorityHolder.getAssociatedUser()).thenReturn(null);

        assertThatThrownBy(() -> factory.requestCredentials(project, descriptor))
                .isInstanceOf(ConnectionCredentialsException.class)
                .hasMessageContaining("signed-in user");
    }

    @Test
    void refusedWithoutEditProjectOnTheBuildConfigurationsProject() {
        connectionWithDimensions(Set.of());
        requestFor(BUILD_TYPE_EXTERNAL_ID);
        when(authorityHolder.isPermissionGrantedForProject("project7", Permission.EDIT_PROJECT)).thenReturn(false);

        assertThatThrownBy(() -> factory.requestCredentials(project, descriptor))
                .isInstanceOf(ConnectionCredentialsException.class)
                .hasMessageContaining("permission to edit project 'Deployments'");
    }

    @Test
    void refusedWhenUserCannotEditTheBuildConfigurationsProject() {
        connectionWithDimensions(Set.of());
        final var otherProject = mock(SProject.class);
        final var otherBuildType = mock(SBuildType.class);
        when(otherProject.getProjectId()).thenReturn("project9");
        when(otherProject.getExternalId()).thenReturn("Secrets");
        when(otherBuildType.getProject()).thenReturn(otherProject);
        when(projectManager.findBuildTypeByExternalId("Secrets_Deploy")).thenReturn(otherBuildType);
        when(authorityHolder.isPermissionGrantedForProject("project9", Permission.EDIT_PROJECT)).thenReturn(false);
        requestFor("Secrets_Deploy");

        assertThatThrownBy(() -> factory.requestCredentials(project, descriptor))
                .isInstanceOf(ConnectionCredentialsException.class)
                .hasMessageContaining("permission to edit project 'Secrets'");
    }

    @Test
    void refusedWhenTheConnectionIsNotVisibleFromTheProject() {
        requestFor(BUILD_TYPE_EXTERNAL_ID);
        when(connectionsManager.resolve(project, CONNECTION_ID)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> factory.requestCredentials(project, descriptor))
                .isInstanceOf(ConnectionCredentialsException.class)
                .hasMessageContaining("OIDC connection 'octopus-oidc' is not available to project 'Deployments'");
    }

    @Test
    void projectScopedTokenNeedsTheConnectionDimension() {
        connectionWithDimensions(Set.of("trigger_type"));
        requestFor(null);

        assertThatThrownBy(() -> factory.requestCredentials(project, descriptor))
                .isInstanceOf(ConnectionCredentialsException.class)
                .hasMessage("Enable the connection subject dimension on this OIDC connection to use it outside a build.");
    }
}
