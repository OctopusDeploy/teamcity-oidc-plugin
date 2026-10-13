package com.octopus.teamcity.oidc;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.BuildTypeTemplate;
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
import org.junit.jupiter.api.AfterEach;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
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

    private final List<LogRecord> logged = new ArrayList<>();
    private final Handler logCapture = new Handler() {
        @Override public void publish(final LogRecord record) { logged.add(record); }
        @Override public void flush() { }
        @Override public void close() { }
    };

    private final Logger factoryLogger = Logger.getLogger(OidcConnectionCredentialsFactory.class.getName());
    private Level originalLevel;

    // The test logging.properties sets the root level to WARNING, so INFO needs enabling here.
    @BeforeEach
    void captureLogs() {
        originalLevel = factoryLogger.getLevel();
        factoryLogger.setLevel(Level.INFO);
        factoryLogger.setUseParentHandlers(false);
        factoryLogger.addHandler(logCapture);
    }

    @AfterEach
    void releaseLogs() {
        factoryLogger.removeHandler(logCapture);
        factoryLogger.setUseParentHandlers(true);
        factoryLogger.setLevel(originalLevel);
    }

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
        lenient().when(descriptor.getProjectId()).thenReturn(CONNECTION_PROJECT_ID);
        lenient().when(project.getProjectId()).thenReturn("project7");
        lenient().when(project.getExternalId()).thenReturn("Deployments");
        lenient().when(project.getProjectPath()).thenReturn(List.of(project));
        lenient().when(buildType.getProject()).thenReturn(project);
        lenient().when(buildType.getProjectId()).thenReturn("project7");
        lenient().when(buildType.getInternalId()).thenReturn("bt42");
        lenient().when(buildType.getExternalId()).thenReturn(BUILD_TYPE_EXTERNAL_ID);
        lenient().when(projectManager.findBuildTypeByExternalId(BUILD_TYPE_EXTERNAL_ID)).thenReturn(buildType);
    }

    private void connectionWithDimensions(final Set<String> dimensions) {
        connectionWithDimensions(project, "RS256", dimensions);
    }

    private void connectionWithDimensions(final SProject resolvingProject, final String algorithm,
                                          final Set<String> dimensions) {
        lenient().when(connectionsManager.resolve(resolvingProject, CONNECTION_ID)).thenReturn(Optional.of(
                new OidcConnection(CONNECTION_ID, CONNECTION_PROJECT_ID, "Octopus",
                        new IssuanceSettings("api://octopus", 30, algorithm, dimensions), "jwt.token")));
    }

    /** A build configuration in a project beside the passed one, on which the caller has Edit Project. */
    private SProject otherProjectWithBuildType(final String buildTypeExternalId) {
        return projectWithBuildType(buildTypeExternalId, List.of());
    }

    /** A build configuration in a subproject of the passed one, on which the caller has Edit Project. */
    private SProject subprojectWithBuildType(final String buildTypeExternalId) {
        return projectWithBuildType(buildTypeExternalId, List.of(project));
    }

    private SProject projectWithBuildType(final String buildTypeExternalId, final List<SProject> ancestors) {
        final var otherProject = mock(SProject.class);
        final var path = new ArrayList<>(ancestors);
        path.add(otherProject);
        lenient().when(otherProject.getProjectPath()).thenReturn(path);
        final var otherBuildType = mock(SBuildType.class);
        lenient().when(otherProject.getProjectId()).thenReturn("project9");
        lenient().when(otherProject.getExternalId()).thenReturn("Secrets");
        lenient().when(otherBuildType.getProject()).thenReturn(otherProject);
        lenient().when(otherBuildType.getInternalId()).thenReturn("bt99");
        lenient().when(otherBuildType.getExternalId()).thenReturn(buildTypeExternalId);
        lenient().when(projectManager.findBuildTypeByExternalId(buildTypeExternalId)).thenReturn(otherBuildType);
        lenient().when(authorityHolder.isPermissionGrantedForProject("project9", Permission.EDIT_PROJECT)).thenReturn(true);
        return otherProject;
    }

    private void requestFor(@Nullable final String buildTypeId) {
        lenient().when(descriptor.getParameters()).thenReturn(buildTypeId == null
                ? Map.of()
                : Map.of(OidcConnectionCredentialsFactory.BUILD_TYPE_ID_PARAM, buildTypeId));
    }

    private static String notFoundOrNoPermission(final String buildTypeId) {
        return "Build configuration '" + buildTypeId
                + "' was not found, or you do not have permission to edit its project.";
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
                .hasMessage(notFoundOrNoPermission(BUILD_TYPE_EXTERNAL_ID));
    }

    @Test
    void refusedWhenTheBuildConfigurationIsInAnotherProject() {
        connectionWithDimensions(Set.of());
        otherProjectWithBuildType("Secrets_Deploy");
        when(authorityHolder.isPermissionGrantedForProject("project9", Permission.EDIT_PROJECT)).thenReturn(false);
        requestFor("Secrets_Deploy");

        assertThatThrownBy(() -> factory.requestCredentials(project, descriptor))
                .isInstanceOf(ConnectionCredentialsException.class)
                .hasMessage(notFoundOrNoPermission("Secrets_Deploy"));
    }

    @Test
    void refusedWhenTheBuildConfigurationIsOutsideThePassedProject() {
        final var otherProject = otherProjectWithBuildType("Secrets_Deploy");
        connectionWithDimensions(otherProject, "RS256", Set.of());
        requestFor("Secrets_Deploy");

        assertThatThrownBy(() -> factory.requestCredentials(project, descriptor))
                .isInstanceOf(ConnectionCredentialsException.class)
                .hasMessage("Build configuration 'Secrets_Deploy' is not in project 'Deployments' or its subprojects.");
    }

    @Test
    void connectionIsResolvedFromTheBuildConfigurationsProjectNotThePassedOne() {
        final var subproject = subprojectWithBuildType("Secrets_Deploy");
        when(connectionsManager.resolve(subproject, CONNECTION_ID)).thenReturn(Optional.empty());
        requestFor("Secrets_Deploy");

        assertThatThrownBy(() -> factory.requestCredentials(project, descriptor))
                .isInstanceOf(ConnectionCredentialsException.class)
                .hasMessageContaining("OIDC connection 'octopus-oidc' is not available to project 'Secrets'");
    }

    @Test
    void tokenForABuildConfigurationInASubprojectUsesThatProjectsIds() throws Exception {
        final var subproject = subprojectWithBuildType("Secrets_Deploy");
        connectionWithDimensions(subproject, "RS256", Set.of("connection", "trigger_type"));
        requestFor("Secrets_Deploy");

        final var claims = claimsOf(factory.requestCredentials(project, descriptor));

        assertThat(claims.getSubject()).isEqualTo(
                "connection_project:project3:connection:octopus-oidc:project:project9:build_type:bt99:trigger_type:user");
        assertThat(claims.getStringClaim("project_internal_id")).isEqualTo("project9");
        assertThat(claims.getStringClaim("project_external_id")).isEqualTo("Secrets");
        assertThat(claims.getStringClaim("build_type_internal_id")).isEqualTo("bt99");
    }

    @Test
    void unsupportedStoredAlgorithmIsRefusedAndLogged() {
        connectionWithDimensions(project, "XX999", Set.of());
        requestFor(BUILD_TYPE_EXTERNAL_ID);

        assertThatThrownBy(() -> factory.requestCredentials(project, descriptor))
                .isInstanceOf(ConnectionCredentialsException.class)
                .hasMessage("Signing the OIDC token failed — check the TeamCity server log for details");

        assertThat(logged).filteredOn(record -> record.getLevel() == Level.SEVERE).isNotEmpty();
        assertThat(logged).filteredOn(record -> record.getLevel() == Level.WARNING)
                .anySatisfy(record -> assertThat(record.getMessage()).contains("alice", CONNECTION_ID));
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

    @Test
    void acceptsTeamCityPrefixedBuildTypeId() throws Exception {
        connectionWithDimensions(Set.of());
        requestFor("buildType:" + BUILD_TYPE_EXTERNAL_ID);

        assertThat(claimsOf(factory.requestCredentials(project, descriptor)).getSubject())
                .isEqualTo("project:project7:build_type:bt42");
    }

    @Test
    void blankBuildTypeIdIsTreatedAsAbsent() throws Exception {
        connectionWithDimensions(Set.of("connection"));
        requestFor("   ");

        assertThat(claimsOf(factory.requestCredentials(project, descriptor)).getSubject())
                .isEqualTo("connection_project:project3:connection:octopus-oidc:project:project7");
    }

    @Test
    void templateIdIsRefusedWithATemplateMessage() {
        requestFor("Deployments_Template");
        final var template = mock(BuildTypeTemplate.class);
        when(template.getProjectId()).thenReturn("project7");
        when(projectManager.findBuildTypeByExternalId("Deployments_Template")).thenReturn(null);
        when(projectManager.findBuildTypeTemplateByExternalId("Deployments_Template")).thenReturn(template);

        assertThatThrownBy(() -> factory.requestCredentials(project, descriptor))
                .isInstanceOf(ConnectionCredentialsException.class)
                .hasMessage("'Deployments_Template' is a template; an OIDC token can only be issued for a build configuration.");
    }

    @Test
    void templateInAProjectTheCallerCannotEditIsNotIdentified() {
        requestFor("Secrets_Template");
        final var template = mock(BuildTypeTemplate.class);
        when(template.getProjectId()).thenReturn("project9");
        when(authorityHolder.isPermissionGrantedForProject("project9", Permission.EDIT_PROJECT)).thenReturn(false);
        when(projectManager.findBuildTypeByExternalId("Secrets_Template")).thenReturn(null);
        when(projectManager.findBuildTypeTemplateByExternalId("Secrets_Template")).thenReturn(template);

        assertThatThrownBy(() -> factory.requestCredentials(project, descriptor))
                .isInstanceOf(ConnectionCredentialsException.class)
                .hasMessage(notFoundOrNoPermission("Secrets_Template"));
    }

    @Test
    void unknownBuildTypeIsReported() {
        requestFor("Nope");

        assertThatThrownBy(() -> factory.requestCredentials(project, descriptor))
                .isInstanceOf(ConnectionCredentialsException.class)
                .hasMessage(notFoundOrNoPermission("Nope"));
    }

    @Test
    void requestCannotOverrideStoredSettings() throws Exception {
        connectionWithDimensions(Set.of());
        when(descriptor.getParameters()).thenReturn(Map.of(
                OidcConnectionCredentialsFactory.BUILD_TYPE_ID_PARAM, BUILD_TYPE_EXTERNAL_ID,
                "audience", "https://attacker.example.com",
                "algorithm", "ES256",
                "subject_dimensions", "branch,trigger_type",
                "ttl_minutes", "60"));

        final var credentials = factory.requestCredentials(project, descriptor);

        final var claims = claimsOf(credentials);
        assertThat(claims.getAudience()).containsExactly("api://octopus");
        assertThat(SignedJWT.parse(credentials.getProperties().get(OidcConnectionCredentialsFactory.ID_TOKEN))
                .getHeader().getAlgorithm().getName()).isEqualTo("RS256");
        assertThat(claims.getSubject()).isEqualTo("project:project7:build_type:bt42");
        assertThat(Duration.between(claims.getIssueTime().toInstant(), claims.getExpirationTime().toInstant()))
                .isEqualTo(Duration.ofMinutes(1));
    }

    @Test
    void refusedWhenTheIssuerUrlIsNotHttps() {
        connectionWithDimensions(Set.of());
        requestFor(BUILD_TYPE_EXTERNAL_ID);
        final var insecureServer = mock(SBuildServer.class);
        when(insecureServer.getRootUrl()).thenReturn("http://teamcity.example.com");
        final var insecureFactory = new OidcConnectionCredentialsFactory(extensionHolder, connectionsManager, keyManager,
                new OidcIssuerUrlProvider(insecureServer, new OidcSettingsManager(tempDir)), projectManager, securityContext);

        assertThatThrownBy(() -> insecureFactory.requestCredentials(project, descriptor))
                .isInstanceOf(ConnectionCredentialsException.class)
                .hasMessage("The TeamCity issuer URL is not HTTPS, so OIDC tokens cannot be issued.");
    }

    @Test
    @SuppressWarnings("deprecation")
    void projectlessRequestIsRefused() {
        assertThatThrownBy(() -> factory.requestCredentials(descriptor))
                .isInstanceOf(ConnectionCredentialsException.class)
                .hasMessage("An OIDC token can only be requested for a project.");
    }

    @Test
    void issuanceIsLoggedWithTheSubjectButNotTheToken() throws Exception {
        connectionWithDimensions(Set.of());
        requestFor(BUILD_TYPE_EXTERNAL_ID);

        final var credentials = factory.requestCredentials(project, descriptor);

        final var token = credentials.getProperties().get(OidcConnectionCredentialsFactory.ID_TOKEN);
        assertThat(logged).filteredOn(record -> record.getLevel() == Level.INFO)
                .anySatisfy(record -> assertThat(record.getMessage())
                        .contains("alice", CONNECTION_ID, "project:project7:build_type:bt42", "api://octopus"));
        assertThat(logged).noneSatisfy(record -> assertThat(record.getMessage()).contains(token));
    }

    @Test
    void refusalIsLoggedAsAWarning() {
        connectionWithDimensions(Set.of());
        requestFor(BUILD_TYPE_EXTERNAL_ID);
        when(authorityHolder.isPermissionGrantedForProject("project7", Permission.EDIT_PROJECT)).thenReturn(false);

        assertThatThrownBy(() -> factory.requestCredentials(project, descriptor))
                .isInstanceOf(ConnectionCredentialsException.class);

        assertThat(logged).filteredOn(record -> record.getLevel() == Level.WARNING)
                .anySatisfy(record -> assertThat(record.getMessage()).contains("alice", CONNECTION_ID, "permission"));
    }

    @Test
    void refusalLogLineCannotBeSplitByTheRequest() {
        requestFor("x\nINFO JWT plugin: issued a forged line\rmore");

        assertThatThrownBy(() -> factory.requestCredentials(project, descriptor))
                .isInstanceOf(ConnectionCredentialsException.class);

        assertThat(logged).filteredOn(record -> record.getLevel() == Level.WARNING)
                .isNotEmpty()
                .allSatisfy(record -> assertThat(record.getMessage()).doesNotContain("\n", "\r"));
    }

    @Test
    void projectScopedTokenIsRefusedWithoutEditProjectOnThePassedProject() {
        connectionWithDimensions(Set.of("connection"));
        requestFor(null);
        when(authorityHolder.isPermissionGrantedForProject("project7", Permission.EDIT_PROJECT)).thenReturn(false);

        assertThatThrownBy(() -> factory.requestCredentials(project, descriptor))
                .isInstanceOf(ConnectionCredentialsException.class)
                .hasMessageContaining("permission to edit project 'Deployments'");
    }

    @Test
    void refusedWhenTheIdResolvesToADifferentConnection() {
        requestFor(BUILD_TYPE_EXTERNAL_ID);
        when(connectionsManager.resolve(project, CONNECTION_ID)).thenReturn(Optional.of(
                new OidcConnection(CONNECTION_ID, "project5", "Octopus",
                        new IssuanceSettings("api://octopus", 30, "RS256", Set.of()), "jwt.token")));

        assertThatThrownBy(() -> factory.requestCredentials(project, descriptor))
                .isInstanceOf(ConnectionCredentialsException.class)
                .hasMessage("OIDC connection 'octopus-oidc' resolves to a different connection from project 'Deployments'.");
    }
}
