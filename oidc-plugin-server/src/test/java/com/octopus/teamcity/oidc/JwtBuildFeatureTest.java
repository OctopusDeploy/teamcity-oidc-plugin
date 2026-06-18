package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.BuildTypeIdentity;
import jetbrains.buildServer.serverSide.InvalidProperty;
import jetbrains.buildServer.serverSide.ProjectManager;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class JwtBuildFeatureTest {

    @Mock private PluginDescriptor pluginDescriptor;
    @Mock private BuildTypeIdentity buildTypeOrTemplate;
    @Mock private OidcConnectionsManager oidcConnectionsManager;
    @Mock private jetbrains.buildServer.serverSide.SBuildType buildType;
    @Mock private jetbrains.buildServer.serverSide.SProject project;
    @Mock private jetbrains.buildServer.serverSide.SProject rootProject;
    @Mock private ProjectManager projectManager;

    @TempDir
    private File tempDir;

    private static final String CONNECTION_ID = "octopus-prod-connection";
    private static final String CONNECTION_PROJECT_ID = "OctopusProject";

    private JwtBuildFeature feature;

    @BeforeEach
    void setUp() {
        lenient().when(buildType.getProject()).thenReturn(project);
        lenient().when(oidcConnectionsManager.resolve(project, CONNECTION_ID))
                .thenReturn(Optional.of(new OidcConnection(CONNECTION_ID, CONNECTION_PROJECT_ID, "Octopus prod",
                        new IssuanceSettings("api://audience", 10, "RS256", Set.of()), "jwt.token")));
        final var buildServer = buildServerWithRootUrl("https://teamcity.example.com");
        lenient().when(buildServer.getProjectManager()).thenReturn(projectManager);
        lenient().when(projectManager.getRootProject()).thenReturn(rootProject);
        lenient().when(projectManager.getProjects()).thenReturn(List.of(rootProject));
        feature = new JwtBuildFeature(pluginDescriptor, buildServer,
                providerFor("https://teamcity.example.com"), new OidcSettingsManager(tempDir),
                oidcConnectionsManager);
    }

    private SBuildServer buildServerWithRootUrl(final String url) {
        final var server = mock(SBuildServer.class);
        lenient().when(server.getRootUrl()).thenReturn(url);
        return server;
    }

    private OidcIssuerUrlProvider providerFor(final String issuerUrl) {
        return new OidcIssuerUrlProvider(buildServerWithRootUrl(issuerUrl), new OidcSettingsManager(tempDir));
    }

    private JwtBuildFeature newFeature(final String rootUrl) {
        return new JwtBuildFeature(pluginDescriptor, buildServerWithRootUrl(rootUrl),
                providerFor(rootUrl), new OidcSettingsManager(tempDir), mock(OidcConnectionsManager.class));
    }

    @Test
    public void validationRejectsHttpRootUrl() {
        final var feature = newFeature("http://teamcity.example.com");
        final var processor = feature.getParametersProcessor(buildTypeOrTemplate);
        assertThat(processor).isNotNull();
        final var errors = processor.process(Map.of());

        assertThat(errors)
                .singleElement()
                .satisfies(e -> assertThat(e.getInvalidReason()).contains("HTTPS"));
    }

    @Test
    public void validationAcceptsHttpsRootUrl() {
        final var feature = newFeature("https://teamcity.example.com");
        final var processor = feature.getParametersProcessor(buildTypeOrTemplate);
        assertThat(processor).isNotNull();
        final var errors = processor.process(Map.of());

        assertThat(errors).isEmpty();
    }

    @Test
    public void validationRejectsNonNumericTtl() {
        final var feature = newFeature("https://teamcity.example.com");
        final var processor = feature.getParametersProcessor(buildTypeOrTemplate);
        assertThat(processor).isNotNull();
        final var errors = processor.process(Map.of("ttl_minutes", "notanumber"));

        assertThat(errors)
                .singleElement()
                .extracting(InvalidProperty::getPropertyName)
                .isEqualTo("ttl_minutes");
    }

    @Test
    public void validationRejectsNonPositiveTtl() {
        final var feature = newFeature("https://teamcity.example.com");
        final var processor = feature.getParametersProcessor(buildTypeOrTemplate);
        assertThat(processor).isNotNull();
        final var errors = processor.process(Map.of("ttl_minutes", "0"));

        assertThat(errors)
                .singleElement()
                .extracting(InvalidProperty::getPropertyName)
                .isEqualTo("ttl_minutes");
    }

    @Test
    public void validationRejectsTtlAboveMaximum() {
        final var feature = newFeature("https://teamcity.example.com");
        final var processor = feature.getParametersProcessor(buildTypeOrTemplate);
        assertThat(processor).isNotNull();
        final var errors = processor.process(Map.of("ttl_minutes",
                String.valueOf(OidcSettings.DEFAULT_MAX_TOKEN_LIFETIME_MINUTES + 1)));

        assertThat(errors)
                .singleElement()
                .extracting(InvalidProperty::getPropertyName)
                .isEqualTo("ttl_minutes");
    }

    @Test
    public void validationAcceptsMaximumTtl() {
        final var feature = newFeature("https://teamcity.example.com");
        final var processor = feature.getParametersProcessor(buildTypeOrTemplate);
        assertThat(processor).isNotNull();
        final var errors = processor.process(Map.of("ttl_minutes",
                String.valueOf(OidcSettings.DEFAULT_MAX_TOKEN_LIFETIME_MINUTES)));

        assertThat(errors).isEmpty();
    }

    @Test
    public void validationAcceptsBlankSubjectDimensions() {
        final var feature = newFeature("https://teamcity.example.com");
        final var processor = feature.getParametersProcessor(buildTypeOrTemplate);
        assertThat(processor.process(Map.of("subject_dimensions", ""))).isEmpty();
        assertThat(processor.process(Map.of())).isEmpty();
    }

    @Test
    public void validationAcceptsKnownSubjectDimensions() {
        final var feature = newFeature("https://teamcity.example.com");
        final var processor = feature.getParametersProcessor(buildTypeOrTemplate);
        assertThat(processor.process(Map.of("subject_dimensions", "branch"))).isEmpty();
        assertThat(processor.process(Map.of("subject_dimensions", "trigger_type"))).isEmpty();
        assertThat(processor.process(Map.of("subject_dimensions", "branch,trigger_type"))).isEmpty();
        assertThat(processor.process(Map.of("subject_dimensions", "branch, trigger_type"))).isEmpty();
    }

    @Test
    public void validationRejectsUnknownSubjectDimension() {
        final var feature = newFeature("https://teamcity.example.com");
        final var processor = feature.getParametersProcessor(buildTypeOrTemplate);
        final var errors = processor.process(Map.of("subject_dimensions", "brnach"));

        assertThat(errors)
                .singleElement()
                .extracting(InvalidProperty::getPropertyName)
                .isEqualTo("subject_dimensions");
        assertThat(errors)
                .singleElement()
                .extracting(InvalidProperty::getInvalidReason).asString()
                .contains("brnach")
                .contains("branch")
                .contains("trigger_type");
    }

    @Test
    public void validationRejectsLegacyNoneSentinel() {
        // "none" used to be a valid sentinel meaning "no optional dimensions". After the
        // default flip, leaving the field blank produces the same result, so "none" is now
        // an unknown dimension name and the validator should reject it on save. This nudges
        // direct-edit users to update their config rather than silently doing what they
        // expected but for the wrong reason.
        final var feature = newFeature("https://teamcity.example.com");
        final var processor = feature.getParametersProcessor(buildTypeOrTemplate);
        final var errors = processor.process(Map.of("subject_dimensions", "none"));

        assertThat(errors)
                .singleElement()
                .extracting(InvalidProperty::getPropertyName)
                .isEqualTo("subject_dimensions");
    }

    @Test
    public void describeParametersShowsMinimalSubjectTemplateByDefault() {
        final var feature = newFeature("https://teamcity.example.com");
        final var description = feature.describeParameters(Map.of());
        assertThat(description).isEqualTo("var:jwt.token\nsub:project:<project_id>:build_type:<build_type_id>");
    }

    @Test
    public void describeParametersIncludesAudienceWhenPresent() {
        final var feature = newFeature("https://teamcity.example.com");
        final var description = feature.describeParameters(Map.of("audience", "api://my-app"));
        assertThat(description).contains("aud:api://my-app");
    }

    @Test
    public void describeParametersOmitsAudienceWhenBlank() {
        final var feature = newFeature("https://teamcity.example.com");
        final var description = feature.describeParameters(Map.of("audience", ""));
        assertThat(description).doesNotContain("aud:");
    }

    @Test
    public void describeParametersIncludesAllConfiguredDimensions() {
        final var feature = newFeature("https://teamcity.example.com");
        final var description = feature.describeParameters(Map.of("subject_dimensions", "branch,trigger_type"));
        assertThat(description).isEqualTo("var:jwt.token\nsub:project:<project_id>:build_type:<build_type_id>:branch:<branch>:trigger_type:<trigger_type>");
    }

    @Test
    public void describeParametersIncludesOnlyConfiguredDimensions() {
        final var feature = newFeature("https://teamcity.example.com");
        final var description = feature.describeParameters(Map.of("subject_dimensions", "branch"));
        assertThat(description).isEqualTo("var:jwt.token\nsub:project:<project_id>:build_type:<build_type_id>:branch:<branch>");
    }

    @Test
    public void skipsInlineValidationWhenConnectionIdSet() {
        // ttl_minutes far out of range — would fail inline validation, but is ignored when connection_id is set.
        final var processor = feature.getParametersProcessor(buildType);
        final var errors = processor.process(Map.of(
                "connection_id", CONNECTION_ID,
                "ttl_minutes", "9999",
                "subject_dimensions", "bogus"));

        // The connection resolves successfully (stubbed in setUp).
        assertThat(errors).extracting(InvalidProperty::getPropertyName).doesNotContain("ttl_minutes", "subject_dimensions");
    }

    @Test
    public void reportsInvalidPropertyWhenConnectionIdUnresolvable() {
        when(oidcConnectionsManager.resolve(project, "missing"))
                .thenReturn(java.util.Optional.empty());

        final var errors = feature.getParametersProcessor(buildType).process(Map.of("connection_id", "missing"));

        assertThat(errors).extracting(InvalidProperty::getPropertyName).contains("connection_id");
    }

    @Test
    public void describeParametersShowsConnectionDisplayNameAudienceAndSubject() {
        when(oidcConnectionsManager.resolve(rootProject, CONNECTION_ID))
                .thenReturn(java.util.Optional.of(new OidcConnection(CONNECTION_ID, CONNECTION_PROJECT_ID, "Octopus production",
                        new IssuanceSettings("api://from-conn", 15, "ES256", java.util.Set.of("branch")), "jwt.token")));

        final var description = feature.describeParameters(Map.of("connection_id", CONNECTION_ID));

        assertThat(description).contains("connection: Octopus production");
        assertThat(description).contains("aud:api://from-conn");
        assertThat(description).contains(":branch:<branch>");
    }

    @Test
    public void allowsMultipleFeaturesPerBuildType() {
        final var feature = newFeature("https://teamcity.example.com");
        assertThat(feature.isMultipleFeaturesPerBuildTypeAllowed()).isTrue();
    }

    @Test
    public void rejectsDuplicateVariableNameAcrossFeatures() {
        // Sibling feature already emits "jwt.token" (default, inline).
        final var sibling = mock(jetbrains.buildServer.serverSide.SBuildFeatureDescriptor.class);
        when(sibling.getId()).thenReturn("SIBLING_ID");
        when(sibling.getParameters()).thenReturn(Map.of());
        when(buildType.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(sibling));

        final var processor = feature.getParametersProcessor(buildType);
        final var errors = processor.process(new HashMap<>(Map.of(
                "self_feature_id", "NEW_ID")));  // candidate also resolves to jwt.token

        assertThat(errors).extracting(InvalidProperty::getPropertyName).contains("token_variable_name");
    }

    @Test
    public void allowsDistinctVariableNamesAcrossFeatures() {
        final var sibling = mock(jetbrains.buildServer.serverSide.SBuildFeatureDescriptor.class);
        when(sibling.getId()).thenReturn("SIBLING_ID");
        when(sibling.getParameters()).thenReturn(Map.of()); // jwt.token
        when(buildType.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(sibling));

        final var processor = feature.getParametersProcessor(buildType);
        final var errors = processor.process(new HashMap<>(Map.of(
                "self_feature_id", "NEW_ID",
                "token_variable_name", "other.token")));

        assertThat(errors).extracting(InvalidProperty::getPropertyName).doesNotContain("token_variable_name");
    }

    @Test
    public void doesNotFlagFeatureAgainstItselfOnEdit() {
        // The persisted sibling list contains the feature being edited (same id as self).
        final var self = mock(jetbrains.buildServer.serverSide.SBuildFeatureDescriptor.class);
        when(self.getId()).thenReturn("SELF_ID");
        lenient().when(self.getParameters()).thenReturn(Map.of()); // jwt.token — skipped because self is excluded
        when(buildType.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(self));

        final var processor = feature.getParametersProcessor(buildType);
        final var errors = processor.process(new HashMap<>(Map.of(
                "self_feature_id", "SELF_ID")));  // unchanged name jwt.token, but it's the same feature

        assertThat(errors).extracting(InvalidProperty::getPropertyName).doesNotContain("token_variable_name");
    }

    @Test
    public void stripsSelfFeatureIdFromPersistedProperties() {
        when(buildType.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of());
        final var processor = feature.getParametersProcessor(buildType);
        final var params = new HashMap<>(Map.of("self_feature_id", "NEW_ID"));
        processor.process(params);
        assertThat(params).doesNotContainKey("self_feature_id");
    }

    @Test
    public void describeParametersInlineShowsVariableName() {
        final var feature = newFeature("https://teamcity.example.com");
        assertThat(feature.describeParameters(Map.of("token_variable_name", "octopus.token")))
                .startsWith("var:octopus.token");
        assertThat(feature.describeParameters(Map.of()))
                .startsWith("var:jwt.token");
    }
}
