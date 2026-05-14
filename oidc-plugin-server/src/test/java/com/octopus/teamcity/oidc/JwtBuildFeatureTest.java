package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.BuildTypeIdentity;
import jetbrains.buildServer.serverSide.InvalidProperty;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class JwtBuildFeatureTest {

    @Mock
    private PluginDescriptor pluginDescriptor;

    @Mock
    private BuildTypeIdentity buildTypeOrTemplate;

    @TempDir
    private File tempDir;

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
                providerFor(rootUrl), new OidcSettingsManager(tempDir));
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
        assertThat(description).isEqualTo("sub:project:<project_id>:build_type:<build_type_id>");
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
        assertThat(description).isEqualTo("sub:project:<project_id>:build_type:<build_type_id>:branch:<branch>:trigger_type:<trigger>");
    }

    @Test
    public void describeParametersIncludesOnlyConfiguredDimensions() {
        final var feature = newFeature("https://teamcity.example.com");
        final var description = feature.describeParameters(Map.of("subject_dimensions", "branch"));
        assertThat(description).isEqualTo("sub:project:<project_id>:build_type:<build_type_id>:branch:<branch>");
    }
}
