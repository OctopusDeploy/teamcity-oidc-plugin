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
    public void describeParametersIncludesAlgorithmAndTtl() {
        final var feature = newFeature("https://teamcity.example.com");
        final var description = feature.describeParameters(Map.of("algorithm", "ES256", "ttl_minutes", "5"));
        assertThat(description).contains("ES256").contains("5m");
    }

    @Test
    public void describeParametersIncludesAudienceWhenPresent() {
        final var feature = newFeature("https://teamcity.example.com");
        final var description = feature.describeParameters(Map.of("audience", "api://my-app"));
        assertThat(description).contains("api://my-app");
    }

    @Test
    public void describeParametersOmitsAudienceWhenBlank() {
        final var feature = newFeature("https://teamcity.example.com");
        final var description = feature.describeParameters(Map.of("algorithm", "RS256", "ttl_minutes", "10"));
        assertThat(description).doesNotContain("aud:");
    }

    @Test
    public void describeParametersDefaultsToRS256AndTenMinutesWhenParamsMissing() {
        final var feature = newFeature("https://teamcity.example.com");
        final var description = feature.describeParameters(Map.of());
        assertThat(description).contains("RS256").contains("10m");
    }
}
