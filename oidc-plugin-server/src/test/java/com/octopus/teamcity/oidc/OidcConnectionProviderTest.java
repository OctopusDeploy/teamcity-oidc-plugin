package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.InvalidProperty;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
public class OidcConnectionProviderTest {

    @Mock PluginDescriptor pluginDescriptor;
    @TempDir File tempDir;

    private OidcConnectionProvider provider;

    @BeforeEach
    void setUp() {
        lenient().when(pluginDescriptor.getPluginResourcesPath("editOidcConnection.jsp"))
                .thenReturn("/plugins/teamcity-oidc-plugin/editOidcConnection.jsp");
        provider = new OidcConnectionProvider(pluginDescriptor, new OidcSettingsManager(tempDir));
    }

    @Test
    public void typeIsOidcIdentityToken() {
        assertThat(provider.getType()).isEqualTo("oidc-identity-token");
    }

    @Test
    public void displayNameIsOidcIdentityToken() {
        assertThat(provider.getDisplayName()).isEqualTo("OIDC Identity Token");
    }

    @Test
    public void editParametersUrlPointsAtJsp() {
        assertThat(provider.getEditParametersUrl())
                .isEqualTo("/plugins/teamcity-oidc-plugin/editOidcConnection.jsp");
    }

    @Test
    public void defaultsIncludeAlgorithmAndTtl() {
        final var defaults = provider.getDefaultProperties();
        assertThat(defaults).containsEntry("algorithm", "RS256");
        assertThat(defaults).containsEntry("ttl_minutes", "10");
    }

    @Test
    public void describeConnectionListsKeyFields() {
        final var description = provider.describeConnection(Map.of(
                "audience", "api://example",
                "ttl_minutes", "20",
                "algorithm", "ES256",
                "subject_dimensions", "branch",
                "token_variable_name", "octopus.token"));
        assertThat(description).contains("aud: api://example");
        assertThat(description).contains("ttl: 20m");
        assertThat(description).contains("alg: ES256");
        assertThat(description).contains("sub: project:<project_id>:build_type:<build_type_id>:branch:<branch>");
        assertThat(description).contains("var: %octopus.token%");
        assertThat(description).contains("\n");
    }

    @Test
    public void propertiesProcessorAcceptsValidValues() {
        final var errors = provider.getPropertiesProcessor().process(validParams());
        assertThat(errors).isEmpty();
    }

    @Test
    public void propertiesProcessorRejectsBlankDisplayName() {
        final var params = validParams();
        params.put("displayName", "  ");
        final var errors = provider.getPropertiesProcessor().process(params);
        assertThat(errors).extracting(InvalidProperty::getPropertyName).contains("displayName");
    }

    @Test
    public void propertiesProcessorRejectsInvalidAlgorithm() {
        final var params = validParams();
        params.put("algorithm", "HS256");
        final var errors = provider.getPropertiesProcessor().process(params);
        assertThat(errors).extracting(InvalidProperty::getPropertyName).contains("algorithm");
    }

    @Test
    public void propertiesProcessorRejectsTtlOutOfRange() {
        final var params = validParams();
        params.put("ttl_minutes", "9999");
        final var errors = provider.getPropertiesProcessor().process(params);
        assertThat(errors).extracting(InvalidProperty::getPropertyName).contains("ttl_minutes");
    }

    @Test
    public void propertiesProcessorRejectsNonIntegerTtl() {
        final var params = validParams();
        params.put("ttl_minutes", "not-a-number");
        final var errors = provider.getPropertiesProcessor().process(params);
        assertThat(errors).extracting(InvalidProperty::getPropertyName).contains("ttl_minutes");
    }

    @Test
    public void propertiesProcessorRejectsUnknownSubjectDimensions() {
        final var params = validParams();
        params.put("subject_dimensions", "branch,bogus");
        final var errors = provider.getPropertiesProcessor().process(params);
        assertThat(errors).extracting(InvalidProperty::getPropertyName).contains("subject_dimensions");
    }

    @Test
    public void propertiesProcessorAllowsBlankAudience() {
        final var params = validParams();
        params.put("audience", "");
        final var errors = provider.getPropertiesProcessor().process(params);
        assertThat(errors).extracting(InvalidProperty::getPropertyName).doesNotContain("audience");
    }

    private static Map<String, String> validParams() {
        final var p = new HashMap<String, String>();
        p.put("displayName", "Octopus production");
        p.put("audience", "api://octopus");
        p.put("ttl_minutes", "20");
        p.put("algorithm", "RS256");
        p.put("subject_dimensions", "branch,trigger_type");
        return p;
    }
}
