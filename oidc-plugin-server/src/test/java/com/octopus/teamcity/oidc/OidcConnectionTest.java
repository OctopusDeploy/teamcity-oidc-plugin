package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.oauth.OAuthConnectionDescriptor;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OidcConnectionTest {

    @Test
    public void fromDescriptorMapsAllFields() {
        final var descriptor = mock(OAuthConnectionDescriptor.class);
        when(descriptor.getId()).thenReturn("PROJECT_EXT_OAuth_42");
        when(descriptor.getProjectId()).thenReturn("MyProject");
        when(descriptor.getConnectionDisplayName()).thenReturn("Octopus production");
        when(descriptor.getParameters()).thenReturn(Map.of(
                "audience", "api://octopus",
                "ttl_minutes", "20",
                "algorithm", "ES256",
                "subject_dimensions", "branch"));

        final var connection = OidcConnection.fromDescriptor(descriptor, "https://teamcity.example.com", 720);

        assertThat(connection.id()).isEqualTo("PROJECT_EXT_OAuth_42");
        assertThat(connection.projectId()).isEqualTo("MyProject");
        assertThat(connection.displayName()).isEqualTo("Octopus production");
        assertThat(connection.settings().audience()).isEqualTo("api://octopus");
        assertThat(connection.settings().ttlMinutes()).isEqualTo(20);
        assertThat(connection.settings().signingAlgorithm()).isEqualTo("ES256");
        assertThat(connection.settings().subjectDimensions()).containsExactly("branch");
    }

    @Test
    public void fromDescriptorAppliesDefaultsForMissingFields() {
        final var descriptor = mock(OAuthConnectionDescriptor.class);
        when(descriptor.getId()).thenReturn("c1");
        when(descriptor.getProjectId()).thenReturn("p1");
        when(descriptor.getConnectionDisplayName()).thenReturn("Defaults");
        when(descriptor.getParameters()).thenReturn(Map.of());

        final var connection = OidcConnection.fromDescriptor(descriptor, "https://issuer", 720);

        assertThat(connection.settings().audience()).isEqualTo("https://issuer");
        assertThat(connection.settings().ttlMinutes()).isEqualTo(10);
        assertThat(connection.settings().signingAlgorithm()).isEqualTo("RS256");
        assertThat(connection.settings().subjectDimensions()).isEmpty();
    }
}
