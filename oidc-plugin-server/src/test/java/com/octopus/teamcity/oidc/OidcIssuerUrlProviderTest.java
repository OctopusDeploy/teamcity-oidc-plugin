package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.SBuildServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OidcIssuerUrlProviderTest {

    @TempDir File tempDir;

    private SBuildServer serverWithRootUrl(final String url) {
        final var server = mock(SBuildServer.class);
        when(server.getRootUrl()).thenReturn(url);
        return server;
    }

    private OidcSettingsManager managerWithOverride(final String override) {
        final var mgr = new OidcSettingsManager(tempDir);
        mgr.saveOverrideIssuerUrl(override);
        return mgr;
    }

    private OidcSettingsManager managerWithNoOverride() {
        return new OidcSettingsManager(tempDir);
    }

    @Test
    void returnsNormalizedRootUrlWhenNoOverride() {
        final var provider = new OidcIssuerUrlProvider(
                serverWithRootUrl("https://tc.internal/"), managerWithNoOverride());
        assertThat(provider.getIssuerUrl()).isEqualTo("https://tc.internal");
    }

    @Test
    void returnsNormalizedOverrideWhenSet() {
        final var provider = new OidcIssuerUrlProvider(
                serverWithRootUrl("https://tc.internal/"),
                managerWithOverride("https://ci.example.com/"));
        assertThat(provider.getIssuerUrl()).isEqualTo("https://ci.example.com");
    }

    @Test
    void overrideTrailingSlashIsStripped() {
        final var provider = new OidcIssuerUrlProvider(
                serverWithRootUrl("https://tc.internal"),
                managerWithOverride("https://ci.example.com///"));
        assertThat(provider.getIssuerUrl()).isEqualTo("https://ci.example.com");
    }

    @Test
    void fallsBackToRootUrlWhenOverrideCleared() {
        final var mgr = managerWithOverride("https://ci.example.com");
        mgr.saveOverrideIssuerUrl(null);
        final var provider = new OidcIssuerUrlProvider(serverWithRootUrl("https://tc.internal"), mgr);
        assertThat(provider.getIssuerUrl()).isEqualTo("https://tc.internal");
    }

    @Test
    void getOverrideUrlReturnsEmptyWhenNotSet() {
        final var provider = new OidcIssuerUrlProvider(
                serverWithRootUrl("https://tc.internal"), managerWithNoOverride());
        assertThat(provider.getOverrideUrl()).isEmpty();
    }

    @Test
    void getOverrideUrlReturnsNormalizedOverrideWhenSet() {
        final var provider = new OidcIssuerUrlProvider(
                serverWithRootUrl("https://tc.internal"),
                managerWithOverride("https://ci.example.com/"));
        assertThat(provider.getOverrideUrl()).contains("https://ci.example.com");
    }
}
