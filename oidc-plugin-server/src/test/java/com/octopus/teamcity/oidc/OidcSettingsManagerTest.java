package com.octopus.teamcity.oidc;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;

import static org.assertj.core.api.Assertions.assertThat;

public class OidcSettingsManagerTest {

    @TempDir File tempDir;

    @Test
    void returnsDefaultsWhenFileAbsent() {
        final var mgr = new OidcSettingsManager(tempDir);
        final var settings = mgr.load();
        assertThat(settings.findOverrideIssuerUrl()).isEmpty();
        assertThat(settings.maxTokenLifetimeMinutes()).isEqualTo(OidcSettings.DEFAULT_MAX_TOKEN_LIFETIME_MINUTES);
    }

    @Test
    void roundTripsOverrideUrl() {
        final var mgr = new OidcSettingsManager(tempDir);
        mgr.saveOverrideIssuerUrl("https://ci.example.com");
        assertThat(mgr.load().findOverrideIssuerUrl()).contains("https://ci.example.com");
    }

    @Test
    void clearingOverrideReturnsEmpty() {
        final var mgr = new OidcSettingsManager(tempDir);
        mgr.saveOverrideIssuerUrl("https://ci.example.com");
        mgr.saveOverrideIssuerUrl(null);
        assertThat(mgr.load().findOverrideIssuerUrl()).isEmpty();
        assertThat(new File(tempDir, "oidc-settings.json")).exists();
    }

    @Test
    void clearingWithBlankStringReturnsEmpty() {
        final var mgr = new OidcSettingsManager(tempDir);
        mgr.saveOverrideIssuerUrl("https://ci.example.com");
        mgr.saveOverrideIssuerUrl("   ");
        assertThat(mgr.load().findOverrideIssuerUrl()).isEmpty();
    }

    @Test
    void jsonNullValueReturnsEmpty() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        Files.writeString(new File(tempDir, "oidc-settings.json").toPath(),
                "{\"overrideIssuerUrl\":null}");
        assertThat(mgr.load().findOverrideIssuerUrl()).isEmpty();
    }

    @Test
    void malformedJsonReturnsDefaults() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        Files.writeString(new File(tempDir, "oidc-settings.json").toPath(), "not json at all");
        final var settings = mgr.load();
        assertThat(settings.findOverrideIssuerUrl()).isEmpty();
        assertThat(settings.maxTokenLifetimeMinutes()).isEqualTo(OidcSettings.DEFAULT_MAX_TOKEN_LIFETIME_MINUTES);
    }

    @Test
    void roundTripsMaxTokenLifetime() {
        final var mgr = new OidcSettingsManager(tempDir);
        mgr.saveMaxTokenLifetimeMinutes(60);
        assertThat(mgr.load().maxTokenLifetimeMinutes()).isEqualTo(60);
    }

    @Test
    void invalidMaxTokenLifetimeFallsBackToDefault() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        Files.writeString(new File(tempDir, "oidc-settings.json").toPath(),
                "{\"maxTokenLifetimeMinutes\":\"not-a-number\"}");
        assertThat(mgr.load().maxTokenLifetimeMinutes())
                .isEqualTo(OidcSettings.DEFAULT_MAX_TOKEN_LIFETIME_MINUTES);
    }

    @Test
    void maxTokenLifetimeIsClampedToAbsoluteCeiling() {
        final var mgr = new OidcSettingsManager(tempDir);
        mgr.saveMaxTokenLifetimeMinutes(OidcSettings.ABSOLUTE_MAX_TOKEN_LIFETIME_MINUTES + 1_000_000);
        assertThat(mgr.load().maxTokenLifetimeMinutes())
                .isEqualTo(OidcSettings.ABSOLUTE_MAX_TOKEN_LIFETIME_MINUTES);
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void saveRestrictsFilePermissionsTo0600() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        mgr.saveOverrideIssuerUrl("https://ci.example.com");
        final var perms = Files.getPosixFilePermissions(
                new File(tempDir, "oidc-settings.json").toPath());
        assertThat(perms).containsExactlyInAnyOrder(
                PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
    }
}
