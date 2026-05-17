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
    void loadClampsMaxTokenLifetimeFromCorruptedConfig() throws Exception {
        // Older versions of the plugin allowed values up to a year. If we read a stored
        // config above the current ceiling, load() should clamp it rather than throw.
        final var mgr = new OidcSettingsManager(tempDir);
        Files.writeString(new File(tempDir, "oidc-settings.json").toPath(),
                "{\"maxTokenLifetimeMinutes\":525600}");
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

    @Test
    void savesAndLoadsJwksCacheLifetime() {
        final var manager = new OidcSettingsManager(tempDir);
        manager.saveJwksCacheLifetimeMinutes(15);
        assertThat(manager.load().jwksCacheLifetimeMinutes()).isEqualTo(15);
    }

    @Test
    void missingJwksCacheLifetimeLoadsAsDefault() throws Exception {
        final var file = new File(tempDir, "oidc-settings.json");
        // Pre-upgrade file shape: no jwksCacheLifetimeMinutes key.
        java.nio.file.Files.writeString(file.toPath(),
                "{\"maxTokenLifetimeMinutes\":600}");
        final var manager = new OidcSettingsManager(tempDir);
        assertThat(manager.load().jwksCacheLifetimeMinutes())
                .isEqualTo(OidcSettings.DEFAULT_JWKS_CACHE_LIFETIME_MINUTES);
    }

    @Test
    void invalidJwksCacheLifetimeInJsonFallsBackToDefault() throws Exception {
        final var file = new File(tempDir, "oidc-settings.json");
        java.nio.file.Files.writeString(file.toPath(),
                "{\"jwksCacheLifetimeMinutes\":-5}");
        final var manager = new OidcSettingsManager(tempDir);
        assertThat(manager.load().jwksCacheLifetimeMinutes())
                .isEqualTo(OidcSettings.DEFAULT_JWKS_CACHE_LIFETIME_MINUTES);
    }

    @Test
    void atomicJwksCacheLifetimeSavePreservesOtherFields() {
        final var manager = new OidcSettingsManager(tempDir);
        manager.save(new OidcSettings("https://example", 600, 10));
        manager.saveJwksCacheLifetimeMinutes(20);
        final var loaded = manager.load();
        assertThat(loaded.overrideIssuerUrl()).isEqualTo("https://example");
        assertThat(loaded.maxTokenLifetimeMinutes()).isEqualTo(600);
        assertThat(loaded.jwksCacheLifetimeMinutes()).isEqualTo(20);
    }
}
