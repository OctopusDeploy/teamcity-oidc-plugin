package com.octopus.teamcity.oidc;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;

import static org.assertj.core.api.Assertions.assertThat;

public class OidcSettingsManagerTest {

    @TempDir File tempDir;

    @Test
    void returnsEmptyWhenFileAbsent() {
        final var mgr = new OidcSettingsManager(tempDir);
        assertThat(mgr.load()).isEmpty();
    }

    @Test
    void roundTripsOverrideUrl() {
        final var mgr = new OidcSettingsManager(tempDir);
        mgr.save("https://ci.example.com");
        assertThat(mgr.load()).contains("https://ci.example.com");
    }

    @Test
    void clearingOverrideReturnsEmpty() {
        final var mgr = new OidcSettingsManager(tempDir);
        mgr.save("https://ci.example.com");
        mgr.save(null);
        assertThat(mgr.load()).isEmpty();
        assertThat(new File(tempDir, "oidc-settings.json")).exists();
    }

    @Test
    void clearingWithBlankStringReturnsEmpty() {
        final var mgr = new OidcSettingsManager(tempDir);
        mgr.save("https://ci.example.com");
        mgr.save("   ");
        assertThat(mgr.load()).isEmpty();
    }

    @Test
    void jsonNullValueReturnsEmpty() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        Files.writeString(new File(tempDir, "oidc-settings.json").toPath(),
                "{\"overrideIssuerUrl\":null}");
        assertThat(mgr.load()).isEmpty();
    }

    @Test
    void malformedJsonReturnsEmpty() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        Files.writeString(new File(tempDir, "oidc-settings.json").toPath(), "not json at all");
        assertThat(mgr.load()).isEmpty();
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void saveRestrictsFilePermissionsTo0600() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        mgr.save("https://ci.example.com");
        final var perms = Files.getPosixFilePermissions(
                new File(tempDir, "oidc-settings.json").toPath());
        assertThat(perms).containsExactlyInAnyOrder(
                PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
    }
}
