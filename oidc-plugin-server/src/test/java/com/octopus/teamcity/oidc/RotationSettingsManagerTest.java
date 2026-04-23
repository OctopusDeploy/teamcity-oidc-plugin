package com.octopus.teamcity.oidc;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

public class RotationSettingsManagerTest {

    @TempDir File tempDir;

    @Test
    void returnsDefaultsWhenFileAbsent() {
        final var before = Instant.now();
        final var mgr = new RotationSettingsManager(tempDir);
        final var settings = mgr.load();
        final var after = Instant.now();
        assertThat(settings.enabled()).isTrue();
        assertThat(settings.cronSchedule()).isEqualTo(RotationSettings.DEFAULT_SCHEDULE);
        // lastRotatedAt must not be null on first install — a null value is treated
        // as epoch 0 by the scheduler, causing immediate key rotation on startup.
        assertThat(settings.lastRotatedAt()).isNotNull()
                .isAfterOrEqualTo(before)
                .isBeforeOrEqualTo(after);
    }

    @Test
    void roundTripsEnabledSettings() {
        final var mgr = new RotationSettingsManager(tempDir);
        final var now = Instant.parse("2026-04-04T03:00:00Z");
        final var schedule = "0 0 2 * * *";
        mgr.save(new RotationSettings(true, schedule, now));

        final var loaded = mgr.load();
        assertThat(loaded.enabled()).isTrue();
        assertThat(loaded.cronSchedule()).isEqualTo(schedule);
        assertThat(loaded.lastRotatedAt()).isEqualTo(now);
    }

    @Test
    void roundTripsNullLastRotatedAt() {
        final var mgr = new RotationSettingsManager(tempDir);
        mgr.save(new RotationSettings(true, RotationSettings.DEFAULT_SCHEDULE, null));

        final var loaded = mgr.load();
        assertThat(loaded.lastRotatedAt()).isNull();
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void saveRestrictsFilePermissionsTo0600() throws Exception {
        final var mgr = new RotationSettingsManager(tempDir);
        mgr.save(new RotationSettings(true, RotationSettings.DEFAULT_SCHEDULE, null));

        final var perms = Files.getPosixFilePermissions(
                new File(tempDir, "rotation-settings.json").toPath());
        assertThat(perms).containsExactlyInAnyOrder(
                PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
    }

    @Test
    void saveEnabledAndSchedulePreservesLastRotatedAt() {
        final var mgr = new RotationSettingsManager(tempDir);
        final var original = Instant.parse("2026-01-01T03:00:00Z");
        mgr.save(new RotationSettings(true, RotationSettings.DEFAULT_SCHEDULE, original));

        mgr.save(false, "0 0 4 * * *");

        final var loaded = mgr.load();
        assertThat(loaded.enabled()).isFalse();
        assertThat(loaded.cronSchedule()).isEqualTo("0 0 4 * * *");
        assertThat(loaded.lastRotatedAt()).isEqualTo(original);
    }

    @Test
    void saveIsVisibleAfterReload() {
        final var mgr = new RotationSettingsManager(tempDir);
        mgr.save(new RotationSettings(true, "0 0 4 * * *", null));
        // new instance, same directory
        final var mgr2 = new RotationSettingsManager(tempDir);
        assertThat(mgr2.load().cronSchedule()).isEqualTo("0 0 4 * * *");
    }
}
