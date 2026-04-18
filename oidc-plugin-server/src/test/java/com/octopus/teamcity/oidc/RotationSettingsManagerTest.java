package com.octopus.teamcity.oidc;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

public class RotationSettingsManagerTest {

    @TempDir File tempDir;

    @Test
    void returnsDefaultsWhenFileAbsent() {
        final var mgr = new RotationSettingsManager(tempDir);
        final var settings = mgr.load();
        assertThat(settings.enabled()).isTrue();
        assertThat(settings.cronSchedule()).isEqualTo(RotationSettings.DEFAULT_SCHEDULE);
        assertThat(settings.lastRotatedAt()).isNull();
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
    void saveIsVisibleAfterReload() {
        final var mgr = new RotationSettingsManager(tempDir);
        mgr.save(new RotationSettings(true, "0 0 4 * * *", null));
        // new instance, same directory
        final var mgr2 = new RotationSettingsManager(tempDir);
        assertThat(mgr2.load().cronSchedule()).isEqualTo("0 0 4 * * *");
    }
}
