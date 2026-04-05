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
        RotationSettingsManager mgr = new RotationSettingsManager(tempDir);
        RotationSettings settings = mgr.load();
        assertThat(settings.enabled()).isTrue();
        assertThat(settings.cronSchedule()).isEqualTo(RotationSettings.DEFAULT_SCHEDULE);
        assertThat(settings.lastRotatedAt()).isNull();
    }

    @Test
    void roundTripsEnabledSettings() {
        RotationSettingsManager mgr = new RotationSettingsManager(tempDir);
        Instant now = Instant.parse("2026-04-04T03:00:00Z");
        mgr.save(new RotationSettings(true, "0 0 2 * * *", now));

        RotationSettings loaded = mgr.load();
        assertThat(loaded.enabled()).isTrue();
        assertThat(loaded.cronSchedule()).isEqualTo("0 0 2 * * *");
        assertThat(loaded.lastRotatedAt()).isEqualTo(now);
    }

    @Test
    void roundTripsNullLastRotatedAt() {
        RotationSettingsManager mgr = new RotationSettingsManager(tempDir);
        mgr.save(new RotationSettings(true, RotationSettings.DEFAULT_SCHEDULE, null));

        RotationSettings loaded = mgr.load();
        assertThat(loaded.lastRotatedAt()).isNull();
    }

    @Test
    void saveIsVisibleAfterReload() {
        RotationSettingsManager mgr = new RotationSettingsManager(tempDir);
        mgr.save(new RotationSettings(true, "0 0 4 * * *", null));
        // new instance, same directory
        RotationSettingsManager mgr2 = new RotationSettingsManager(tempDir);
        assertThat(mgr2.load().cronSchedule()).isEqualTo("0 0 4 * * *");
    }
}
