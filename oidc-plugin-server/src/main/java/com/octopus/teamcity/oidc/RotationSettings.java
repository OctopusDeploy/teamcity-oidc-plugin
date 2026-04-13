package com.octopus.teamcity.oidc;

import org.jetbrains.annotations.Nullable;
import java.time.Instant;

/**
 * Immutable snapshot of auto-rotation configuration.
 * Persisted to rotation-settings.json in the key directory.
 */
public record RotationSettings(
        boolean enabled,
        String cronSchedule,
        @Nullable Instant lastRotatedAt
) {
    static final String DEFAULT_SCHEDULE = "0 0 3 1 */3 *";

    static RotationSettings defaults() {
        return new RotationSettings(true, DEFAULT_SCHEDULE, null);
    }
}
