package com.octopus.teamcity.oidc;

import org.jetbrains.annotations.NotNull;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/**
 * Test-only Clock. Advance via {@link #setTo} or {@link #advanceBy} to drive
 * time-dependent code deterministically.
 */
class MutableClock extends Clock {
    private volatile Instant instant;

    MutableClock(@NotNull final Instant initial) {
        this.instant = initial;
    }

    @Override public Instant instant() { return instant; }
    @Override public ZoneId getZone() { return ZoneOffset.UTC; }
    @Override public Clock withZone(final ZoneId zone) { return this; }

    void setTo(@NotNull final Instant newInstant) { this.instant = newInstant; }
    void advanceBy(@NotNull final Duration delta) { this.instant = this.instant.plus(delta); }
}
