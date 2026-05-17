package com.octopus.teamcity.oidc;

import org.jetbrains.annotations.NotNull;

import java.time.Instant;

/**
 * Thrown by {@link JwtKeyManager#rotateKey()} when a previous rotation is still
 * in its warmup window (i.e. at least one algorithm has a pending slot whose
 * {@code activateAt} hasn't been reached yet). Caught by
 * {@link KeyRotationController} to return an HTTP 409, and by
 * {@link KeyRotationScheduler} to log + skip the cron tick.
 *
 * <p>Why this is a sentinel exception and not a boolean return: rotation has
 * multiple failure modes (key generation, encryption, disk I/O) which need to
 * propagate as exceptions anyway, and a boolean would force every caller to
 * branch on both the boolean and the exception. A typed sentinel keeps the
 * caller code one-branch.
 */
public class PendingRotationInProgressException extends RuntimeException {

    private final Instant pendingActivateAt;

    public PendingRotationInProgressException(@NotNull final Instant pendingActivateAt) {
        super("A previous key rotation is still in its warmup window — pending key will become "
                + "active at " + pendingActivateAt + ". Wait for the warmup to elapse before "
                + "rotating again.");
        this.pendingActivateAt = pendingActivateAt;
    }

    public @NotNull Instant getPendingActivateAt() {
        return pendingActivateAt;
    }
}
