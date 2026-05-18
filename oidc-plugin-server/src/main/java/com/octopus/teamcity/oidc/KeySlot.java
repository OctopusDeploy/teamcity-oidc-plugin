package com.octopus.teamcity.oidc;

import com.nimbusds.jose.jwk.JWK;
import org.jetbrains.annotations.NotNull;

import java.time.Instant;
import java.util.Objects;

/**
 * One slot in a {@link JwtKeyManager.KeyMaterial} algorithm position. The {@code activateAt}
 * timestamp is "when this key became eligible to sign" — set when the key was promoted
 * out of pending (or to {@code now} at genesis on a fresh install), preserved unchanged
 * through demotion to retired.
 */
public record KeySlot(@NotNull JWK jwk, @NotNull Instant activateAt) {

    public KeySlot {
        Objects.requireNonNull(jwk, "jwk");
        Objects.requireNonNull(activateAt, "activateAt");
    }

    /**
     * Returns {@code true} iff this slot's {@code activateAt} is at or before {@code now},
     * i.e. the slot is eligible to be the current signer. Used by {@code JwtKeyManager.sign()}
     * to decide whether a pending slot has finished warming up.
     */
    public boolean isActiveAt(@NotNull final Instant now) {
        return !activateAt.isAfter(now);
    }
}
