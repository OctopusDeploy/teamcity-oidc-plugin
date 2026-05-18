package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.ServerPaths;
import jetbrains.buildServer.serverSide.crypt.Encryption;
import jetbrains.buildServer.serverSide.crypt.EncryptionKeysStorage;
import jetbrains.buildServer.serverSide.crypt.impl.CustomKeyEncryption;
import org.jetbrains.annotations.NotNull;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Map;

class TestJwtKeyManagerFactory {
    private static final String KEY_ID = "0".repeat(32);
    private static final byte[] KEY    = new byte[16];
    private static final Map<String, byte[]> KEYS = Map.of(KEY_ID, KEY);

    static JwtKeyManager create(@NotNull final ServerPaths serverPaths) {
        return create(serverPaths, Clock.systemUTC());
    }

    static JwtKeyManager create(@NotNull final ServerPaths serverPaths, @NotNull final Clock clock) {
        final var manager = new JwtKeyManager(serverPaths, testEncryption(), clock);
        manager.notifyTeamCityServerStartupCompleted();
        if (!manager.isReady()) throw new RuntimeException(
                "JwtKeyManager failed to initialize in test — see log for details");
        return manager;
    }

    static Encryption testEncryption() {
        return new CustomKeyEncryption(new EncryptionKeysStorage() {
            @Override public Map<String, byte[]> getKeys() { return KEYS; }
            @Override public @NotNull String getDefaultKeyId() { return KEY_ID; }
            @Override public void reloadSettings() {}
        });
    }

    /**
     * Test-only Clock that lets the test advance time deterministically.
     * <p>
     * Cleaner than the previous {@code __testOverridePendingActivateAt} back-door because
     * the production class has no test-specific code and the test fully controls
     * which {@code now} each query observes.
     */
    static class MutableClock extends Clock {
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
}
