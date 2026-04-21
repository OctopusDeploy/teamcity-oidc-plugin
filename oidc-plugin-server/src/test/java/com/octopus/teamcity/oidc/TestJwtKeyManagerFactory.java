package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.serverSide.ServerPaths;
import jetbrains.buildServer.serverSide.crypt.EncryptionKeysStorage;
import jetbrains.buildServer.serverSide.crypt.impl.CustomKeyEncryption;
import org.jetbrains.annotations.NotNull;

import java.util.Map;

import static org.mockito.Mockito.mock;

class TestJwtKeyManagerFactory {
    private static final String KEY_ID = "0".repeat(32);
    private static final byte[] KEY    = new byte[16];
    private static final Map<String, byte[]> KEYS = Map.of(KEY_ID, KEY);

    static JwtKeyManager create(@NotNull final ServerPaths serverPaths) {
        return create(serverPaths, mock(SBuildServer.class));
    }

    static JwtKeyManager create(@NotNull final ServerPaths serverPaths, @NotNull final SBuildServer buildServer) {
        final var customKeyEncryption = new CustomKeyEncryption(new EncryptionKeysStorage() {
            @Override public Map<String, byte[]> getKeys() { return KEYS; }
            @Override public @NotNull String getDefaultKeyId() { return KEY_ID; }
            @Override public void reloadSettings() {}
        });
        final var manager = new JwtKeyManager(serverPaths, customKeyEncryption, buildServer);
        manager.serverStartup();
        if (!manager.isReady()) throw new RuntimeException(
                "JwtKeyManager failed to initialize in test — see log for details");
        return manager;
    }
}
