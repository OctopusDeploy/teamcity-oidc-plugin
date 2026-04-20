package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.ServerPaths;
import jetbrains.buildServer.serverSide.crypt.EncryptionKeysStorage;
import jetbrains.buildServer.serverSide.crypt.impl.CustomKeyEncryption;
import org.jetbrains.annotations.NotNull;

import java.util.Map;

class TestJwtKeyManagerFactory {
    private static final String KEY_ID = "0".repeat(32);
    private static final byte[] KEY    = new byte[16];
    private static final Map<String, byte[]> KEYS = Map.of(KEY_ID, KEY);

    static JwtKeyManager create(@NotNull final ServerPaths serverPaths) {
        return new JwtKeyManager(serverPaths, new CustomKeyEncryption(new EncryptionKeysStorage() {
            @Override public Map<String, byte[]> getKeys() { return KEYS; }
            @Override public @NotNull String getDefaultKeyId() { return KEY_ID; }
            @Override public void reloadSettings() {}
        }));
    }
}
