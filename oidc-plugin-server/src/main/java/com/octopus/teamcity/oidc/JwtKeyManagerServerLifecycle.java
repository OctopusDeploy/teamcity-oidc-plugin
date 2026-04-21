package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.BuildServerAdapter;
import jetbrains.buildServer.serverSide.SBuildServer;
import org.jetbrains.annotations.NotNull;

import java.util.logging.Logger;

/**
 * Listens for TC server startup and triggers {@link JwtKeyManager#notifyTeamCityServerStartupCompleted()} once
 * {@code EncryptionManager} has its encryption strategy set and key loading is safe.
 */
public class JwtKeyManagerServerLifecycle extends BuildServerAdapter {
    private static final Logger LOG = Logger.getLogger(JwtKeyManagerServerLifecycle.class.getName());

    private final JwtKeyManager keyManager;

    public JwtKeyManagerServerLifecycle(@NotNull final SBuildServer buildServer,
                                        @NotNull final JwtKeyManager keyManager) {
        this.keyManager = keyManager;
        buildServer.addListener(this);
        LOG.info("JWT plugin: JwtKeyManagerServerLifecycle registered — keys will load on serverStartup");
    }

    @Override
    public void serverStartup() {
        keyManager.notifyTeamCityServerStartupCompleted();
    }
}
