package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.SBuildServer;
import org.jetbrains.annotations.NotNull;

import java.util.Optional;

public class OidcIssuerUrlProvider {

    private final SBuildServer buildServer;
    private final OidcSettingsManager settingsManager;

    public OidcIssuerUrlProvider(@NotNull final SBuildServer buildServer,
                                 @NotNull final OidcSettingsManager settingsManager) {
        this.buildServer = buildServer;
        this.settingsManager = settingsManager;
    }

    public @NotNull String getIssuerUrl() {
        return loadOverride()
                .orElseGet(() -> OidcUrlUtils.normalizeRootUrl(buildServer.getRootUrl()));
    }

    public @NotNull Optional<String> getOverrideUrl() {
        return loadOverride();
    }

    private Optional<String> loadOverride() {
        return settingsManager.load().map(OidcUrlUtils::normalizeRootUrl);
    }
}
