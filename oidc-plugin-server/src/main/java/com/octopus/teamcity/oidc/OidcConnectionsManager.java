package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.SProject;
import jetbrains.buildServer.serverSide.oauth.OAuthConnectionsManager;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.List;
import java.util.Optional;

/**
 * Lookups for the plugin's {@link OidcConnectionProvider} connections. Wraps TC's
 * {@link OAuthConnectionsManager} so callers receive typed {@link OidcConnection}s
 * with effective settings (defaults applied, TTL clamped to the server max).
 */
public class OidcConnectionsManager {
    private final OAuthConnectionsManager teamcityOAuth;
    private final OidcIssuerUrlProvider issuerUrlProvider;
    private final OidcSettingsManager settingsManager;

    public OidcConnectionsManager(@NotNull final OAuthConnectionsManager teamcityOAuth,
                                  @NotNull final OidcIssuerUrlProvider issuerUrlProvider,
                                  @NotNull final OidcSettingsManager settingsManager) {
        this.teamcityOAuth = teamcityOAuth;
        this.issuerUrlProvider = issuerUrlProvider;
        this.settingsManager = settingsManager;
    }

    public @NotNull List<OidcConnection> listAvailable(@NotNull final SProject project) {
        final var issuerUrl = issuerUrlProvider.getIssuerUrl();
        final var maxTtl = settingsManager.load().maxTokenLifetimeMinutes();
        return teamcityOAuth.getAvailableConnectionsOfType(project, OidcConnectionProvider.TYPE).stream()
                .map(d -> OidcConnection.fromDescriptor(d, issuerUrl, maxTtl))
                .toList();
    }

    public @NotNull Optional<OidcConnection> resolve(@NotNull final SProject project,
                                                     @Nullable final String connectionId) {
        if (connectionId == null || connectionId.isBlank()) return Optional.empty();
        final var descriptor = teamcityOAuth.findConnectionById(project, connectionId);
        if (descriptor == null) return Optional.empty();
        final var issuerUrl = issuerUrlProvider.getIssuerUrl();
        final var maxTtl = settingsManager.load().maxTokenLifetimeMinutes();
        return Optional.of(OidcConnection.fromDescriptor(descriptor, issuerUrl, maxTtl));
    }
}
