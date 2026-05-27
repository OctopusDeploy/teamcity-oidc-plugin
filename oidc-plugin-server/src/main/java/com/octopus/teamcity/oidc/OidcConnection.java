package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.oauth.OAuthConnectionDescriptor;
import org.jetbrains.annotations.NotNull;

public record OidcConnection(@NotNull String id,
                             @NotNull String projectId,
                             @NotNull String displayName,
                             @NotNull IssuanceSettings settings) {

    public static @NotNull OidcConnection fromDescriptor(@NotNull final OAuthConnectionDescriptor descriptor,
                                                         @NotNull final String issuerUrl,
                                                         final int maxTtlMinutes) {
        return new OidcConnection(
                descriptor.getId(),
                descriptor.getProjectId(),
                descriptor.getConnectionDisplayName(),
                IssuanceSettings.fromBuildFeatureParams(descriptor.getParameters(), issuerUrl, maxTtlMinutes));
    }
}
