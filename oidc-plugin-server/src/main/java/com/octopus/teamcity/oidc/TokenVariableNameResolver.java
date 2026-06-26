package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.SProject;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Map;
import java.util.Optional;

/**
 * Resolves the effective build-variable name a feature's JWT is emitted into, via the
 * fallback chain: feature override (non-blank {@code token_variable_name}) →
 * connection default → {@link #DEFAULT_VARIABLE_NAME}. Shared by issuance, save-time
 * validation, and the build-feature description so they always agree.
 */
public final class TokenVariableNameResolver {

    public static final String DEFAULT_VARIABLE_NAME = "jwt.token";

    private TokenVariableNameResolver() {
    }

    /**
     * Resolves the name for a feature, looking up its {@code connection_id} (if any) against the
     * given project. Used where only the params and project are at hand (validation, emulation).
     */
    public static @NotNull String resolve(@NotNull final Map<String, String> featureParams,
                                          @NotNull final OidcConnectionsManager connections,
                                          @Nullable final SProject project) {
        final var connectionId = featureParams.getOrDefault("connection_id", "").trim();
        final var connection = project == null || connectionId.isBlank()
                ? Optional.<OidcConnection>empty()
                : connections.resolve(project, connectionId);
        return resolve(featureParams, connection);
    }

    public static @NotNull String resolve(@NotNull final Map<String, String> featureParams,
                                          @NotNull final Optional<OidcConnection> connection) {
        final var override = featureParams.getOrDefault("token_variable_name", "").trim();
        if (!override.isBlank()) {
            return override;
        }
        if (connection.isPresent()) {
            final var connectionName = connection.get().tokenVariableName().trim();
            if (!connectionName.isBlank()) {
                return connectionName;
            }
        }
        return DEFAULT_VARIABLE_NAME;
    }
}
