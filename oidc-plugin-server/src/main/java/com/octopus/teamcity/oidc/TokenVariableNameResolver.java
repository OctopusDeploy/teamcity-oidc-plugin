package com.octopus.teamcity.oidc;

import org.jetbrains.annotations.NotNull;

import java.util.Map;
import java.util.Optional;

/**
 * Resolves the effective build-variable name a feature's JWT is emitted into, via the
 * fallback chain: feature override (non-blank {@code token_variable_name}) →
 * connection default → {@link #DEFAULT_VARIABLE_NAME}. Kept pure (no Spring deps) so it can
 * be reused by issuance, save-time validation, and the build-feature description.
 */
public final class TokenVariableNameResolver {

    public static final String DEFAULT_VARIABLE_NAME = "jwt.token";

    private TokenVariableNameResolver() {
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
