package com.octopus.teamcity.oidc;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Optional;
import java.util.Set;

/**
 * Composes the {@code sub} claim as a colon-separated key:value string, in the style of
 * GitHub Actions' {@code repo:org/repo:ref:...}. Always includes {@code project}, using the
 * rename-stable internal id; includes {@code build_type} when the token is for one; appends
 * {@code branch} and {@code trigger_type} only when configured, mirroring the Octopus Deploy
 * convention where trust policies match on {@code sub} with wildcards.
 *
 * <p>{@code connection} comes first so {@code connection_project:...:connection:...:*} matches every
 * token issued through the connection; everything before the wildcard is then set by the plugin
 * rather than by build-controlled values such as the branch name. It pairs the connection id with
 * its owning project's internal id because another project's settings can reuse the connection id,
 * but not the internal id.
 *
 * <p>Every issuance path uses this, so their subjects cannot drift apart.
 */
final class SubjectComposer {

    private SubjectComposer() {
    }

    /**
     * @param buildTypeId internal build configuration id, or {@code null} when the token is not for one
     * @param branchName  appended when the {@code branch} dimension is set and this is non-empty
     * @param triggerType appended when the {@code trigger_type} dimension is set
     */
    static @NotNull String compose(@NotNull final Set<String> dimensions,
                                   @NotNull final Optional<OidcConnection> connection,
                                   @NotNull final String projectId,
                                   @Nullable final String buildTypeId,
                                   @NotNull final String branchName,
                                   @NotNull final String triggerType) {
        final var sb = new StringBuilder();
        if (dimensions.contains("connection") && connection.isPresent()) {
            sb.append("connection_project:").append(connection.get().projectId())
                    .append(":connection:").append(connection.get().id()).append(":");
        }
        sb.append("project:").append(projectId);
        if (buildTypeId != null) {
            sb.append(":build_type:").append(buildTypeId);
        }
        if (dimensions.contains("branch") && !branchName.isEmpty()) {
            sb.append(":branch:").append(branchName);
        }
        if (dimensions.contains("trigger_type")) {
            sb.append(":trigger_type:").append(triggerType);
        }
        return sb.toString();
    }
}
