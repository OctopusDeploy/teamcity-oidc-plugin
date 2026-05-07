package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.TriggeredBy;

/**
 * Resolves JWT claim values from a TeamCity build's runtime state.
 * Pure functions: no side effects, no dependencies beyond the inputs.
 */
final class ClaimsResolver {

    private ClaimsResolver() {}

    /**
     * Resolves the branch name for the JWT {@code branch} claim.
     * <p>
     * TeamCity reports default-branch builds as {@code <default>}; this method converts
     * that to the VCS root's actual default branch ref (e.g. {@code refs/heads/master})
     * since {@code <default>} is not meaningful to OIDC consumers.
     *
     * @return the resolved branch name, or empty string if the build has no branch info
     */
    static String resolveBranchName(final SBuild build) {
        final var branch = build.getBranch();
        if (branch == null) return "";
        if (!branch.isDefaultBranch()) return branch.getName();
        final var buildType = build.getBuildType();
        if (buildType == null) return branch.getName();
        return buildType.getVcsRoots().stream()
                .map(r -> r.getProperty("branch"))
                .filter(b -> b != null && !b.isBlank())
                .findFirst()
                .orElse(branch.getName());
    }

    /**
     * Resolves the {@code trigger_type} claim from the build's {@link TriggeredBy} info,
     * preferring categorical signals (snapshot dependency, user) before falling back to
     * the trigger's {@code type} parameter.
     *
     * @return one of {@code snapshotDependency}, {@code user}, the trigger's type
     *         parameter (e.g. {@code vcsTrigger}, {@code schedulingTrigger}), or
     *         {@code unknown} if no signal is available
     */
    static String resolveTriggerType(final TriggeredBy triggeredBy) {
        if (triggeredBy.isTriggeredBySnapshotDependency()) {
            return "snapshotDependency";
        }
        if (triggeredBy.getUser() != null) {
            return "user";
        }
        final var typeParam = triggeredBy.getParameters().get("type");
        if (typeParam != null && !typeParam.isBlank()) {
            return typeParam;
        }
        return "unknown";
    }
}
