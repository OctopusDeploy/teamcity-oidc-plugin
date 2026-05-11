package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.BuildServerAdapter;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.serverSide.SRunningBuild;
import org.jetbrains.annotations.NotNull;

import java.util.logging.Logger;

/**
 * Evicts cached JWTs once their build is no longer running, so the cache doesn't grow
 * unboundedly on a long-lived TeamCity server.
 *
 * <p>The masked-strings set is persisted on the build at start time, so eviction here
 * does not affect masking of the build's stored parameters or log lines.
 */
public class JwtIssuanceCacheLifecycle extends BuildServerAdapter {
    private static final Logger LOG = Logger.getLogger(JwtIssuanceCacheLifecycle.class.getName());

    private final JwtIssuanceService issuanceService;

    public JwtIssuanceCacheLifecycle(@NotNull final SBuildServer buildServer,
                                     @NotNull final JwtIssuanceService issuanceService) {
        this.issuanceService = issuanceService;
        buildServer.addListener(this);
        LOG.info("JWT plugin: JwtIssuanceCacheLifecycle registered");
    }

    @Override
    public void buildFinished(@NotNull final SRunningBuild build) {
        issuanceService.evict(build.getBuildId());
    }

    @Override
    public void buildInterrupted(@NotNull final SRunningBuild build) {
        issuanceService.evict(build.getBuildId());
    }
}
