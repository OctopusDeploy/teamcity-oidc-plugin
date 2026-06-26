package com.octopus.teamcity.oidc;

import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.BuildStartContext;
import jetbrains.buildServer.serverSide.BuildStartContextProcessor;
import org.jetbrains.annotations.NotNull;

import java.util.logging.Logger;

/**
 * Binds {@code jwt.token} as a shared parameter on the running build.
 */
public class JwtBuildStartContext implements BuildStartContextProcessor {
    private static final Logger LOG = Logger.getLogger(JwtBuildStartContext.class.getName());

    private final ExtensionHolder extensionHolder;
    private final JwtIssuanceService issuanceService;

    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    public JwtBuildStartContext(@NotNull final ExtensionHolder extensionHolder,
                                @NotNull final JwtIssuanceService issuanceService) {
        this.extensionHolder = extensionHolder;
        this.issuanceService = issuanceService;
    }

    public void register() {
        extensionHolder.registerExtension(BuildStartContextProcessor.class, this.getClass().getName(), this);
        LOG.info("JWT plugin: JwtBuildStartContext registered as BuildStartContextProcessor");
    }

    @Override
    public void updateParameters(@NotNull final BuildStartContext buildStartContext) {
        final var build = buildStartContext.getBuild();
        issuanceService.tokensFor(build).forEach(buildStartContext::addSharedParameter);
    }
}
