package com.octopus.teamcity.oidc;

import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.parameters.AbstractBuildParametersProvider;
import org.jetbrains.annotations.NotNull;

import java.util.Collection;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Tells TC that the configured token variable(s) will be available for builds with the OIDC feature:
 * <ul>
 *   <li>In emulation mode (queue / UI validation): returns a placeholder map so TC
 *       doesn't warn about token variables being undefined in build steps.</li>
 *   <li>In real-build mode: returns empty map, leaving no competing definition.
 *       The real JWTs are injected exclusively via
 *       {@link JwtBuildStartContext#updateParameters} → {@code addSharedParameter},
 *       which is the sole source and therefore wins reliably.</li>
 * </ul>
 */
public class JwtBuildParametersProvider extends AbstractBuildParametersProvider {
    private static final Logger LOG = Logger.getLogger(JwtBuildParametersProvider.class.getName());

    private final ExtensionHolder extensionHolder;
    private final JwtIssuanceService issuanceService;

    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    public JwtBuildParametersProvider(@NotNull final ExtensionHolder extensionHolder,
                                      @NotNull final JwtIssuanceService issuanceService) {
        this.extensionHolder = extensionHolder;
        this.issuanceService = issuanceService;
    }

    public void register() {
        extensionHolder.registerExtension(
                jetbrains.buildServer.serverSide.parameters.BuildParametersProvider.class,
                this.getClass().getName(),
                this);
        LOG.info("JWT plugin: JwtBuildParametersProvider registered");
    }

    @NotNull
    @Override
    public Map<String, String> getParameters(@NotNull final SBuild build, final boolean emulationMode) {
        if (!emulationMode) {
            return Map.of();
        }
        final var names = issuanceService.variableNamesFor(build);
        if (names.isEmpty()) {
            return Map.of();
        }
        final var params = new java.util.LinkedHashMap<String, String>();
        for (final var name : names) {
            params.put(name, "");
        }
        return params;
    }

    @NotNull
    @Override
    public Collection<String> getParametersAvailableOnAgent(@NotNull final SBuild build) {
        return new java.util.ArrayList<>(issuanceService.variableNamesFor(build));
    }
}
