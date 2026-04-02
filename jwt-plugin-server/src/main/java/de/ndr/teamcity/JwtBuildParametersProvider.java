package de.ndr.teamcity;

import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.parameters.AbstractBuildParametersProvider;
import org.jetbrains.annotations.NotNull;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Tells TC that {@code jwt.token} will be available for builds with the JWT feature:
 * <ul>
 *   <li>In emulation mode (queue / UI validation): returns {@code {"jwt.token": ""}} so TC
 *       doesn't warn about {@code %jwt.token%} being undefined in build steps.</li>
 *   <li>In real-build mode: returns empty map, leaving no competing definition.
 *       The real JWT is injected exclusively via
 *       {@link JwtBuildStartContext#updateParameters} → {@code addSharedParameter},
 *       which is the sole source and therefore wins reliably.</li>
 * </ul>
 */
public class JwtBuildParametersProvider extends AbstractBuildParametersProvider {
    private static final Logger LOG = Logger.getLogger(JwtBuildParametersProvider.class.getName());

    private final ExtensionHolder extensionHolder;

    public JwtBuildParametersProvider(@NotNull ExtensionHolder extensionHolder) {
        this.extensionHolder = extensionHolder;
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
    public Map<String, String> getParameters(@NotNull SBuild build, boolean emulationMode) {
        if (!emulationMode) {
            return Map.of();
        }
        try {
            if (build.getBuildFeaturesOfType("JWT-Plugin").isEmpty()) {
                return Map.of();
            }
        } catch (Exception ignored) {
            return Map.of();
        }
        return Map.of(JwtPasswordsProvider.JWT_PARAMETER_NAME, "");
    }

    @NotNull
    @Override
    public Collection<String> getParametersAvailableOnAgent(@NotNull SBuild build) {
        try {
            if (!build.getBuildFeaturesOfType("JWT-Plugin").isEmpty()) {
                return List.of(JwtPasswordsProvider.JWT_PARAMETER_NAME);
            }
        } catch (Exception ignored) {
            // ignore mock build issues
        }
        return List.of();
    }
}
