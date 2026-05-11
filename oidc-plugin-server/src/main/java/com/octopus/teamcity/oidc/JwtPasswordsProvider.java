package com.octopus.teamcity.oidc;

import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.Parameter;
import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.SimpleParameter;
import jetbrains.buildServer.serverSide.parameters.types.PasswordsProvider;
import org.jetbrains.annotations.NotNull;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Tells TeamCity that {@code jwt.token} (and any value resolving to it, like
 * {@code env.ARM_OIDC_TOKEN=%jwt.token%}) must be masked. TC's
 * {@code PasswordsBuildStartContextProcessor} runs before our {@link JwtBuildStartContext},
 * so we cannot rely on {@code jwt.token} already being a build parameter at this point —
 * we ask {@link JwtIssuanceService} to issue (and cache) the JWT here, and
 * {@link JwtBuildStartContext} then binds the same cached value as the shared parameter.
 */
public class JwtPasswordsProvider implements PasswordsProvider {

    static final String JWT_PARAMETER_NAME = "jwt.token";

    private final ExtensionHolder extensionHolder;
    private final JwtIssuanceService issuanceService;

    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    public JwtPasswordsProvider(@NotNull final ExtensionHolder extensionHolder,
                                @NotNull final JwtIssuanceService issuanceService) {
        this.extensionHolder = extensionHolder;
        this.issuanceService = issuanceService;
    }

    public void register() {
        extensionHolder.registerExtension(PasswordsProvider.class, this.getClass().getName(), this);
    }

    @NotNull
    @Override
    public Collection<Parameter> getPasswordParameters(@NotNull final SBuild build) {
        return issuanceService.issueOrGet(build)
                .<Collection<Parameter>>map(jwt -> List.of(new SimpleParameter(JWT_PARAMETER_NAME, jwt)))
                .orElse(Collections.emptyList());
    }
}
