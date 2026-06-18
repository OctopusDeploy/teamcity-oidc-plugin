package com.octopus.teamcity.oidc;

import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.Parameter;
import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.SimpleParameter;
import jetbrains.buildServer.serverSide.parameters.types.PasswordsProvider;
import org.jetbrains.annotations.NotNull;

import java.util.Collection;
import java.util.stream.Collectors;

/**
 * Tells TeamCity that the configured token variable(s) must be masked. TC's
 * {@code PasswordsBuildStartContextProcessor} runs before our {@link JwtBuildStartContext},
 * so we cannot rely on the token parameters already being present at this point —
 * we ask {@link JwtIssuanceService} to issue (and cache) the JWTs here, and
 * {@link JwtBuildStartContext} then binds the same cached values as shared parameters.
 */
public class JwtPasswordsProvider implements PasswordsProvider {

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
        return issuanceService.issueAll(build).entrySet().stream()
                .<Parameter>map(e -> new SimpleParameter(e.getKey(), e.getValue()))
                .collect(Collectors.toList());
    }
}
