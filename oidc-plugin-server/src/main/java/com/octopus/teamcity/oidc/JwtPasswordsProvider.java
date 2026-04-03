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

public class JwtPasswordsProvider implements PasswordsProvider {

    static final String JWT_PARAMETER_NAME = "jwt.token";

    private final ExtensionHolder extensionHolder;

    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    public JwtPasswordsProvider(@NotNull ExtensionHolder extensionHolder) {
        this.extensionHolder = extensionHolder;
    }

    public void register() {
        extensionHolder.registerExtension(PasswordsProvider.class, this.getClass().getName(), this);
    }

    @NotNull
    @Override
    public Collection<Parameter> getPasswordParameters(@NotNull SBuild build) {
        String value = build.getParametersProvider().get(JWT_PARAMETER_NAME);
        if (value == null) return Collections.emptyList();
        return List.of(new SimpleParameter(JWT_PARAMETER_NAME, value));
    }
}
