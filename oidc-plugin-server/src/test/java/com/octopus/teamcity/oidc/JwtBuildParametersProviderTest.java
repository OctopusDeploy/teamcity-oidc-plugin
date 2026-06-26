package com.octopus.teamcity.oidc;

import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.SBuild;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class JwtBuildParametersProviderTest {

    @Mock ExtensionHolder extensionHolder;
    @Mock SBuild build;

    @Test
    public void returnsEmptyMapInRealBuildMode() {
        final var provider = new JwtBuildParametersProvider(extensionHolder, mock(JwtIssuanceService.class));
        assertThat(provider.getParameters(build, false)).isEmpty();
    }

    @Test
    public void returnsEmptyMapInEmulationModeWhenNoVariables() {
        final var issuanceService = mock(JwtIssuanceService.class);
        when(issuanceService.variableNamesFor(build)).thenReturn(java.util.Set.of());
        final var provider = new JwtBuildParametersProvider(extensionHolder, issuanceService);
        assertThat(provider.getParameters(build, true)).isEmpty();
    }

    @Test
    public void returnsPlaceholderPerVariableInEmulationMode() {
        final var issuanceService = mock(JwtIssuanceService.class);
        when(issuanceService.variableNamesFor(build))
                .thenReturn(new java.util.LinkedHashSet<>(java.util.List.of("jwt.token", "second.token")));
        final var provider = new JwtBuildParametersProvider(extensionHolder, issuanceService);
        assertThat(provider.getParameters(build, true))
                .containsOnly(org.assertj.core.api.Assertions.entry("jwt.token", ""),
                              org.assertj.core.api.Assertions.entry("second.token", ""));
    }

    @Test
    public void advertisesEachVariableAsAvailableOnAgent() {
        final var issuanceService = mock(JwtIssuanceService.class);
        when(issuanceService.variableNamesFor(build))
                .thenReturn(new java.util.LinkedHashSet<>(java.util.List.of("jwt.token", "second.token")));
        final var provider = new JwtBuildParametersProvider(extensionHolder, issuanceService);
        assertThat(provider.getParametersAvailableOnAgent(build))
                .containsExactly("jwt.token", "second.token");
    }

    @Test
    public void doesNotAdvertiseAnyVariableWhenNoFeatures() {
        final var issuanceService = mock(JwtIssuanceService.class);
        when(issuanceService.variableNamesFor(build)).thenReturn(java.util.Set.of());
        final var provider = new JwtBuildParametersProvider(extensionHolder, issuanceService);
        assertThat(provider.getParametersAvailableOnAgent(build)).isEmpty();
    }
}
