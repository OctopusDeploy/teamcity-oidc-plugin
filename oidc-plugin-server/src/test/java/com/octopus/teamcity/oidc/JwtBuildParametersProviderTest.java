package com.octopus.teamcity.oidc;

import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.SBuildFeatureDescriptor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class JwtBuildParametersProviderTest {

    @Mock ExtensionHolder extensionHolder;
    @Mock SBuild build;
    @Mock SBuildFeatureDescriptor featureDescriptor;

    @Test
    public void returnsEmptyMapInRealBuildMode() {
        var provider = new JwtBuildParametersProvider(extensionHolder);
        assertThat(provider.getParameters(build, false)).isEmpty();
    }

    @Test
    public void returnsEmptyMapInEmulationModeWhenFeatureAbsent() {
        when(build.getBuildFeaturesOfType(JwtBuildFeature.FEATURE_TYPE)).thenReturn(List.of());
        var provider = new JwtBuildParametersProvider(extensionHolder);
        assertThat(provider.getParameters(build, true)).isEmpty();
    }

    @Test
    public void returnsPlaceholderInEmulationModeWhenFeaturePresent() {
        when(build.getBuildFeaturesOfType(JwtBuildFeature.FEATURE_TYPE)).thenReturn(List.of(featureDescriptor));
        var provider = new JwtBuildParametersProvider(extensionHolder);
        assertThat(provider.getParameters(build, true))
                .containsEntry(JwtPasswordsProvider.JWT_PARAMETER_NAME, "");
    }

    @Test
    public void advertisesParameterAsAvailableOnAgentWhenFeaturePresent() {
        when(build.getBuildFeaturesOfType(JwtBuildFeature.FEATURE_TYPE)).thenReturn(List.of(featureDescriptor));
        var provider = new JwtBuildParametersProvider(extensionHolder);
        assertThat(provider.getParametersAvailableOnAgent(build))
                .containsExactly(JwtPasswordsProvider.JWT_PARAMETER_NAME);
    }

    @Test
    public void doesNotAdvertiseParameterOnAgentWhenFeatureAbsent() {
        when(build.getBuildFeaturesOfType(JwtBuildFeature.FEATURE_TYPE)).thenReturn(List.of());
        var provider = new JwtBuildParametersProvider(extensionHolder);
        assertThat(provider.getParametersAvailableOnAgent(build)).isEmpty();
    }
}
