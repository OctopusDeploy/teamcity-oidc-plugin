package com.octopus.teamcity.oidc;

import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.parameters.ParametersProvider;
import jetbrains.buildServer.serverSide.SBuild;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class JwtPasswordsProviderTest {

    @Mock
    ExtensionHolder extensionHolder;

    @Mock
    SBuild build;

    @Test
    public void returnsJwtTokenAsPasswordParameterWhenPresent() {
        final var parametersProvider = mock(ParametersProvider.class);
        when(parametersProvider.get("jwt.token")).thenReturn("a.b.c");
        when(build.getParametersProvider()).thenReturn(parametersProvider);

        final var provider = new JwtPasswordsProvider(extensionHolder);
        final var passwords = provider.getPasswordParameters(build);

        assertThat(passwords)
                .singleElement()
                .satisfies(p -> {
                    assertThat(p.getName()).isEqualTo("jwt.token");
                    assertThat(p.getValue()).isEqualTo("a.b.c");
                });
    }

    @Test
    public void returnsEmptyWhenJwtTokenNotPresent() {
        final var parametersProvider = mock(ParametersProvider.class);
        when(parametersProvider.get("jwt.token")).thenReturn(null);
        when(build.getParametersProvider()).thenReturn(parametersProvider);

        final var provider = new JwtPasswordsProvider(extensionHolder);
        final var passwords = provider.getPasswordParameters(build);

        assertThat(passwords).isEmpty();
    }
}
