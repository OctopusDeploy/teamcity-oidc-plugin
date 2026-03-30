package de.ndr.teamcity;

import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.parameters.ParametersProvider;
import jetbrains.buildServer.serverSide.Parameter;
import jetbrains.buildServer.serverSide.SBuild;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collection;

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
        ParametersProvider parametersProvider = mock(ParametersProvider.class);
        when(parametersProvider.get("jwt.token")).thenReturn("a.b.c");
        when(build.getParametersProvider()).thenReturn(parametersProvider);

        JwtPasswordsProvider provider = new JwtPasswordsProvider(extensionHolder);
        Collection<Parameter> passwords = provider.getPasswordParameters(build);

        assertThat(passwords).hasSize(1);
        Parameter param = passwords.iterator().next();
        assertThat(param.getName()).isEqualTo("jwt.token");
        assertThat(param.getValue()).isEqualTo("a.b.c");
    }

    @Test
    public void returnsEmptyWhenJwtTokenNotPresent() {
        ParametersProvider parametersProvider = mock(ParametersProvider.class);
        when(parametersProvider.get("jwt.token")).thenReturn(null);
        when(build.getParametersProvider()).thenReturn(parametersProvider);

        JwtPasswordsProvider provider = new JwtPasswordsProvider(extensionHolder);
        Collection<Parameter> passwords = provider.getPasswordParameters(build);

        assertThat(passwords).isEmpty();
    }
}
