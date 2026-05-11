package com.octopus.teamcity.oidc;

import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.SBuild;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

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
    public void returnsJwtFromIssuanceServiceAsPasswordParameter() {
        final var issuanceService = mock(JwtIssuanceService.class);
        when(issuanceService.issueOrGet(build)).thenReturn(Optional.of("a.b.c"));

        final var provider = new JwtPasswordsProvider(extensionHolder, issuanceService);

        assertThat(provider.getPasswordParameters(build))
                .singleElement()
                .satisfies(p -> {
                    assertThat(p.getName()).isEqualTo("jwt.token");
                    assertThat(p.getValue()).isEqualTo("a.b.c");
                });
    }

    @Test
    public void returnsEmptyWhenIssuanceServiceReturnsEmpty() {
        final var issuanceService = mock(JwtIssuanceService.class);
        when(issuanceService.issueOrGet(build)).thenReturn(Optional.empty());

        final var provider = new JwtPasswordsProvider(extensionHolder, issuanceService);

        assertThat(provider.getPasswordParameters(build)).isEmpty();
    }
}
