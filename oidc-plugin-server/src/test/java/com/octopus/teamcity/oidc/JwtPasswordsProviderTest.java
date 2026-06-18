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
public class JwtPasswordsProviderTest {

    @Mock
    ExtensionHolder extensionHolder;

    @Mock
    SBuild build;

    @Test
    public void returnsOneMaskedParameterPerFeatureToken() {
        final var issuanceService = mock(JwtIssuanceService.class);
        when(issuanceService.issueAll(build)).thenReturn(new java.util.LinkedHashMap<>(java.util.Map.of(
                "jwt.token", "a.b.c", "second.token", "d.e.f")));

        final var provider = new JwtPasswordsProvider(extensionHolder, issuanceService);

        assertThat(provider.getPasswordParameters(build))
                .extracting(p -> p.getName() + "=" + p.getValue())
                .containsExactlyInAnyOrder("jwt.token=a.b.c", "second.token=d.e.f");
    }

    @Test
    public void returnsEmptyWhenIssuanceServiceReturnsEmpty() {
        final var issuanceService = mock(JwtIssuanceService.class);
        when(issuanceService.issueAll(build)).thenReturn(java.util.Map.of());

        final var provider = new JwtPasswordsProvider(extensionHolder, issuanceService);

        assertThat(provider.getPasswordParameters(build)).isEmpty();
    }
}
