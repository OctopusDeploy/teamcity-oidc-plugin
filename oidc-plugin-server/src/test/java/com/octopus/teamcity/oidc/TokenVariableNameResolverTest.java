package com.octopus.teamcity.oidc;

import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

public class TokenVariableNameResolverTest {

    @Test
    public void usesFeatureOverrideWhenPresent() {
        final var name = TokenVariableNameResolver.resolve(
                Map.of("token_variable_name", "octopus.token"), Optional.empty());
        assertThat(name).isEqualTo("octopus.token");
    }

    @Test
    public void trimsFeatureOverride() {
        final var name = TokenVariableNameResolver.resolve(
                Map.of("token_variable_name", "  octopus.token  "), Optional.empty());
        assertThat(name).isEqualTo("octopus.token");
    }

    @Test
    public void fallsBackToDefaultWhenOverrideBlankAndNoConnection() {
        assertThat(TokenVariableNameResolver.resolve(Map.of("token_variable_name", "   "), Optional.empty()))
                .isEqualTo("jwt.token");
        assertThat(TokenVariableNameResolver.resolve(Map.of(), Optional.empty()))
                .isEqualTo("jwt.token");
    }
}
