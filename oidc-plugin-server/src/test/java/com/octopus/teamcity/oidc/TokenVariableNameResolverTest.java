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

    @Test
    public void usesConnectionDefaultWhenOverrideBlank() {
        final var conn = new OidcConnection("id", "proj", "Display",
                new IssuanceSettings("aud", 10, "RS256", java.util.Set.of()), "conn.token");
        assertThat(TokenVariableNameResolver.resolve(Map.of(), Optional.of(conn)))
                .isEqualTo("conn.token");
    }

    @Test
    public void featureOverrideBeatsConnectionDefault() {
        final var conn = new OidcConnection("id", "proj", "Display",
                new IssuanceSettings("aud", 10, "RS256", java.util.Set.of()), "conn.token");
        assertThat(TokenVariableNameResolver.resolve(Map.of("token_variable_name", "feature.token"), Optional.of(conn)))
                .isEqualTo("feature.token");
    }

    @Test
    public void fallsBackToDefaultWhenConnectionVariableNameBlank() {
        final var conn = new OidcConnection("id", "proj", "Display",
                new IssuanceSettings("aud", 10, "RS256", java.util.Set.of()), "  ");
        assertThat(TokenVariableNameResolver.resolve(Map.of(), Optional.of(conn)))
                .isEqualTo("jwt.token");
    }
}
