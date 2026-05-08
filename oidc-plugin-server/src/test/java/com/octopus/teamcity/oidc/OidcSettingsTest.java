package com.octopus.teamcity.oidc;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class OidcSettingsTest {

    @Test
    void rejectsZeroMaxTokenLifetime() {
        assertThatThrownBy(() -> new OidcSettings(null, 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maxTokenLifetimeMinutes");
    }

    @Test
    void rejectsNegativeMaxTokenLifetime() {
        assertThatThrownBy(() -> new OidcSettings(null, -1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maxTokenLifetimeMinutes");
    }

    @Test
    void rejectsMaxTokenLifetimeAboveAbsoluteCeiling() {
        assertThatThrownBy(() -> new OidcSettings(null, OidcSettings.ABSOLUTE_MAX_TOKEN_LIFETIME_MINUTES + 1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maxTokenLifetimeMinutes");
    }

    @Test
    void acceptsMinTokenLifetime() {
        final var settings = new OidcSettings(null, OidcSettings.MIN_TOKEN_LIFETIME_MINUTES);
        assertThat(settings.maxTokenLifetimeMinutes()).isEqualTo(OidcSettings.MIN_TOKEN_LIFETIME_MINUTES);
    }

    @Test
    void acceptsMaxAbsoluteCeiling() {
        final var settings = new OidcSettings(null, OidcSettings.ABSOLUTE_MAX_TOKEN_LIFETIME_MINUTES);
        assertThat(settings.maxTokenLifetimeMinutes()).isEqualTo(OidcSettings.ABSOLUTE_MAX_TOKEN_LIFETIME_MINUTES);
    }

    @Test
    void withMaxTokenLifetimeRejectsOutOfRange() {
        // The wither produces a new record, which goes through the same compact constructor.
        final var settings = OidcSettings.defaults();
        assertThatThrownBy(() -> settings.withMaxTokenLifetimeMinutes(0))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void defaultsAreInRange() {
        // Sanity: defaults() must not trip the validation.
        final var settings = OidcSettings.defaults();
        assertThat(settings.maxTokenLifetimeMinutes()).isEqualTo(OidcSettings.DEFAULT_MAX_TOKEN_LIFETIME_MINUTES);
    }
}
