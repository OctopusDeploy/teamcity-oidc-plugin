package com.octopus.teamcity.oidc;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class OidcSettingsTest {

    @Test
    void rejectsZeroMaxTokenLifetime() {
        assertThatThrownBy(() -> new OidcSettings(null, 0, OidcSettings.DEFAULT_JWKS_CACHE_LIFETIME_MINUTES))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maxTokenLifetimeMinutes");
    }

    @Test
    void rejectsNegativeMaxTokenLifetime() {
        assertThatThrownBy(() -> new OidcSettings(null, -1, OidcSettings.DEFAULT_JWKS_CACHE_LIFETIME_MINUTES))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maxTokenLifetimeMinutes");
    }

    @Test
    void rejectsMaxTokenLifetimeAboveAbsoluteCeiling() {
        assertThatThrownBy(() -> new OidcSettings(null, OidcSettings.ABSOLUTE_MAX_TOKEN_LIFETIME_MINUTES + 1,
                OidcSettings.DEFAULT_JWKS_CACHE_LIFETIME_MINUTES))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maxTokenLifetimeMinutes");
    }

    @Test
    void acceptsMinTokenLifetime() {
        final var settings = new OidcSettings(null, OidcSettings.MIN_TOKEN_LIFETIME_MINUTES,
                OidcSettings.DEFAULT_JWKS_CACHE_LIFETIME_MINUTES);
        assertThat(settings.maxTokenLifetimeMinutes()).isEqualTo(OidcSettings.MIN_TOKEN_LIFETIME_MINUTES);
    }

    @Test
    void acceptsMaxAbsoluteCeiling() {
        final var settings = new OidcSettings(null, OidcSettings.ABSOLUTE_MAX_TOKEN_LIFETIME_MINUTES,
                OidcSettings.DEFAULT_JWKS_CACHE_LIFETIME_MINUTES);
        assertThat(settings.maxTokenLifetimeMinutes()).isEqualTo(OidcSettings.ABSOLUTE_MAX_TOKEN_LIFETIME_MINUTES);
    }

    @Test
    void withMaxTokenLifetimeRejectsOutOfRange() {
        // The with...() copy goes through the same compact constructor as direct construction.
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

    @Test
    void rejectsZeroJwksCacheLifetime() {
        assertThatThrownBy(() -> new OidcSettings(null, OidcSettings.DEFAULT_MAX_TOKEN_LIFETIME_MINUTES, 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("jwksCacheLifetimeMinutes");
    }

    @Test
    void rejectsJwksCacheLifetimeAboveCeiling() {
        assertThatThrownBy(() -> new OidcSettings(null, OidcSettings.DEFAULT_MAX_TOKEN_LIFETIME_MINUTES,
                OidcSettings.MAX_JWKS_CACHE_LIFETIME_MINUTES + 1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("jwksCacheLifetimeMinutes");
    }

    @Test
    void acceptsMinJwksCacheLifetime() {
        final var settings = new OidcSettings(null, OidcSettings.DEFAULT_MAX_TOKEN_LIFETIME_MINUTES,
                OidcSettings.MIN_JWKS_CACHE_LIFETIME_MINUTES);
        assertThat(settings.jwksCacheLifetimeMinutes()).isEqualTo(OidcSettings.MIN_JWKS_CACHE_LIFETIME_MINUTES);
    }

    @Test
    void acceptsMaxJwksCacheLifetime() {
        final var settings = new OidcSettings(null, OidcSettings.DEFAULT_MAX_TOKEN_LIFETIME_MINUTES,
                OidcSettings.MAX_JWKS_CACHE_LIFETIME_MINUTES);
        assertThat(settings.jwksCacheLifetimeMinutes()).isEqualTo(OidcSettings.MAX_JWKS_CACHE_LIFETIME_MINUTES);
    }

    @Test
    void defaultJwksCacheLifetimeInRange() {
        final var settings = OidcSettings.defaults();
        assertThat(settings.jwksCacheLifetimeMinutes()).isEqualTo(OidcSettings.DEFAULT_JWKS_CACHE_LIFETIME_MINUTES);
    }

    @Test
    void withJwksCacheLifetimeRejectsOutOfRange() {
        final var s = OidcSettings.defaults();
        assertThatThrownBy(() -> s.withJwksCacheLifetimeMinutes(0))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void withJwksCacheLifetimePreservesOtherFields() {
        final var s = new OidcSettings("https://example", 100, 5);
        final var updated = s.withJwksCacheLifetimeMinutes(20);
        assertThat(updated.overrideIssuerUrl()).isEqualTo("https://example");
        assertThat(updated.maxTokenLifetimeMinutes()).isEqualTo(100);
        assertThat(updated.jwksCacheLifetimeMinutes()).isEqualTo(20);
    }

    @Test
    void withOverrideIssuerUrlPreservesJwksCacheLifetime() {
        final var settings = new OidcSettings("https://example", 100, 5);
        final var updated = settings.withOverrideIssuerUrl("https://other");
        assertThat(updated.overrideIssuerUrl()).isEqualTo("https://other");
        assertThat(updated.maxTokenLifetimeMinutes()).isEqualTo(100);
        assertThat(updated.jwksCacheLifetimeMinutes()).isEqualTo(5);
    }

    @Test
    void withMaxTokenLifetimeMinutesPreservesJwksCacheLifetime() {
        final var settings = new OidcSettings("https://example", 100, 5);
        final var updated = settings.withMaxTokenLifetimeMinutes(200);
        assertThat(updated.overrideIssuerUrl()).isEqualTo("https://example");
        assertThat(updated.maxTokenLifetimeMinutes()).isEqualTo(200);
        assertThat(updated.jwksCacheLifetimeMinutes()).isEqualTo(5);
    }
}
