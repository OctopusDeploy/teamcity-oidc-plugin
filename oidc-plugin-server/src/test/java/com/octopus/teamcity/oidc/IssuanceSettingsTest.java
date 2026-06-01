package com.octopus.teamcity.oidc;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.assertj.core.api.Assertions.assertThat;

public class IssuanceSettingsTest {

    @Test
    public void fromBuildFeatureParamsAppliesDefaults() {
        final var settings = IssuanceSettings.fromBuildFeatureParams(
                Map.of(), "https://teamcity.example.com", 720);

        assertThat(settings.audience()).isEqualTo("https://teamcity.example.com");
        assertThat(settings.ttlMinutes()).isEqualTo(10);
        assertThat(settings.signingAlgorithm()).isEqualTo("RS256");
        assertThat(settings.subjectDimensions()).isEmpty();
    }

    @Test
    public void fromBuildFeatureParamsUsesProvidedValues() {
        final var params = Map.of(
                "audience", "api://example",
                "ttl_minutes", "30",
                "algorithm", "ES256",
                "subject_dimensions", "branch,trigger_type");
        final var settings = IssuanceSettings.fromBuildFeatureParams(
                params,"https://teamcity.example.com", 720);

        assertThat(settings.audience()).isEqualTo("api://example");
        assertThat(settings.ttlMinutes()).isEqualTo(30);
        assertThat(settings.signingAlgorithm()).isEqualTo("ES256");
        assertThat(settings.subjectDimensions()).containsExactlyInAnyOrder("branch", "trigger_type");
    }

    @Test
    public void ttlClampedToServerMaxAndMin() {
        final var clampedHigh = IssuanceSettings.fromBuildFeatureParams(
                Map.of("ttl_minutes", "9999"), "https://issuer", 60);
        assertThat(clampedHigh.ttlMinutes()).isEqualTo(60);

        final var clampedLow = IssuanceSettings.fromBuildFeatureParams(
                Map.of("ttl_minutes", "-5"), "https://issuer", 720);
        assertThat(clampedLow.ttlMinutes()).isEqualTo(OidcSettings.MIN_TOKEN_LIFETIME_MINUTES);
    }

    @Test
    public void invalidTtlFallsBackToDefaultClampedToMax() {
        final var fallback = IssuanceSettings.fromBuildFeatureParams(
                Map.of("ttl_minutes", "not-a-number"), "https://issuer", 720);
        assertThat(fallback.ttlMinutes()).isEqualTo(IssuanceSettings.DEFAULT_TTL_MINUTES);

        final var fallbackClamped = IssuanceSettings.fromBuildFeatureParams(
                Map.of("ttl_minutes", "not-a-number"), "https://issuer", 5);
        assertThat(fallbackClamped.ttlMinutes()).isEqualTo(5);
    }

    @Test
    public void blankAudienceDefaultsToIssuerUrl() {
        final var settings = IssuanceSettings.fromBuildFeatureParams(
                Map.of("audience", ""), "https://teamcity.example.com", 720);
        assertThat(settings.audience()).isEqualTo("https://teamcity.example.com");
    }

    @Test
    public void unknownSubjectDimensionsAreFilteredOut() {
        final var settings = IssuanceSettings.fromBuildFeatureParams(
                Map.of("subject_dimensions", "branch,bogus,trigger_type"),
                "https://issuer", 720);
        assertThat(settings.subjectDimensions()).containsExactlyInAnyOrder("branch", "trigger_type");
    }

    @Test
    public void unknownSubjectDimensionsProduceWarning() {
        final var logger = Logger.getLogger(IssuanceSettings.class.getName());
        final List<LogRecord> captured = new ArrayList<>();
        final var handler = new Handler() {
            @Override public void publish(final LogRecord r) { captured.add(r); }
            @Override public void flush() {}
            @Override public void close() {}
        };
        logger.addHandler(handler);
        try {
            final var params = Map.of("subject_dimensions", "branch,bogus");
            IssuanceSettings.fromBuildFeatureParams(params, "https://issuer", 720);
        } finally {
            logger.removeHandler(handler);
        }
        assertThat(captured)
                .anyMatch(r -> r.getMessage().contains("unrecognised subject dimensions")
                        && r.getMessage().contains("bogus"));
    }
}
