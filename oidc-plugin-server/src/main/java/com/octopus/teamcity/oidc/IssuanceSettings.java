package com.octopus.teamcity.oidc;

import org.jetbrains.annotations.NotNull;

import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * The effective OIDC issuance configuration for a single build, after defaults
 * and server-wide bounds have been applied. The source is either the build
 * feature's inline parameters or a resolved {@link OidcConnection} — once
 * computed, downstream issuance code is uniform.
 */
public record IssuanceSettings(@NotNull String audience,
                               int ttlMinutes,
                               @NotNull String signingAlgorithm,
                               @NotNull Set<String> subjectDimensions) {

    private static final Logger LOG = Logger.getLogger(IssuanceSettings.class.getName());
    private static final Pattern SUBJECT_DIMENSIONS_SPLIT = Pattern.compile("\\s*,\\s*");
    static final int DEFAULT_TTL_MINUTES = 10;
    private static final String DEFAULT_ALGORITHM = "RS256";

    public static @NotNull IssuanceSettings fromBuildFeatureParams(
            @NotNull final Map<String, String> params,
            @NotNull final String issuerUrl,
            final int maxTtlMinutes) {
        final var rawAudience = params.getOrDefault("audience", "");
        final var audience = rawAudience.isBlank() ? issuerUrl : rawAudience;

        final var ttlMinutes = parseTtl(params.getOrDefault("ttl_minutes", String.valueOf(DEFAULT_TTL_MINUTES)), maxTtlMinutes);

        final var algorithm = params.getOrDefault("algorithm", DEFAULT_ALGORITHM);

        final var subjectDimensions = parseSubjectDimensions(params.getOrDefault("subject_dimensions", ""));

        return new IssuanceSettings(audience, ttlMinutes, algorithm, subjectDimensions);
    }

    public @NotNull IssuanceSettings withTtlMinutes(final int ttlMinutes) {
        return new IssuanceSettings(audience, ttlMinutes, signingAlgorithm, subjectDimensions);
    }

    private static int parseTtl(final String raw, final int maxTtlMinutes) {
        try {
            return Math.clamp(Integer.parseInt(raw), OidcSettings.MIN_TOKEN_LIFETIME_MINUTES, maxTtlMinutes);
        } catch (final NumberFormatException e) {
            LOG.warning("JWT plugin: invalid ttl_minutes '" + sanitize(raw) + "' — using default "
                    + DEFAULT_TTL_MINUTES + " (clamped to server max " + maxTtlMinutes + ")");
            return Math.min(DEFAULT_TTL_MINUTES, maxTtlMinutes);
        }
    }

    private static Set<String> parseSubjectDimensions(final String raw) {
        if (raw.isBlank()) return Set.of();
        final var requested = Arrays.stream(SUBJECT_DIMENSIONS_SPLIT.split(raw))
                .filter(s -> !s.isBlank())
                .collect(Collectors.toUnmodifiableSet());
        final var unknown = requested.stream()
                .filter(s -> !JwtBuildFeature.ALL_OPTIONAL_SUBJECT_DIMENSIONS.contains(s))
                .map(IssuanceSettings::sanitize)
                .collect(Collectors.toUnmodifiableSet());
        if (!unknown.isEmpty()) {
            LOG.warning("JWT plugin: ignoring unrecognised subject dimensions: " + unknown);
        }
        return requested.stream()
                .filter(JwtBuildFeature.ALL_OPTIONAL_SUBJECT_DIMENSIONS::contains)
                .collect(Collectors.toUnmodifiableSet());
    }

    private static String sanitize(final String s) {
        return s == null ? "" : s.replaceAll("[\\r\\n\\t]", "_");
    }
}
