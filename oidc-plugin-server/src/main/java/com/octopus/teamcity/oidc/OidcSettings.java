package com.octopus.teamcity.oidc;

import org.jetbrains.annotations.Nullable;

import java.util.Optional;

/**
 * Server-wide OIDC settings persisted to {@code oidc-settings.json}.
 *
 * @param overrideIssuerUrl optional override for the public-facing issuer URL,
 *                          used when TeamCity is behind a reverse proxy. Null/blank
 *                          means "use the server root URL".
 * @param maxTokenLifetimeMinutes upper bound applied to the {@code ttl_minutes}
 *                                build-feature parameter. The build feature both
 *                                rejects values above this on save and silently
 *                                clamps any stored value at runtime.
 */
public record OidcSettings(@Nullable String overrideIssuerUrl, int maxTokenLifetimeMinutes) {

    /** Default upper bound on token lifetime (12 hours). */
    public static final int DEFAULT_MAX_TOKEN_LIFETIME_MINUTES = 720;

    /** Smallest meaningful token lifetime; also the floor enforced when validating user input. */
    public static final int MIN_TOKEN_LIFETIME_MINUTES = 1;

    /**
     * Hard ceiling on the configurable max (24 hours). No mainstream cloud OIDC consumer
     * (AWS IAM, Azure workload identity federation, GCP, GitHub Actions, etc.) will accept
     * tokens with a longer lifetime, so allowing more here would only let users configure
     * builds that produce tokens guaranteed to be rejected.
     */
    public static final int ABSOLUTE_MAX_TOKEN_LIFETIME_MINUTES = 1440;

    public OidcSettings {
        if (maxTokenLifetimeMinutes < MIN_TOKEN_LIFETIME_MINUTES
                || maxTokenLifetimeMinutes > ABSOLUTE_MAX_TOKEN_LIFETIME_MINUTES) {
            throw new IllegalArgumentException(
                    "maxTokenLifetimeMinutes must be between " + MIN_TOKEN_LIFETIME_MINUTES
                    + " and " + ABSOLUTE_MAX_TOKEN_LIFETIME_MINUTES + " (got " + maxTokenLifetimeMinutes + ")");
        }
    }

    public static OidcSettings defaults() {
        return new OidcSettings(null, DEFAULT_MAX_TOKEN_LIFETIME_MINUTES);
    }

    public Optional<String> findOverrideIssuerUrl() {
        return overrideIssuerUrl == null || overrideIssuerUrl.isBlank()
                ? Optional.empty()
                : Optional.of(overrideIssuerUrl);
    }

    public OidcSettings withOverrideIssuerUrl(@Nullable final String url) {
        return new OidcSettings(url, this.maxTokenLifetimeMinutes);
    }

    public OidcSettings withMaxTokenLifetimeMinutes(final int minutes) {
        return new OidcSettings(this.overrideIssuerUrl, minutes);
    }
}
