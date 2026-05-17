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
 * @param jwksCacheLifetimeMinutes how long (in minutes) OIDC consumers should cache
 *                                 the JWKS / discovery document. Drives the
 *                                 {@code Cache-Control: max-age} header on those
 *                                 endpoints and the post-rotation warmup window before
 *                                 a newly-generated key starts signing.
 */
public record OidcSettings(@Nullable String overrideIssuerUrl,
                           int maxTokenLifetimeMinutes,
                           int jwksCacheLifetimeMinutes) {

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

    /** Default JWKS cache lifetime (10 minutes). Drives the {@code Cache-Control} header on
     *  the JWKS + discovery endpoints AND the post-rotation warmup window before a newly-
     *  generated key starts signing. */
    public static final int DEFAULT_JWKS_CACHE_LIFETIME_MINUTES = 10;

    /** Minimum JWKS cache lifetime: 1 minute. Below this the warmup is so short that the
     *  round-trip cost of consumers fetching+caching+signing dominates, making the warmup
     *  theatre rather than safety. */
    public static final int MIN_JWKS_CACHE_LIFETIME_MINUTES = 1;

    /** Maximum JWKS cache lifetime: 24 hours. Past this we'd be blocking emergency
     *  rotation for more than a day with no upside — AWS-class consumers cache JWKS for
     *  ~24h regardless of headers, so longer values protect against nothing additional. */
    public static final int MAX_JWKS_CACHE_LIFETIME_MINUTES = 1440;

    public OidcSettings {
        if (maxTokenLifetimeMinutes < MIN_TOKEN_LIFETIME_MINUTES
                || maxTokenLifetimeMinutes > ABSOLUTE_MAX_TOKEN_LIFETIME_MINUTES) {
            throw new IllegalArgumentException(
                    "maxTokenLifetimeMinutes must be between " + MIN_TOKEN_LIFETIME_MINUTES
                    + " and " + ABSOLUTE_MAX_TOKEN_LIFETIME_MINUTES + " (got " + maxTokenLifetimeMinutes + ")");
        }
        if (jwksCacheLifetimeMinutes < MIN_JWKS_CACHE_LIFETIME_MINUTES
                || jwksCacheLifetimeMinutes > MAX_JWKS_CACHE_LIFETIME_MINUTES) {
            throw new IllegalArgumentException(
                    "jwksCacheLifetimeMinutes must be between " + MIN_JWKS_CACHE_LIFETIME_MINUTES
                    + " and " + MAX_JWKS_CACHE_LIFETIME_MINUTES + " (got " + jwksCacheLifetimeMinutes + ")");
        }
    }

    public static OidcSettings defaults() {
        return new OidcSettings(null, DEFAULT_MAX_TOKEN_LIFETIME_MINUTES, DEFAULT_JWKS_CACHE_LIFETIME_MINUTES);
    }

    public Optional<String> findOverrideIssuerUrl() {
        return overrideIssuerUrl == null || overrideIssuerUrl.isBlank()
                ? Optional.empty()
                : Optional.of(overrideIssuerUrl);
    }

    public OidcSettings withOverrideIssuerUrl(@Nullable final String url) {
        return new OidcSettings(url, this.maxTokenLifetimeMinutes, this.jwksCacheLifetimeMinutes);
    }

    public OidcSettings withMaxTokenLifetimeMinutes(final int minutes) {
        return new OidcSettings(this.overrideIssuerUrl, minutes, this.jwksCacheLifetimeMinutes);
    }

    public OidcSettings withJwksCacheLifetimeMinutes(final int minutes) {
        return new OidcSettings(this.overrideIssuerUrl, this.maxTokenLifetimeMinutes, minutes);
    }
}
