package com.octopus.teamcity.oidc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import jetbrains.buildServer.serverSide.SBuild;
import org.jetbrains.annotations.NotNull;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Issues a single JWT per build and caches it for the build's lifetime.
 *
 * <p>We have a separate service, as the {@code PasswordsBuildStartContextProcessor}
 * runs before our {@link JwtBuildStartContext} does, and queries every {@code PasswordsProvider}
 * (including {@link JwtPasswordsProvider}) to assemble the agent's masking set. By having both
 * the password provider and the build-start-context processor route through this service, the
 * same JWT value lands in both the masking set and the {@code jwt.token} shared parameter —
 * regardless of which extension runs first.
 */
public class JwtIssuanceService {
    private static final Logger LOG = Logger.getLogger(JwtIssuanceService.class.getName());

    private static final Pattern CLAIMS_SPLIT = Pattern.compile("\\s*,\\s*");
    private static final Set<String> ALL_CUSTOM_CLAIMS = Set.of("branch", "trigger_type");

    private final OidcIssuerUrlProvider issuerUrlProvider;
    private final JwtKeyManager keyManager;
    private final OidcSettingsManager oidcSettingsManager;

    private final ConcurrentHashMap<Long, String> tokenByBuildId = new ConcurrentHashMap<>();

    public JwtIssuanceService(@NotNull final OidcIssuerUrlProvider issuerUrlProvider,
                              @NotNull final JwtKeyManager keyManager,
                              @NotNull final OidcSettingsManager oidcSettingsManager) {
        this.issuerUrlProvider = issuerUrlProvider;
        this.keyManager = keyManager;
        this.oidcSettingsManager = oidcSettingsManager;
    }

    /**
     * Returns the JWT for this build, issuing it on first call and serving the cached
     * value on subsequent calls. Returns {@link Optional#empty()} if the build has no
     * JWT feature configured, or if the configured issuer URL is not HTTPS.
     *
     * @throws RuntimeException if signing fails — propagated to fail the build, mirroring
     *         the previous behaviour.
     */
    public Optional<String> issueOrGet(@NotNull final SBuild build) {
        if (build.getBuildFeaturesOfType(JwtBuildFeature.FEATURE_TYPE).isEmpty()) {
            return Optional.empty();
        }
        return Optional.ofNullable(tokenByBuildId.computeIfAbsent(build.getBuildId(), id -> issue(build)));
    }

    public void evict(final long buildId) {
        tokenByBuildId.remove(buildId);
    }

    private String issue(final SBuild build) {
        try {
            final var descriptor = build
                    .getBuildFeaturesOfType(JwtBuildFeature.FEATURE_TYPE)
                    .stream()
                    .findFirst()
                    .orElseThrow();
            final var params = descriptor.getParameters();

            final var maxTtl = oidcSettingsManager.load().maxTokenLifetimeMinutes();
            final var ttlRaw = params.getOrDefault("ttl_minutes", "10");
            int ttlMinutes;
            try {
                ttlMinutes = Math.clamp(Integer.parseInt(ttlRaw),
                        OidcSettings.MIN_TOKEN_LIFETIME_MINUTES, maxTtl);
            } catch (final NumberFormatException e) {
                ttlMinutes = Math.min(10, maxTtl);
                LOG.warning("JWT plugin: invalid ttl_minutes value '" + sanitize(ttlRaw)
                        + "' for build " + build.getBuildId()
                        + " — check the build feature configuration. Using default of " + ttlMinutes + " minutes.");
            }
            final var algorithmName = params.getOrDefault("algorithm", "RS256");

            final var issuerUrl = issuerUrlProvider.getIssuerUrl();
            LOG.info("JWT plugin: issuing JWT for build " + build.getBuildId()
                    + ", issuerUrl=" + sanitize(issuerUrl) + ", algorithm=" + sanitize(algorithmName));

            if (!OidcUrlUtils.isHttpsUrl(issuerUrl)) {
                LOG.warning("JWT plugin: skipping JWT — issuer URL is not HTTPS: " + sanitize(issuerUrl));
                return null;
            }

            final var rawAudience = params.getOrDefault("audience", "");
            final var audience = rawAudience.isBlank() ? issuerUrl : rawAudience;

            final var claimsParam = params.get("claims");
            final Set<String> requestedClaims = (claimsParam == null || claimsParam.isBlank())
                    ? ALL_CUSTOM_CLAIMS
                    : new HashSet<>(Arrays.asList(CLAIMS_SPLIT.split(claimsParam)));
            final var unknownClaims = requestedClaims.stream()
                    .filter(c -> !ALL_CUSTOM_CLAIMS.contains(c))
                    .collect(Collectors.toSet());
            if (!unknownClaims.isEmpty()) {
                LOG.warning("JWT plugin: ignoring unrecognised claim names for build "
                        + build.getBuildId() + ": "
                        + unknownClaims.stream().map(JwtIssuanceService::sanitize).collect(Collectors.toSet()));
            }
            final var enabledClaims = requestedClaims.stream()
                    .filter(ALL_CUSTOM_CLAIMS::contains)
                    .collect(Collectors.toSet());

            final var now = Instant.now();
            final var claimsBuilder = new JWTClaimsSet.Builder()
                    .jwtID(build.getBuildId() + "-" + UUID.randomUUID())
                    .subject(build.getBuildTypeExternalId())
                    .audience(List.of(audience))
                    .issuer(issuerUrl)
                    .issueTime(Date.from(now))
                    .notBeforeTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(ttlMinutes, ChronoUnit.MINUTES)))
                    .claim("build_type_external_id", build.getBuildTypeExternalId())
                    .claim("project_external_id", build.getProjectExternalId());

            if (enabledClaims.contains("branch")) {
                final var branchName = ClaimsResolver.resolveBranchName(build);
                if (!branchName.isEmpty()) {
                    claimsBuilder.claim("branch", branchName);
                }
            }
            if (enabledClaims.contains("trigger_type")) {
                claimsBuilder.claim("trigger_type", ClaimsResolver.resolveTriggerType(build.getTriggeredBy()));
            }

            final var signedJWT = keyManager.sign(claimsBuilder.build(), algorithmName);
            LOG.info("JWT plugin: JWT issued successfully for build " + build.getBuildId()
                    + " (iss=" + sanitize(issuerUrl) + ", aud=" + sanitize(audience) + ", alg=" + sanitize(algorithmName)
                    + ", kid=" + signedJWT.getHeader().getKeyID() + ")");
            return signedJWT.serialize();
        } catch (final JOSEException e) {
            LOG.log(Level.SEVERE, "JWT plugin: JOSEException while signing JWT for build " + build.getBuildId(), e);
            throw new RuntimeException("JWT plugin: failed to sign token — check the TeamCity server log for details");
        } catch (final RuntimeException e) {
            LOG.log(Level.SEVERE, "JWT plugin: unexpected exception issuing JWT for build " + build.getBuildId(), e);
            throw new RuntimeException("JWT plugin: unexpected error issuing token — check the TeamCity server log for details");
        }
    }

    private static String sanitize(final String s) {
        return s == null ? "" : s.replaceAll("[\\r\\n\\t]", "_");
    }
}
