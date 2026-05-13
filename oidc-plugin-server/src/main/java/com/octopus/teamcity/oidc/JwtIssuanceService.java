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

    private static final Pattern SUBJECT_DIMENSIONS_SPLIT = Pattern.compile("\\s*,\\s*");

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

            final var subjectDimensions = parseSubjectDimensions(subjectDimensionsParam(params), build);

            final var branchName = ClaimsResolver.resolveBranchName(build);
            final var triggerType = ClaimsResolver.resolveTriggerType(build.getTriggeredBy());

            final var subject = composeSubject(build, subjectDimensions, branchName, triggerType);

            final var now = Instant.now();
            final var claimsBuilder = new JWTClaimsSet.Builder()
                    .jwtID(build.getBuildId() + "-" + UUID.randomUUID())
                    .subject(subject)
                    .audience(List.of(audience))
                    .issuer(issuerUrl)
                    .issueTime(Date.from(now))
                    .notBeforeTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(ttlMinutes, ChronoUnit.MINUTES)))
                    .claim("build_type_external_id", build.getBuildTypeExternalId())
                    .claim("project_external_id", build.getProjectExternalId())
                    .claim("build_type_internal_id", build.getBuildTypeId())
                    .claim("project_internal_id", build.getProjectId())
                    .claim("trigger_type", triggerType);

            if (!branchName.isEmpty()) {
                claimsBuilder.claim("branch", branchName);
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

    private static String subjectDimensionsParam(final java.util.Map<String, String> params) {
        final var raw = params.get("subject_dimensions");
        return raw == null ? "" : raw;
    }

    /**
     * Parses the {@code subject_dimensions} build feature parameter into the set of optional
     * dimensions that should appear in the {@code sub} claim. The semantics:
     * <ul>
     *   <li>{@code null} or empty → no optional dimensions (default for a fresh feature);
     *       {@code sub} is just {@code project:&lt;id&gt;:build_type:&lt;id&gt;}</li>
     *   <li>comma-separated list → only the named dimensions (unknown names are ignored with a log)</li>
     * </ul>
     */
    private Set<String> parseSubjectDimensions(final String raw, final SBuild build) {
        if (raw.isBlank()) return Set.of();
        final var requested = new HashSet<>(Arrays.asList(SUBJECT_DIMENSIONS_SPLIT.split(raw)));
        final var unknown = requested.stream()
                .filter(c -> !JwtBuildFeature.ALL_OPTIONAL_SUBJECT_DIMENSIONS.contains(c))
                .collect(Collectors.toSet());
        if (!unknown.isEmpty()) {
            LOG.warning("JWT plugin: ignoring unrecognised subject dimensions for build "
                    + build.getBuildId() + ": "
                    + unknown.stream().map(JwtIssuanceService::sanitize).collect(Collectors.toSet()));
        }
        return requested.stream().filter(JwtBuildFeature.ALL_OPTIONAL_SUBJECT_DIMENSIONS::contains).collect(Collectors.toSet());
    }

    /**
     * Composes the {@code sub} claim as a colon-separated key:value string, in the style of
     * GitHub Actions' {@code repo:org/repo:ref:...}. Always includes {@code project} and
     * {@code build_type} (using the rename-stable internal IDs); appends {@code branch} and
     * {@code trigger_type} only when configured via the build feature, mirroring the
     * Octopus Deploy convention where trust policies match on {@code sub} with wildcards.
     */
    private String composeSubject(final SBuild build,
                                  final Set<String> dimensions,
                                  final String branchName,
                                  final String triggerType) {
        final var sb = new StringBuilder("project:")
                .append(build.getProjectId())
                .append(":build_type:")
                .append(build.getBuildTypeId());
        if (dimensions.contains("branch") && !branchName.isEmpty()) {
            sb.append(":branch:").append(branchName);
        }
        if (dimensions.contains("trigger_type")) {
            sb.append(":trigger_type:").append(triggerType);
        }
        return sb.toString();
    }
}
