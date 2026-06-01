package com.octopus.teamcity.oidc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import jetbrains.buildServer.serverSide.SBuild;
import org.jetbrains.annotations.NotNull;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

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

    private final OidcIssuerUrlProvider issuerUrlProvider;
    private final JwtKeyManager keyManager;
    private final OidcSettingsManager oidcSettingsManager;
    private final OidcConnectionsManager connectionsManager;

    private final ConcurrentHashMap<Long, String> tokenByBuildId = new ConcurrentHashMap<>();

    public JwtIssuanceService(@NotNull final OidcIssuerUrlProvider issuerUrlProvider,
                              @NotNull final JwtKeyManager keyManager,
                              @NotNull final OidcSettingsManager oidcSettingsManager,
                              @NotNull final OidcConnectionsManager connectionsManager) {
        this.issuerUrlProvider = issuerUrlProvider;
        this.keyManager = keyManager;
        this.oidcSettingsManager = oidcSettingsManager;
        this.connectionsManager = connectionsManager;
    }

    /**
     * Returns the JWT for this build, issuing it on first call and serving the cached
     * value on subsequent calls. Returns {@link Optional#empty()} if the build has no
     * JWT feature configured, or if the configured issuer URL is not HTTPS.
     *
     * @throws RuntimeException if signing fails, or if the build feature references an
     *         {@code connection_id} that cannot be resolved in the build's project
     *         hierarchy — both fail the build with a clear message in the build log.
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
        final var descriptor = build
                .getBuildFeaturesOfType(JwtBuildFeature.FEATURE_TYPE)
                .stream()
                .findFirst()
                .orElseThrow();
        final var params = descriptor.getParameters();

        final var issuerUrl = issuerUrlProvider.getIssuerUrl();
        LOG.info("JWT plugin: issuing JWT for build " + build.getBuildId()
                + ", issuerUrl=" + sanitize(issuerUrl));

        if (!OidcUrlUtils.isHttpsUrl(issuerUrl)) {
            LOG.warning("JWT plugin: skipping JWT — issuer URL is not HTTPS: " + sanitize(issuerUrl));
            return null;
        }

        final var maxTtl = oidcSettingsManager.load().maxTokenLifetimeMinutes();
        final var connectionId = params.get("connection_id");
        final IssuanceSettings settings;
        if (connectionId != null && !connectionId.isBlank()) {
            final var project = build.getBuildType().getProject();
            final var resolved = connectionsManager.resolve(project, connectionId);
            if (resolved.isEmpty()) {
                throw new RuntimeException("JWT plugin: OIDC Identity Token connection '"
                        + sanitize(connectionId) + "' could not be found in this project or any parent. "
                        + "Edit the build feature and select a valid connection, or remove the connection reference.");
            }
            settings = resolved.get().settings();
        } else {
            settings = IssuanceSettings.fromBuildFeatureParams(params, issuerUrl, maxTtl);
        }

        final var branchName = ClaimsResolver.resolveBranchName(build);
        final var triggerType = ClaimsResolver.resolveTriggerType(build.getTriggeredBy());

        final var subject = composeSubject(build, settings.subjectDimensions(), branchName, triggerType);

        final var now = Instant.now();
        final var claimsBuilder = new JWTClaimsSet.Builder()
                .jwtID(build.getBuildId() + "-" + UUID.randomUUID())
                .subject(subject)
                .audience(List.of(settings.audience()))
                .issuer(issuerUrl)
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(now.plus(settings.ttlMinutes(), ChronoUnit.MINUTES)))
                .claim("build_type_external_id", build.getBuildTypeExternalId())
                .claim("project_external_id", build.getProjectExternalId())
                .claim("build_type_internal_id", build.getBuildTypeId())
                .claim("project_internal_id", build.getProjectId())
                .claim("trigger_type", triggerType);

        if (!branchName.isEmpty()) {
            claimsBuilder.claim("branch", branchName);
        }

        try {
            final var signedJWT = keyManager.sign(claimsBuilder.build(), settings.signingAlgorithm());
            LOG.info("JWT plugin: JWT issued successfully for build " + build.getBuildId()
                    + " (iss=" + sanitize(issuerUrl) + ", aud=" + sanitize(settings.audience())
                    + ", alg=" + sanitize(settings.signingAlgorithm())
                    + ", kid=" + signedJWT.getHeader().getKeyID() + ")");
            return signedJWT.serialize();
        } catch (final JOSEException e) {
            LOG.log(Level.SEVERE, "JWT plugin: JOSEException while signing JWT for build " + build.getBuildId(), e);
            throw new RuntimeException("JWT plugin: failed to sign token — check the TeamCity server log for details");
        }
    }

    private static String sanitize(final String s) {
        return s == null ? "" : s.replaceAll("[\\r\\n\\t]", "_");
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
