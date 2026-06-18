package com.octopus.teamcity.oidc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import jetbrains.buildServer.serverSide.SBuild;
import org.jetbrains.annotations.NotNull;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
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

    private final ConcurrentHashMap<Long, Map<String, String>> tokensByBuildId = new ConcurrentHashMap<>();

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
     * Returns the JWTs for this build keyed by their effective build-variable name — one
     * entry per OIDC build feature. Issued on first call and cached for the build's lifetime.
     * Empty when the build has no feature or the issuer URL is not HTTPS. If two features
     * resolve to the same variable name (only possible via Kotlin DSL/REST, which bypass the
     * UI uniqueness validation), the first is kept and the rest are skipped with a warning.
     *
     * @throws RuntimeException if signing fails, or a feature references a {@code connection_id}
     *         that cannot be resolved — both fail the build with a clear log message.
     */
    public @NotNull Map<String, String> issueAll(@NotNull final SBuild build) {
        if (build.getBuildFeaturesOfType(JwtBuildFeature.FEATURE_TYPE).isEmpty()) {
            return Map.of();
        }
        return tokensByBuildId.computeIfAbsent(build.getBuildId(), id -> issueAllFresh(build));
    }

    /**
     * The effective variable names for all of the build's features, without issuing tokens
     * and without an HTTPS check — used to advertise parameter availability (emulation mode,
     * agent-available list).
     */
    public @NotNull Set<String> variableNamesFor(@NotNull final SBuild build) {
        final var names = new LinkedHashSet<String>();
        for (final var descriptor : build.getBuildFeaturesOfType(JwtBuildFeature.FEATURE_TYPE)) {
            names.add(effectiveVariableName(build, descriptor.getParameters()));
        }
        return names;
    }

    public void evict(final long buildId) {
        tokensByBuildId.remove(buildId);
    }

    private Map<String, String> issueAllFresh(final SBuild build) {
        final var issuerUrl = issuerUrlProvider.getIssuerUrl();
        if (!OidcUrlUtils.isHttpsUrl(issuerUrl)) {
            LOG.warning("JWT plugin: skipping JWT — issuer URL is not HTTPS: " + sanitize(issuerUrl));
            return Map.of();
        }
        final var maxTtl = oidcSettingsManager.load().maxTokenLifetimeMinutes();
        final var result = new LinkedHashMap<String, String>();
        for (final var descriptor : build.getBuildFeaturesOfType(JwtBuildFeature.FEATURE_TYPE)) {
            final var params = descriptor.getParameters();
            final var variableName = effectiveVariableName(build, params);
            if (result.containsKey(variableName)) {
                LOG.warning("JWT plugin: duplicate token variable name '" + sanitize(variableName)
                        + "' across OIDC build features for build " + build.getBuildId()
                        + "; keeping the first and skipping the duplicate.");
                continue;
            }
            final var settings = resolveSettings(build, params, issuerUrl, maxTtl);
            result.put(variableName, mintToken(build, settings, issuerUrl));
        }
        return result;
    }

    private String effectiveVariableName(final SBuild build, final Map<String, String> params) {
        final var connectionId = params.getOrDefault("connection_id", "").trim();
        final Optional<OidcConnection> connection =
                connectionId.isBlank() || build.getBuildType() == null
                        ? Optional.empty()
                        : connectionsManager.resolve(build.getBuildType().getProject(), connectionId);
        return TokenVariableNameResolver.resolve(params, connection);
    }

    private IssuanceSettings resolveSettings(final SBuild build,
                                             final Map<String, String> params,
                                             final String issuerUrl,
                                             final int maxTtl) {
        final var connectionId = params.get("connection_id");
        if (connectionId != null && !connectionId.isBlank()) {
            final var project = build.getBuildType().getProject();
            final var resolved = connectionsManager.resolve(project, connectionId);
            if (resolved.isEmpty()) {
                throw new RuntimeException("JWT plugin: OIDC Identity Token connection '"
                        + sanitize(connectionId) + "' could not be found in this project or any parent. "
                        + "Edit the build feature and select a valid connection, or remove the connection reference.");
            }
            return resolved.get().settings();
        }
        return IssuanceSettings.fromBuildFeatureParams(params, issuerUrl, maxTtl);
    }

    private String mintToken(final SBuild build, final IssuanceSettings settings, final String issuerUrl) {
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
