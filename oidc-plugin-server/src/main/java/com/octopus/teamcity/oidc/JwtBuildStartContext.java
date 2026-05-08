package com.octopus.teamcity.oidc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.*;
import org.jetbrains.annotations.NotNull;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class JwtBuildStartContext implements BuildStartContextProcessor {
    private static final Logger LOG = Logger.getLogger(JwtBuildStartContext.class.getName());

    private final ExtensionHolder extensionHolder;
    private final OidcIssuerUrlProvider issuerUrlProvider;
    private final JwtKeyManager keyManager;
    private final OidcSettingsManager oidcSettingsManager;

    private static final Pattern CLAIMS_SPLIT = Pattern.compile("\\s*,\\s*");

    private static final Set<String> ALL_CUSTOM_CLAIMS = Set.of("branch", "trigger_type");

    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    public JwtBuildStartContext(@NotNull final ExtensionHolder extensionHolder,
                                @NotNull final OidcIssuerUrlProvider issuerUrlProvider,
                                @NotNull final JwtKeyManager keyManager,
                                @NotNull final OidcSettingsManager oidcSettingsManager) {
        this.extensionHolder = extensionHolder;
        this.issuerUrlProvider = issuerUrlProvider;
        this.keyManager = keyManager;
        this.oidcSettingsManager = oidcSettingsManager;
    }

    public void register() {
        extensionHolder.registerExtension(BuildStartContextProcessor.class, this.getClass().getName(), this);
        LOG.info("JWT plugin: JwtBuildStartContext registered as BuildStartContextProcessor");
    }

    private static String sanitize(final String s) {
        return s == null ? "" : s.replaceAll("[\\r\\n\\t]", "_");
    }

    @Override
    public void updateParameters(@NotNull final BuildStartContext buildStartContext) {
        final var build = buildStartContext.getBuild();
        final var jwtBuildFeatures = build.getBuildFeaturesOfType(JwtBuildFeature.FEATURE_TYPE);

        LOG.fine("JWT plugin: updateParameters called for build " + build.getBuildId()
                + " (" + build.getBuildTypeExternalId() + "), JWT features: " + jwtBuildFeatures.size());

        if (!jwtBuildFeatures.isEmpty()) {
            try {
                final var descriptor = jwtBuildFeatures.stream().findFirst().orElseThrow();
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
                    return;
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
                            + build.getBuildId() + ": " + unknownClaims.stream().map(JwtBuildStartContext::sanitize).collect(Collectors.toSet()));
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
                final var serialized = signedJWT.serialize();
                buildStartContext.addSharedParameter(JwtPasswordsProvider.JWT_PARAMETER_NAME, serialized);
                LOG.info("JWT plugin: JWT issued successfully for build " + build.getBuildId()
                        + " (iss=" + sanitize(issuerUrl) + ", aud=" + sanitize(audience) + ", alg=" + sanitize(algorithmName)
                        + ", kid=" + signedJWT.getHeader().getKeyID() + ")");
            } catch (final JOSEException e) {
                LOG.log(Level.SEVERE, "JWT plugin: JOSEException while signing JWT for build " + build.getBuildId(), e);
                throw new RuntimeException("JWT plugin: failed to sign token — check the TeamCity server log for details");
            } catch (final Exception e) {
                LOG.log(Level.SEVERE, "JWT plugin: unexpected exception in updateParameters for build " + build.getBuildId(), e);
                throw new RuntimeException("JWT plugin: unexpected error issuing token — check the TeamCity server log for details");
            }
        }
    }
}
