package com.octopus.teamcity.oidc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.*;
import org.jetbrains.annotations.NotNull;
import org.joda.time.DateTime;

import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class JwtBuildStartContext implements BuildStartContextProcessor {
    private static final Logger LOG = Logger.getLogger(JwtBuildStartContext.class.getName());

    private final ExtensionHolder extensionHolder;
    private final SBuildServer buildServer;
    private final JwtKeyManager keyManager;

    private static final Set<String> ALL_CUSTOM_CLAIMS = Set.of(
            "branch", "build_type_external_id", "project_external_id",
            "triggered_by", "triggered_by_id", "build_number");

    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    public JwtBuildStartContext(@NotNull final ExtensionHolder extensionHolder,
                                @NotNull final SBuildServer buildServer,
                                @NotNull final JwtKeyManager keyManager) {
        this.extensionHolder = extensionHolder;
        this.buildServer = buildServer;
        this.keyManager = keyManager;
    }

    public void register() {
        extensionHolder.registerExtension(BuildStartContextProcessor.class, this.getClass().getName(), this);
        LOG.info("JWT plugin: JwtBuildStartContext registered as BuildStartContextProcessor");
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

                final var ttlMinutes = Math.max(1, Math.min(1440,
                        Integer.parseInt(params.getOrDefault("ttl_minutes", "10"))));
                final var algorithmName = params.getOrDefault("algorithm", "RS256");

                final var buildServerRootUrl = JwtKeyManager.normalizeRootUrl(buildServer.getRootUrl());
                LOG.info("JWT plugin: issuing JWT for build " + build.getBuildId()
                        + ", rootUrl=" + buildServerRootUrl + ", algorithm=" + algorithmName);

                if (!JwtKeyManager.isHttpsUrl(buildServerRootUrl)) {
                    LOG.warning("JWT plugin: skipping JWT — root URL is not HTTPS: " + buildServerRootUrl);
                    return;
                }

                final var rawAudience = params.getOrDefault("audience", "");
                final var audience = rawAudience.isBlank() ? buildServerRootUrl : rawAudience;

                final var claimsParam = params.get("claims");
                final Set<String> requestedClaims = (claimsParam == null || claimsParam.isBlank())
                        ? ALL_CUSTOM_CLAIMS
                        : new HashSet<>(Arrays.asList(claimsParam.split("\\s*,\\s*")));
                final var unknownClaims = requestedClaims.stream()
                        .filter(c -> !ALL_CUSTOM_CLAIMS.contains(c))
                        .collect(Collectors.toSet());
                if (!unknownClaims.isEmpty()) {
                    LOG.warning("JWT plugin: ignoring unrecognised claim names for build "
                            + build.getBuildId() + ": " + unknownClaims);
                }
                final var enabledClaims = requestedClaims.stream()
                        .filter(ALL_CUSTOM_CLAIMS::contains)
                        .collect(Collectors.toSet());

                final var branch = build.getBranch();
                final var branchName = branch != null ? branch.getName() : "";

                final var triggeredBy = build.getTriggeredBy();
                final var user = triggeredBy.getUser();

                final var now = new DateTime();
                final var claimsBuilder = new JWTClaimsSet.Builder()
                        .jwtID(build.getBuildId() + "-" + UUID.randomUUID())
                        .subject(build.getBuildTypeExternalId())
                        .audience(List.of(audience))
                        .issuer(buildServerRootUrl)
                        .issueTime(now.toDate())
                        .notBeforeTime(now.toDate())
                        .expirationTime(now.plusMinutes(ttlMinutes).toDate());

                if (enabledClaims.contains("branch")) {
                    claimsBuilder.claim("branch", branchName);
                }
                if (enabledClaims.contains("build_type_external_id")) {
                    claimsBuilder.claim("build_type_external_id", build.getBuildTypeExternalId());
                }
                if (enabledClaims.contains("project_external_id")) {
                    claimsBuilder.claim("project_external_id", build.getProjectExternalId());
                }
                if (enabledClaims.contains("triggered_by")) {
                    claimsBuilder.claim("triggered_by", triggeredBy.getAsString());
                }
                if (enabledClaims.contains("triggered_by_id") && user != null) {
                    claimsBuilder.claim("triggered_by_id", user.getId());
                }
                if (enabledClaims.contains("build_number")) {
                    claimsBuilder.claim("build_number", build.getBuildNumber());
                }

                final var signedJWT = keyManager.sign(claimsBuilder.build(), algorithmName);
                final var serialized = signedJWT.serialize();
                buildStartContext.addSharedParameter(JwtPasswordsProvider.JWT_PARAMETER_NAME, serialized);
                LOG.info("JWT plugin: JWT issued successfully for build " + build.getBuildId()
                        + " (iss=" + buildServerRootUrl + ", aud=" + audience + ", alg=" + algorithmName
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
