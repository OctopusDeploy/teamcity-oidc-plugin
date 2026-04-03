package com.octopus.teamcity.oidc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.*;
import jetbrains.buildServer.users.SUser;
import org.jetbrains.annotations.NotNull;
import org.joda.time.DateTime;

import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class JwtBuildStartContext implements BuildStartContextProcessor {
    private static final Logger LOG = Logger.getLogger(JwtBuildStartContext.class.getName());

    private final ExtensionHolder extensionHolder;
    private final SBuildServer buildServer;
    private final JwtKeyManager keyManager;

    private static final Set<String> ALL_CUSTOM_CLAIMS = Set.of(
            "branch", "build_type_external_id", "project_external_id",
            "triggered_by", "triggered_by_id", "build_number");

    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    public JwtBuildStartContext(@NotNull ExtensionHolder extensionHolder,
                                @NotNull SBuildServer buildServer,
                                @NotNull JwtKeyManager keyManager) {
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
        SRunningBuild build = buildStartContext.getBuild();
        Collection<SBuildFeatureDescriptor> jwtBuildFeatures = build.getBuildFeaturesOfType(JwtBuildFeature.FEATURE_TYPE);

        LOG.fine("JWT plugin: updateParameters called for build " + build.getBuildId()
                + " (" + build.getBuildTypeExternalId() + "), JWT features: " + jwtBuildFeatures.size());

        if (!jwtBuildFeatures.isEmpty()) {
            try {
                SBuildFeatureDescriptor descriptor = jwtBuildFeatures.stream().findFirst().get();
                Map<String, String> params = descriptor.getParameters();

                int ttlMinutes = Integer.parseInt(params.getOrDefault("ttl_minutes", "10"));
                String algorithmName = params.getOrDefault("algorithm", "RS256");

                String buildServerRootUrl = buildServer.getRootUrl();
                LOG.info("JWT plugin: issuing JWT for build " + build.getBuildId()
                        + ", rootUrl=" + buildServerRootUrl + ", algorithm=" + algorithmName);

                if (!JwtKeyManager.isHttpsUrl(buildServerRootUrl)) {
                    LOG.warning("JWT plugin: skipping JWT — root URL is not HTTPS: " + buildServerRootUrl);
                    return;
                }

                String audience = params.getOrDefault("audience", buildServerRootUrl);

                String claimsParam = params.get("claims");
                Set<String> enabledClaims = (claimsParam == null || claimsParam.isBlank())
                        ? ALL_CUSTOM_CLAIMS
                        : new HashSet<>(Arrays.asList(claimsParam.split("\\s*,\\s*")));

                Branch branch = build.getBranch();
                String branchName = branch != null ? branch.getName() : "";

                TriggeredBy triggeredBy = build.getTriggeredBy();
                SUser user = triggeredBy.getUser();

                DateTime now = new DateTime();
                JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
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

                SignedJWT signedJWT = keyManager.sign(claimsBuilder.build(), algorithmName);
                String serialized = signedJWT.serialize();
                buildStartContext.addSharedParameter(JwtPasswordsProvider.JWT_PARAMETER_NAME, serialized);
                LOG.info("JWT plugin: JWT issued successfully for build " + build.getBuildId()
                        + " (iss=" + buildServerRootUrl + ", aud=" + audience + ", alg=" + algorithmName
                        + ", kid=" + signedJWT.getHeader().getKeyID() + ")");
            } catch (JOSEException e) {
                LOG.log(Level.SEVERE, "JWT plugin: JOSEException while signing JWT for build " + build.getBuildId(), e);
                throw new RuntimeException(e);
            } catch (Exception e) {
                LOG.log(Level.SEVERE, "JWT plugin: unexpected exception in updateParameters for build " + build.getBuildId(), e);
                throw e;
            }
        }
    }
}
