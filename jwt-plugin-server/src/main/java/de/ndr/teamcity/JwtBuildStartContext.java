package de.ndr.teamcity;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.*;
import jetbrains.buildServer.users.SUser;
import org.jetbrains.annotations.NotNull;
import org.joda.time.DateTime;

import java.util.*;

public class JwtBuildStartContext implements BuildStartContextProcessor  {
    private final ExtensionHolder extensionHolder;

    private final SBuildServer buildServer;

    private static final Set<String> ALL_CUSTOM_CLAIMS = Set.of(
            "branch", "build_type_external_id", "project_external_id",
            "triggered_by", "triggered_by_id", "build_number");

    public JwtBuildStartContext(@NotNull final ExtensionHolder extensionHolder, @NotNull SBuildServer buildServer) {
        this.extensionHolder = extensionHolder;
        this.buildServer = buildServer;
    }

    public void register() {
        extensionHolder.registerExtension(BuildStartContextProcessor.class, this.getClass().getName(), this);
    }

    @Override
    public void updateParameters(@NotNull final BuildStartContext buildStartContext) {
        Collection<SBuildFeatureDescriptor> jwtBuildFeatures = buildStartContext.getBuild().getBuildFeaturesOfType("JWT-Plugin");

        if (!jwtBuildFeatures.isEmpty()) {
            try {
                SBuildFeatureDescriptor descriptor = jwtBuildFeatures.stream().findFirst().get();
                JwtBuildFeature jwtBuildFeature = (JwtBuildFeature) descriptor.getBuildFeature();
                Map<String, String> params = descriptor.getParameters();

                int ttlMinutes = Integer.parseInt(params.getOrDefault("ttl_minutes", "10"));
                String algorithmName = params.getOrDefault("algorithm", "RS256");

                SRunningBuild build = buildStartContext.getBuild();

                String buildServerRootUrl = buildServer.getRootUrl();
                if (!buildServerRootUrl.startsWith("https://")) {
                    throw new IllegalStateException(
                            "TeamCity root URL must use HTTPS for OIDC token issuance, but was: " + buildServerRootUrl);
                }

                String audience = params.getOrDefault("audience", buildServerRootUrl);

                String claimsParam = params.get("claims");
                Set<String> enabledClaims = claimsParam != null
                        ? new HashSet<>(Arrays.asList(claimsParam.split("\\s*,\\s*")))
                        : ALL_CUSTOM_CLAIMS;

                JWSHeader jwsHeader;
                JWSSigner signer;
                if ("ES256".equals(algorithmName)) {
                    ECKey ecKey = jwtBuildFeature.getEcKey();
                    jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .type(JOSEObjectType.JWT)
                            .keyID(ecKey.getKeyID())
                            .build();
                    signer = new ECDSASigner(ecKey);
                } else {
                    RSAKey rsaKey = jwtBuildFeature.getRsaKey();
                    jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .type(JOSEObjectType.JWT)
                            .keyID(rsaKey.getKeyID())
                            .build();
                    signer = new RSASSASigner(rsaKey);
                }

                Branch branch = build.getBranch();
                String branchName = branch != null ? branch.getName() : "";

                TriggeredBy triggeredBy = build.getTriggeredBy();
                SUser user = triggeredBy.getUser();

                DateTime now = new DateTime();
                JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
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

                JWTClaimsSet jwtClaimsSet = claimsBuilder.build();

                SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
                signedJWT.sign(signer);

                buildStartContext.addSharedParameter(JwtPasswordsProvider.JWT_PARAMETER_NAME, signedJWT.serialize());
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }
        }
    }

}
