package de.ndr.teamcity;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.*;
import jetbrains.buildServer.users.SUser;
import org.jetbrains.annotations.NotNull;
import org.joda.time.DateTime;

import java.util.Collection;
import java.util.List;

public class JwtBuildStartContext implements BuildStartContextProcessor  {
    private final ExtensionHolder extensionHolder;

    private final SBuildServer buildServer;

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
                JwtBuildFeature jwtBuildFeature = (JwtBuildFeature) jwtBuildFeatures.stream().findFirst().get().getBuildFeature();
                RSAKey rsaKey = jwtBuildFeature.getRsaKey();

                SRunningBuild build = buildStartContext.getBuild();

                JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .type(JOSEObjectType.JWT)
                        .keyID(rsaKey.getKeyID())
                        .build();

                String buildServerRootUrl = buildServer.getRootUrl();
                if (!buildServerRootUrl.startsWith("https://")) {
                    throw new IllegalStateException(
                            "TeamCity root URL must use HTTPS for OIDC token issuance, but was: " + buildServerRootUrl);
                }

                Branch branch = build.getBranch();
                String branchName = branch != null ? branch.getName() : "";

                TriggeredBy triggeredBy = build.getTriggeredBy();
                SUser user = triggeredBy.getUser();

                DateTime now = new DateTime();
                JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                        .subject(build.getBuildTypeExternalId())
                        .audience(List.of(buildServerRootUrl))
                        .issuer(buildServerRootUrl)
                        .issueTime(now.toDate()) // iat
                        .notBeforeTime(now.toDate()) // nbf
                        .expirationTime(now.plusHours(1).toDate()) // exp
                        .claim("branch", branchName)
                        .claim("build_type_external_id", build.getBuildTypeExternalId())
                        .claim("project_external_id", build.getProjectExternalId())
                        .claim("triggered_by", triggeredBy.getAsString())
                        .claim("build_number", build.getBuildNumber());

                if (user != null) {
                    claimsBuilder.claim("triggered_by_id", user.getId());
                }

                JWTClaimsSet jwtClaimsSet = claimsBuilder.build();

                SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
                JWSSigner signer = new RSASSASigner(rsaKey);
                signedJWT.sign(signer);

                buildStartContext.addSharedParameter("env.JWT", signedJWT.serialize());
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }
        }
    }

}
