package com.octopus.teamcity.oidc;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import jetbrains.buildServer.serverSide.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class JwtIssuanceAndVerificationTest {

    @Mock ServerPaths serverPaths;
    @Mock SRunningBuild runningBuild;
    @Mock SBuildFeatureDescriptor featureDescriptor;

    @TempDir File tempDir;

    private JwtKeyManager keyManager;

    @BeforeEach
    void setUp() {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        keyManager = TestJwtKeyManagerFactory.create(serverPaths);
    }

    private SBuildServer buildServerWithRootUrl(final String url) {
        final var server = mock(SBuildServer.class);
        lenient().when(server.getRootUrl()).thenReturn(url);
        return server;
    }

    private OidcIssuerUrlProvider providerFor(final String issuerUrl) {
        return new OidcIssuerUrlProvider(buildServerWithRootUrl(issuerUrl), new OidcSettingsManager(tempDir));
    }

    @Test
    public void rs256JwtSignatureVerifiesAgainstJwksPublicKey() throws Exception {
        final var token = issueToken(Map.of());

        final var jwks = getJwks();
        final var jwt = SignedJWT.parse(token);

        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);

        final var signingKey = jwks.getKeyByKeyId(jwt.getHeader().getKeyID());
        assertThat(signingKey).as("signing key must be in JWKS").isNotNull();
        assertThat(signingKey).isInstanceOf(RSAKey.class);
        assertThat(signingKey.isPrivate()).isFalse();

        assertThat(jwt.verify(new RSASSAVerifier((RSAKey) signingKey))).isTrue();
    }

    @Test
    public void es256JwtSignatureVerifiesAgainstJwksPublicKey() throws Exception {
        final var token = issueToken(Map.of("algorithm", "ES256"));

        final var jwks = getJwks();
        final var jwt = SignedJWT.parse(token);

        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);

        final var signingKey = jwks.getKeyByKeyId(jwt.getHeader().getKeyID());
        assertThat(signingKey).as("signing key must be in JWKS").isNotNull();
        assertThat(signingKey).isInstanceOf(ECKey.class);
        assertThat(signingKey.isPrivate()).isFalse();

        assertThat(jwt.verify(new ECDSAVerifier((ECKey) signingKey))).isTrue();
    }

    @Test
    public void jwtIssuedBeforeKeyRotationRemainsVerifiableAfterRotation() throws Exception {
        final var tokenBeforeRotation = issueToken(Map.of());
        final var jwtBefore = SignedJWT.parse(tokenBeforeRotation);
        final var kidBefore = jwtBefore.getHeader().getKeyID();

        keyManager.rotateKey();

        final var jwksAfterRotation = getJwks();
        final var oldKey = jwksAfterRotation.getKeyByKeyId(kidBefore);
        assertThat(oldKey).as("old key should still be in JWKS after rotation").isNotNull();

        assertThat(jwtBefore.verify(new RSASSAVerifier((RSAKey) oldKey))).isTrue();
    }

    @Test
    public void jwtClaimsMatchBuildContextAndConfiguration() throws Exception {
        final var branch = mock(Branch.class);
        when(branch.getName()).thenReturn("refs/heads/main");
        when(runningBuild.getBranch()).thenReturn(branch);
        when(runningBuild.getBuildTypeId()).thenReturn("bt42");
        when(runningBuild.getProjectId()).thenReturn("project7");

        final var jwt = SignedJWT.parse(issueToken(Map.of("audience", "my-cloud-audience", "ttl_minutes", "5")));
        final var claims = jwt.getJWTClaimsSet();

        assertThat(claims.getIssuer()).isEqualTo("https://teamcity.example.com");
        assertThat(claims.getAudience()).containsExactly("my-cloud-audience");
        assertThat(claims.getSubject())
                .isEqualTo("project:project7:build_type:bt42:branch:refs/heads/main:trigger_type:unknown");
        assertThat(claims.getStringClaim("branch")).isEqualTo("refs/heads/main");
        assertThat(claims.getIssueTime()).isNotNull();
        assertThat(claims.getExpirationTime()).isNotNull();

        final var ttlSeconds = (claims.getExpirationTime().getTime() - claims.getIssueTime().getTime()) / 1000;
        assertThat(ttlSeconds).isEqualTo(5 * 60);
    }

    @Test
    public void subjectIsMinimalCompositeWhenNoOptionalDimensionsConfigured() throws Exception {
        when(runningBuild.getBuildTypeId()).thenReturn("bt42");
        when(runningBuild.getProjectId()).thenReturn("project7");

        final var jwt = SignedJWT.parse(issueToken(Map.of("subject_dimensions", "none")));
        final var sub = jwt.getJWTClaimsSet().getSubject();

        assertThat(sub).isEqualTo("project:project7:build_type:bt42");
    }

    @Test
    public void subjectIncludesOnlyConfiguredOptionalDimensions() throws Exception {
        when(runningBuild.getBuildTypeId()).thenReturn("bt42");
        when(runningBuild.getProjectId()).thenReturn("project7");
        final var branch = mock(Branch.class);
        when(branch.getName()).thenReturn("refs/heads/main");
        when(runningBuild.getBranch()).thenReturn(branch);

        final var jwt = SignedJWT.parse(issueToken(Map.of("subject_dimensions", "branch")));
        final var sub = jwt.getJWTClaimsSet().getSubject();

        assertThat(sub).isEqualTo("project:project7:build_type:bt42:branch:refs/heads/main");
    }

    @Test
    public void branchAndTriggerTypeClaimsAreAlwaysEmittedRegardlessOfSubjectScoping() throws Exception {
        final var branch = mock(Branch.class);
        when(branch.getName()).thenReturn("refs/heads/main");
        when(runningBuild.getBranch()).thenReturn(branch);
        when(runningBuild.getBuildTypeId()).thenReturn("bt42");
        when(runningBuild.getProjectId()).thenReturn("project7");

        final var jwt = SignedJWT.parse(issueToken(Map.of("subject_dimensions", "none")));
        final var claims = jwt.getJWTClaimsSet();

        assertThat(claims.getSubject()).isEqualTo("project:project7:build_type:bt42");
        assertThat(claims.getStringClaim("branch")).isEqualTo("refs/heads/main");
        assertThat(claims.getStringClaim("trigger_type")).isEqualTo("unknown");
    }

    @Test
    public void jwtIncludesBothExternalAndInternalIdClaims() throws Exception {
        when(runningBuild.getBuildTypeExternalId()).thenReturn("MyProject_MyBuildType");
        when(runningBuild.getProjectExternalId()).thenReturn("MyProject");
        when(runningBuild.getBuildTypeId()).thenReturn("bt42");
        when(runningBuild.getProjectId()).thenReturn("project7");

        final var jwt = SignedJWT.parse(issueToken(Map.of()));
        final var claims = jwt.getJWTClaimsSet();

        assertThat(claims.getStringClaim("build_type_external_id")).isEqualTo("MyProject_MyBuildType");
        assertThat(claims.getStringClaim("project_external_id")).isEqualTo("MyProject");
        assertThat(claims.getStringClaim("build_type_internal_id")).isEqualTo("bt42");
        assertThat(claims.getStringClaim("project_internal_id")).isEqualTo("project7");
    }

    @Test
    public void jwksContainsOnlyPublicKeys() {
        final var jwks = getJwks();

        for (final var key : jwks.getKeys()) {
            assertThat(key.isPrivate()).as("JWKS must not expose private key material for " + key.getKeyID()).isFalse();
        }
    }

    @Test
    public void jwtSignedWithNewKeyVerifiesAfterRotation() throws Exception {
        keyManager.rotateKey();

        final var token = issueToken(Map.of());
        final var jwt = SignedJWT.parse(token);
        final var jwks = getJwks();

        final var signingKey = jwks.getKeyByKeyId(jwt.getHeader().getKeyID());
        assertThat(signingKey).as("new key must be in JWKS after rotation").isNotNull();
        assertThat(jwt.verify(new RSASSAVerifier((RSAKey) signingKey))).isTrue();
    }

    // --- helpers ---

    private String issueToken(final Map<String, String> params) {
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(featureDescriptor));
        when(featureDescriptor.getParameters()).thenReturn(params);
        final var triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);

        final var service = new JwtIssuanceService(
                providerFor("https://teamcity.example.com"),
                keyManager,
                new OidcSettingsManager(tempDir));
        return service.issueOrGet(runningBuild)
                .orElseThrow(() -> new AssertionError("issueOrGet returned empty"));
    }

    private JWKSet getJwks() {
        return new JWKSet(keyManager.getPublicKeys());
    }
}
