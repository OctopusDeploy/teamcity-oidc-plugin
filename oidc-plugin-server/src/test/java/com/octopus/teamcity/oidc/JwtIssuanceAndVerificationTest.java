package com.octopus.teamcity.oidc;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.*;
import jetbrains.buildServer.serverSide.ServerPaths;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
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
    @Mock SBuildServer buildServer;
    @Mock ExtensionHolder extensionHolder;
    @Mock BuildStartContext buildStartContext;
    @Mock SRunningBuild runningBuild;
    @Mock SBuildFeatureDescriptor featureDescriptor;

    @TempDir File tempDir;

    private JwtKeyManager keyManager;

    @BeforeEach
    void setUp() {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        keyManager = new JwtKeyManager(serverPaths);
    }

    @Test
    public void rs256JwtSignatureVerifiesAgainstJwksPublicKey() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");

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
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");

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
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");

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
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");

        setupBuildContext(Map.of("audience", "my-cloud-audience", "ttl_minutes", "5"));

        final var branch = mock(Branch.class);
        when(branch.getName()).thenReturn("refs/heads/main");
        when(runningBuild.getBranch()).thenReturn(branch);
        when(runningBuild.getBuildTypeExternalId()).thenReturn("My_BuildType");

        final var tokenCaptor = ArgumentCaptor.forClass(String.class);
        new JwtBuildStartContext(extensionHolder, buildServer, keyManager).updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq(JwtPasswordsProvider.JWT_PARAMETER_NAME), tokenCaptor.capture());

        final var jwt = SignedJWT.parse(tokenCaptor.getValue());
        final var claims = jwt.getJWTClaimsSet();

        assertThat(claims.getIssuer()).isEqualTo("https://teamcity.example.com");
        assertThat(claims.getAudience()).containsExactly("my-cloud-audience");
        assertThat(claims.getSubject()).isEqualTo("My_BuildType");
        assertThat(claims.getStringClaim("branch")).isEqualTo("refs/heads/main");
        assertThat(claims.getIssueTime()).isNotNull();
        assertThat(claims.getExpirationTime()).isNotNull();

        final var ttlSeconds = (claims.getExpirationTime().getTime() - claims.getIssueTime().getTime()) / 1000;
        assertThat(ttlSeconds).isEqualTo(5 * 60);
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
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");

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
        setupBuildContext(params);
        final var tokenCaptor = ArgumentCaptor.forClass(String.class);
        new JwtBuildStartContext(extensionHolder, buildServer, keyManager).updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq(JwtPasswordsProvider.JWT_PARAMETER_NAME), tokenCaptor.capture());
        return tokenCaptor.getValue();
    }

    private void setupBuildContext(final Map<String, String> params) {
        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(featureDescriptor));
        when(featureDescriptor.getParameters()).thenReturn(params);
        final var triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);
    }

    private JWKSet getJwks() {
        return new JWKSet(keyManager.getPublicKeys());
    }
}
