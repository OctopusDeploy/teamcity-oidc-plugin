package com.octopus.teamcity.oidc;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.*;
import jetbrains.buildServer.users.SUser;
import jetbrains.buildServer.serverSide.ServerPaths;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
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

    @Test
    public void rs256JwtSignatureVerifiesAgainstJwksPublicKey() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");
        JwtKeyManager keyManager = new JwtKeyManager(serverPaths);

        String token = issueToken(keyManager, Map.of());

        JWKSet jwks = getJwks(keyManager);
        SignedJWT jwt = SignedJWT.parse(token);

        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);

        JWK signingKey = jwks.getKeyByKeyId(jwt.getHeader().getKeyID());
        assertThat(signingKey).as("signing key must be in JWKS").isNotNull();
        assertThat(signingKey).isInstanceOf(RSAKey.class);
        assertThat(signingKey.isPrivate()).isFalse();

        assertThat(jwt.verify(new RSASSAVerifier((RSAKey) signingKey))).isTrue();
    }

    @Test
    public void es256JwtSignatureVerifiesAgainstJwksPublicKey() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");
        JwtKeyManager keyManager = new JwtKeyManager(serverPaths);

        String token = issueToken(keyManager, Map.of("algorithm", "ES256"));

        JWKSet jwks = getJwks(keyManager);
        SignedJWT jwt = SignedJWT.parse(token);

        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);

        JWK signingKey = jwks.getKeyByKeyId(jwt.getHeader().getKeyID());
        assertThat(signingKey).as("signing key must be in JWKS").isNotNull();
        assertThat(signingKey).isInstanceOf(ECKey.class);
        assertThat(signingKey.isPrivate()).isFalse();

        assertThat(jwt.verify(new ECDSAVerifier((ECKey) signingKey))).isTrue();
    }

    @Test
    public void jwtIssuedBeforeKeyRotationRemainsVerifiableAfterRotation() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");
        JwtKeyManager keyManager = new JwtKeyManager(serverPaths);

        String tokenBeforeRotation = issueToken(keyManager, Map.of());
        SignedJWT jwtBefore = SignedJWT.parse(tokenBeforeRotation);
        String kidBefore = jwtBefore.getHeader().getKeyID();

        keyManager.rotateKey();

        JWKSet jwksAfterRotation = getJwks(keyManager);
        JWK oldKey = jwksAfterRotation.getKeyByKeyId(kidBefore);
        assertThat(oldKey).as("old key should still be in JWKS after rotation").isNotNull();

        assertThat(jwtBefore.verify(new RSASSAVerifier((RSAKey) oldKey))).isTrue();
    }

    @Test
    public void jwtClaimsMatchBuildContextAndConfiguration() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");
        JwtKeyManager keyManager = new JwtKeyManager(serverPaths);

        setupBuildContext(Map.of("audience", "my-cloud-audience", "ttl_minutes", "5"));

        Branch branch = mock(Branch.class);
        when(branch.getName()).thenReturn("refs/heads/main");
        when(runningBuild.getBranch()).thenReturn(branch);
        when(runningBuild.getBuildTypeExternalId()).thenReturn("My_BuildType");

        ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);
        new JwtBuildStartContext(extensionHolder, buildServer, keyManager).updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq(JwtPasswordsProvider.JWT_PARAMETER_NAME), tokenCaptor.capture());

        SignedJWT jwt = SignedJWT.parse(tokenCaptor.getValue());
        final var claims = jwt.getJWTClaimsSet();

        assertThat(claims.getIssuer()).isEqualTo("https://teamcity.example.com");
        assertThat(claims.getAudience()).containsExactly("my-cloud-audience");
        assertThat(claims.getSubject()).isEqualTo("My_BuildType");
        assertThat(claims.getStringClaim("branch")).isEqualTo("refs/heads/main");
        assertThat(claims.getIssueTime()).isNotNull();
        assertThat(claims.getExpirationTime()).isNotNull();

        long ttlSeconds = (claims.getExpirationTime().getTime() - claims.getIssueTime().getTime()) / 1000;
        assertThat(ttlSeconds).isEqualTo(5 * 60);
    }

    @Test
    public void jwksContainsOnlyPublicKeys() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtKeyManager keyManager = new JwtKeyManager(serverPaths);

        JWKSet jwks = getJwks(keyManager);

        for (JWK key : jwks.getKeys()) {
            assertThat(key.isPrivate()).as("JWKS must not expose private key material for " + key.getKeyID()).isFalse();
        }
    }

    @Test
    public void jwtSignedWithNewKeyVerifiesAfterRotation() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");
        JwtKeyManager keyManager = new JwtKeyManager(serverPaths);

        keyManager.rotateKey();

        String token = issueToken(keyManager, Map.of());
        SignedJWT jwt = SignedJWT.parse(token);
        JWKSet jwks = getJwks(keyManager);

        JWK signingKey = jwks.getKeyByKeyId(jwt.getHeader().getKeyID());
        assertThat(signingKey).as("new key must be in JWKS after rotation").isNotNull();
        assertThat(jwt.verify(new RSASSAVerifier((RSAKey) signingKey))).isTrue();
    }

    // --- helpers ---

    private String issueToken(JwtKeyManager keyManager, Map<String, String> params) throws Exception {
        setupBuildContext(params);
        ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);
        new JwtBuildStartContext(extensionHolder, buildServer, keyManager).updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq(JwtPasswordsProvider.JWT_PARAMETER_NAME), tokenCaptor.capture());
        return tokenCaptor.getValue();
    }

    private void setupBuildContext(Map<String, String> params) {
        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(featureDescriptor));
        when(featureDescriptor.getParameters()).thenReturn(params);
        TriggeredBy triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);
    }

    private JWKSet getJwks(JwtKeyManager keyManager) throws Exception {
        WellKnownPublicFilter filter = new WellKnownPublicFilter(keyManager, mock(SBuildServer.class));
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.JWKS_PATH);
        when(request.getContextPath()).thenReturn("");
        filter.doFilter(request, response, mock(javax.servlet.FilterChain.class));
        return JWKSet.parse(writer.toString());
    }
}
