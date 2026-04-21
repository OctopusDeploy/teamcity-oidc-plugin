package com.octopus.teamcity.oidc;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
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
public class AlgorithmChoiceTest {

    @Mock ExtensionHolder extensionHolder;
    @Mock SBuildServer buildServer;
    @Mock SRunningBuild runningBuild;
    @Mock BuildStartContext buildStartContext;
    @Mock SBuildFeatureDescriptor featureDescriptor;
    @Mock ServerPaths serverPaths;

    @TempDir File tempDir;

    private JwtKeyManager keyManager;

    @BeforeEach
    void setUp() {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        keyManager = TestJwtKeyManagerFactory.create(serverPaths, buildServer);
    }

    private JwtBuildStartContext buildContext() {
        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        final var context = new JwtBuildStartContext(extensionHolder, buildServer, keyManager);
        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(featureDescriptor));
        final var triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);
        return context;
    }

    @Test
    public void usesRS256ByDefault() throws Exception {
        final var context = buildContext();
        when(featureDescriptor.getParameters()).thenReturn(Map.of());

        final var jwtCaptor = ArgumentCaptor.forClass(String.class);
        context.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        final var jwt = SignedJWT.parse(jwtCaptor.getValue());
        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(jwt.verify(new RSASSAVerifier(keyManager.getRsaKey().toPublicJWK()))).isTrue();
    }

    @Test
    public void usesES256WhenConfigured() throws Exception {
        final var context = buildContext();
        when(featureDescriptor.getParameters()).thenReturn(Map.of("algorithm", "ES256"));

        final var jwtCaptor = ArgumentCaptor.forClass(String.class);
        context.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        final var jwt = SignedJWT.parse(jwtCaptor.getValue());
        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
        assertThat(jwt.verify(new ECDSAVerifier(keyManager.getEcKey().toPublicJWK()))).isTrue();
    }

    @Test
    public void jwksIncludesBothRsaAndEcPublicKeys() {
        final var keys = keyManager.getPublicKeys();
        assertThat(keys).hasSize(2);
        assertThat(keys.stream().anyMatch(k -> k.getAlgorithm() != null && k.getAlgorithm().getName().equals("RS256"))).isTrue();
        assertThat(keys.stream().anyMatch(k -> k.getAlgorithm() != null && k.getAlgorithm().getName().equals("ES256"))).isTrue();
    }

    @Test
    public void ecKeyIdIsThumbprintOfPublicKey() throws Exception {
        final var ecKey = keyManager.getEcKey();
        assertThat(ecKey.getKeyID()).isEqualTo(ecKey.computeThumbprint().toString());
    }
}
