package de.ndr.teamcity;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.*;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AlgorithmChoiceTest {

    @Mock
    ExtensionHolder extensionHolder;

    @Mock
    SBuildServer buildServer;

    @Mock
    SRunningBuild runningBuild;

    @Mock
    BuildStartContext buildStartContext;

    @Mock
    SBuildFeatureDescriptor featureDescriptor;

    @Mock
    private ServerPaths serverPaths;

    @Mock
    private PluginDescriptor pluginDescriptor;

    @TempDir
    private File tempDir;

    @Test
    public void usesRS256ByDefault() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        JwtBuildStartContext context = new JwtBuildStartContext(extensionHolder, buildServer);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("JWT-Plugin")).thenReturn(List.of(featureDescriptor));
        when(featureDescriptor.getBuildFeature()).thenReturn(jwtBuildFeature);
        when(featureDescriptor.getParameters()).thenReturn(Map.of());

        TriggeredBy triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);

        ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
        context.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        SignedJWT jwt = SignedJWT.parse(jwtCaptor.getValue());
        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(jwt.verify(new RSASSAVerifier(jwtBuildFeature.getRsaKey().toPublicJWK()))).isTrue();
    }

    @Test
    public void usesES256WhenConfigured() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        when(buildServer.getRootUrl()).thenReturn("https://localhost:8111");
        JwtBuildStartContext context = new JwtBuildStartContext(extensionHolder, buildServer);

        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("JWT-Plugin")).thenReturn(List.of(featureDescriptor));
        when(featureDescriptor.getBuildFeature()).thenReturn(jwtBuildFeature);
        when(featureDescriptor.getParameters()).thenReturn(Map.of("algorithm", "ES256"));

        TriggeredBy triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);

        ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
        context.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), jwtCaptor.capture());

        SignedJWT jwt = SignedJWT.parse(jwtCaptor.getValue());
        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
        assertThat(jwt.verify(new ECDSAVerifier(jwtBuildFeature.getEcKey().toPublicJWK()))).isTrue();
    }

    @Test
    public void jwksIncludesBothRsaAndEcPublicKeys() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        List<JWK> keys = jwtBuildFeature.getPublicKeys();
        assertThat(keys).hasSize(2);
        assertThat(keys.stream().anyMatch(k -> k.getAlgorithm() != null && k.getAlgorithm().getName().equals("RS256"))).isTrue();
        assertThat(keys.stream().anyMatch(k -> k.getAlgorithm() != null && k.getAlgorithm().getName().equals("ES256"))).isTrue();
    }

    @Test
    public void ecKeyIdIsThumbprintOfPublicKey() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        ECKey ecKey = jwtBuildFeature.getEcKey();
        assertThat(ecKey.getKeyID()).isEqualTo(ecKey.computeThumbprint().toString());
    }
}
