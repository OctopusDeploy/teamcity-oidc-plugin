package com.octopus.teamcity.oidc;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.shaded.gson.JsonArray;
import com.nimbusds.jose.shaded.gson.JsonParser;
import jetbrains.buildServer.serverSide.ServerPaths;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class KeyRotationTest {

    @Mock private ServerPaths serverPaths;

    @TempDir private File tempDir;

    private JwtKeyManager keyManager;

    @BeforeEach
    void setUp() {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        keyManager = new JwtKeyManager(serverPaths);
    }

    @Test
    public void rotationGeneratesNewRsaAndEcKeys() throws Exception {
        final RSAKey originalRsa = keyManager.getRsaKey();
        final ECKey originalEc = keyManager.getEcKey();

        keyManager.rotateKey();

        assertThat(keyManager.getRsaKey().getKeyID()).isNotEqualTo(originalRsa.getKeyID());
        assertThat(keyManager.getEcKey().getKeyID()).isNotEqualTo(originalEc.getKeyID());
    }

    @Test
    public void jwksContainsCurrentAndRetiredKeysAfterRotation() throws Exception {
        final RSAKey originalRsa = keyManager.getRsaKey();
        final ECKey originalEc = keyManager.getEcKey();

        keyManager.rotateKey();
        final RSAKey newRsa = keyManager.getRsaKey();
        final ECKey newEc = keyManager.getEcKey();

        final var keys = jwksKeys();
        assertThat(keys).hasSize(4);
        assertThat(kidsIn(keys)).contains(originalRsa.getKeyID(), newRsa.getKeyID(),
                                           originalEc.getKeyID(), newEc.getKeyID());
    }

    @Test
    public void rotatingAgainRetiresPreviousRetiredKeys() throws Exception {
        final RSAKey rsa1 = keyManager.getRsaKey();
        final ECKey ec1 = keyManager.getEcKey();

        keyManager.rotateKey();
        final RSAKey rsa2 = keyManager.getRsaKey();
        final ECKey ec2 = keyManager.getEcKey();

        keyManager.rotateKey();
        final RSAKey rsa3 = keyManager.getRsaKey();
        final ECKey ec3 = keyManager.getEcKey();

        final var keys = jwksKeys();
        assertThat(keys).hasSize(4);
        assertThat(kidsIn(keys)).doesNotContain(rsa1.getKeyID(), ec1.getKeyID());
        assertThat(kidsIn(keys)).contains(rsa2.getKeyID(), rsa3.getKeyID(), ec2.getKeyID(), ec3.getKeyID());
    }

    // --- helpers ---

    private JsonArray jwksKeys() throws Exception {
        final var filter = new WellKnownPublicFilter(keyManager, mock(jetbrains.buildServer.serverSide.SBuildServer.class));
        final var request = mock(HttpServletRequest.class);
        final var response = mock(HttpServletResponse.class);
        final var writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.JWKS_PATH);
        when(request.getContextPath()).thenReturn("");
        filter.doFilter(request, response, mock(FilterChain.class));
        return JsonParser.parseString(writer.toString()).getAsJsonObject().get("keys").getAsJsonArray();
    }

    private List<String> kidsIn(JsonArray keys) {
        final var kids = new ArrayList<String>();
        for (int i = 0; i < keys.size(); i++) {
            kids.add(keys.get(i).getAsJsonObject().get("kid").getAsString());
        }
        return kids;
    }
}
