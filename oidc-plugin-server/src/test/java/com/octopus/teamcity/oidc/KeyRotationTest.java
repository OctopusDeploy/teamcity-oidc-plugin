package com.octopus.teamcity.oidc;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.shaded.gson.JsonArray;
import com.nimbusds.jose.shaded.gson.JsonParser;
import jetbrains.buildServer.serverSide.ServerPaths;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class KeyRotationTest {

    @Mock private ServerPaths serverPaths;

    @TempDir private File tempDir;

    @Test
    public void rotationGeneratesNewRsaAndEcKeys() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtKeyManager keyManager = new JwtKeyManager(serverPaths);
        RSAKey originalRsa = keyManager.getRsaKey();
        ECKey originalEc = keyManager.getEcKey();

        keyManager.rotateKey();

        assertThat(keyManager.getRsaKey().getKeyID()).isNotEqualTo(originalRsa.getKeyID());
        assertThat(keyManager.getEcKey().getKeyID()).isNotEqualTo(originalEc.getKeyID());
    }

    @Test
    public void jwksContainsCurrentAndRetiredKeysAfterRotation() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtKeyManager keyManager = new JwtKeyManager(serverPaths);
        RSAKey originalRsa = keyManager.getRsaKey();
        ECKey originalEc = keyManager.getEcKey();

        keyManager.rotateKey();
        RSAKey newRsa = keyManager.getRsaKey();
        ECKey newEc = keyManager.getEcKey();

        JsonArray keys = jwksKeys(keyManager);
        assertThat(keys).hasSize(4);

        var kids = kidsInArray(keys);
        assertThat(kids).contains(originalRsa.getKeyID(), newRsa.getKeyID(),
                                   originalEc.getKeyID(), newEc.getKeyID());
    }

    @Test
    public void rotatingAgainRetiresPreviousRetiredKeys() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtKeyManager keyManager = new JwtKeyManager(serverPaths);
        RSAKey rsa1 = keyManager.getRsaKey();
        ECKey ec1 = keyManager.getEcKey();

        keyManager.rotateKey();
        RSAKey rsa2 = keyManager.getRsaKey();
        ECKey ec2 = keyManager.getEcKey();

        keyManager.rotateKey();
        RSAKey rsa3 = keyManager.getRsaKey();
        ECKey ec3 = keyManager.getEcKey();

        JsonArray keys = jwksKeys(keyManager);
        assertThat(keys).hasSize(4);

        var kids = kidsInArray(keys);
        assertThat(kids).doesNotContain(rsa1.getKeyID(), ec1.getKeyID());
        assertThat(kids).contains(rsa2.getKeyID(), rsa3.getKeyID(), ec2.getKeyID(), ec3.getKeyID());
    }

    // --- helpers ---

    private JsonArray jwksKeys(JwtKeyManager keyManager) throws Exception {
        WellKnownPublicFilter filter = new WellKnownPublicFilter(keyManager, mock(jetbrains.buildServer.serverSide.SBuildServer.class));
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.JWKS_PATH);
        when(request.getContextPath()).thenReturn("");
        filter.doFilter(request, response, chain);
        return JsonParser.parseString(writer.toString()).getAsJsonObject().get("keys").getAsJsonArray();
    }

    private java.util.List<String> kidsInArray(JsonArray keys) {
        var kids = new java.util.ArrayList<String>();
        for (int i = 0; i < keys.size(); i++) {
            kids.add(keys.get(i).getAsJsonObject().get("kid").getAsString());
        }
        return kids;
    }
}
