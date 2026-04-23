package com.octopus.teamcity.oidc;

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
        keyManager = TestJwtKeyManagerFactory.create(serverPaths);
    }

    @Test
    public void rotationGeneratesNewRsaAndEcKeys() throws Exception {
        final var originalRsa = keyManager.getRsaKey();
        final var originalEc = keyManager.getEcKey();

        keyManager.rotateKey();

        assertThat(keyManager.getRsaKey().getKeyID()).isNotEqualTo(originalRsa.getKeyID());
        assertThat(keyManager.getEcKey().getKeyID()).isNotEqualTo(originalEc.getKeyID());
    }

    @Test
    public void jwksContainsCurrentAndRetiredKeysAfterRotation() throws Exception {
        final var originalRsa = keyManager.getRsaKey();
        final var originalRsa3072 = keyManager.getRsa3072Key();
        final var originalEc = keyManager.getEcKey();

        keyManager.rotateKey();
        final var newRsa = keyManager.getRsaKey();
        final var newRsa3072 = keyManager.getRsa3072Key();
        final var newEc = keyManager.getEcKey();

        final var keys = jwksKeys();
        assertThat(keys).hasSize(6);
        assertThat(kidsIn(keys)).contains(
                originalRsa.getKeyID(), newRsa.getKeyID(),
                originalRsa3072.getKeyID(), newRsa3072.getKeyID(),
                originalEc.getKeyID(), newEc.getKeyID());
    }

    @Test
    public void rotatingAgainRetiresPreviousRetiredKeys() throws Exception {
        final var rsa1 = keyManager.getRsaKey();
        final var rsa3072_1 = keyManager.getRsa3072Key();
        final var ec1 = keyManager.getEcKey();

        keyManager.rotateKey();
        final var rsa2 = keyManager.getRsaKey();
        final var rsa3072_2 = keyManager.getRsa3072Key();
        final var ec2 = keyManager.getEcKey();

        keyManager.rotateKey();
        final var rsa3 = keyManager.getRsaKey();
        final var rsa3072_3 = keyManager.getRsa3072Key();
        final var ec3 = keyManager.getEcKey();

        final var keys = jwksKeys();
        assertThat(keys).hasSize(6);
        assertThat(kidsIn(keys)).doesNotContain(rsa1.getKeyID(), rsa3072_1.getKeyID(), ec1.getKeyID());
        assertThat(kidsIn(keys)).contains(
                rsa2.getKeyID(), rsa3.getKeyID(),
                rsa3072_2.getKeyID(), rsa3072_3.getKeyID(),
                ec2.getKeyID(), ec3.getKeyID());
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

    private List<String> kidsIn(final JsonArray keys) {
        final var kids = new ArrayList<String>();
        for (var i = 0; i < keys.size(); i++) {
            kids.add(keys.get(i).getAsJsonObject().get("kid").getAsString());
        }
        return kids;
    }
}
