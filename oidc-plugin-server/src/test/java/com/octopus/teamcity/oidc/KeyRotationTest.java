package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.ServerPaths;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
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
        final var originalEc = keyManager.getEcKey();

        keyManager.rotateKey();
        final var newRsa = keyManager.getRsaKey();
        final var newEc = keyManager.getEcKey();

        final var keys = jwksKeys();
        assertThat(keys).hasSize(4);
        assertThat(kidsIn(keys)).contains(originalRsa.getKeyID(), newRsa.getKeyID(),
                                           originalEc.getKeyID(), newEc.getKeyID());
    }

    @Test
    public void rotatingAgainRetiresPreviousRetiredKeys() throws Exception {
        final var rsa1 = keyManager.getRsaKey();
        final var ec1 = keyManager.getEcKey();

        keyManager.rotateKey();
        final var rsa2 = keyManager.getRsaKey();
        final var ec2 = keyManager.getEcKey();

        keyManager.rotateKey();
        final var rsa3 = keyManager.getRsaKey();
        final var ec3 = keyManager.getEcKey();

        final var keys = jwksKeys();
        assertThat(keys).hasSize(4);
        assertThat(kidsIn(keys)).doesNotContain(rsa1.getKeyID(), ec1.getKeyID());
        assertThat(kidsIn(keys)).contains(rsa2.getKeyID(), rsa3.getKeyID(), ec2.getKeyID(), ec3.getKeyID());
    }

    // --- helpers ---

    private JSONArray jwksKeys() throws Exception {
        final var filter = new WellKnownPublicFilter(keyManager, mock(jetbrains.buildServer.serverSide.SBuildServer.class));
        final var request = mock(HttpServletRequest.class);
        final var response = mock(HttpServletResponse.class);
        final var writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.JWKS_PATH);
        when(request.getContextPath()).thenReturn("");
        filter.doFilter(request, response, mock(FilterChain.class));
        final var parsed = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(writer.toString());
        return (JSONArray) parsed.get("keys");
    }

    private List<String> kidsIn(final JSONArray keys) {
        final var kids = new ArrayList<String>();
        for (var i = 0; i < keys.size(); i++) {
            kids.add((String) ((JSONObject) keys.get(i)).get("kid"));
        }
        return kids;
    }
}
