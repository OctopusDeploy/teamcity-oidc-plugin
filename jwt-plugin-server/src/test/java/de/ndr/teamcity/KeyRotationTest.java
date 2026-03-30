package de.ndr.teamcity;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.shaded.gson.JsonArray;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;
import jetbrains.buildServer.serverSide.ServerPaths;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class KeyRotationTest {

    @Mock
    private WebControllerManager controllerManager;

    @Mock
    private ServerPaths serverPaths;

    @Mock
    private PluginDescriptor pluginDescriptor;

    @TempDir
    private File tempDir;

    @Test
    public void jwksContainsBothKeysAfterRotation() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor);
        RSAKey originalKey = jwtBuildFeature.getRsaKey();

        jwtBuildFeature.rotateKey();
        RSAKey newKey = jwtBuildFeature.getRsaKey();

        assertThat(newKey.getKeyID()).isNotEqualTo(originalKey.getKeyID());

        JwksController controller = new JwksController(controllerManager, jwtBuildFeature);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        controller.doHandle(request, response);

        JsonObject json = JsonParser.parseString(writer.toString()).getAsJsonObject();
        JsonArray keys = json.get("keys").getAsJsonArray();
        assertThat(keys).hasSize(2);

        boolean hasOriginalKid = false;
        boolean hasNewKid = false;
        for (int i = 0; i < keys.size(); i++) {
            String kid = keys.get(i).getAsJsonObject().get("kid").getAsString();
            if (kid.equals(originalKey.getKeyID())) hasOriginalKid = true;
            if (kid.equals(newKey.getKeyID())) hasNewKid = true;
        }
        assertThat(hasOriginalKid).isTrue();
        assertThat(hasNewKid).isTrue();
    }

    @Test
    public void activeKeyIsNewKeyAfterRotation() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor);
        RSAKey originalKey = jwtBuildFeature.getRsaKey();

        jwtBuildFeature.rotateKey();

        RSAKey activeKey = jwtBuildFeature.getRsaKey();
        assertThat(activeKey.getKeyID()).isNotEqualTo(originalKey.getKeyID());
    }

    @Test
    public void rotatingAgainRetiresPreviousRetiredKey() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor);
        RSAKey key1 = jwtBuildFeature.getRsaKey();

        jwtBuildFeature.rotateKey();
        RSAKey key2 = jwtBuildFeature.getRsaKey();

        jwtBuildFeature.rotateKey();
        RSAKey key3 = jwtBuildFeature.getRsaKey();

        JwksController controller = new JwksController(controllerManager, jwtBuildFeature);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));
        controller.doHandle(request, response);

        JsonObject json = JsonParser.parseString(writer.toString()).getAsJsonObject();
        JsonArray keys = json.get("keys").getAsJsonArray();

        // Only current key and the most recently retired key — not key1
        assertThat(keys).hasSize(2);
        boolean hasKey1 = false;
        boolean hasKey2 = false;
        boolean hasKey3 = false;
        for (int i = 0; i < keys.size(); i++) {
            String kid = keys.get(i).getAsJsonObject().get("kid").getAsString();
            if (kid.equals(key1.getKeyID())) hasKey1 = true;
            if (kid.equals(key2.getKeyID())) hasKey2 = true;
            if (kid.equals(key3.getKeyID())) hasKey3 = true;
        }
        assertThat(hasKey1).isFalse();
        assertThat(hasKey2).isTrue();
        assertThat(hasKey3).isTrue();
    }
}
