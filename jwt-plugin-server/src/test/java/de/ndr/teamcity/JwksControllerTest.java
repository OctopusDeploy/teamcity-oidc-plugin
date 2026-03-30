package de.ndr.teamcity;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;
import jetbrains.buildServer.serverSide.ServerPaths;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
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
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class JwksControllerTest {

    @Mock
    private WebControllerManager controllerManager;

    @Mock
    private ServerPaths serverPaths;

    @Mock
    private PluginDescriptor pluginDescriptor;

    @TempDir
    private File tempDir;

    @Test
    public void registersAtWellKnownPath() throws NoSuchAlgorithmException, IOException, ParseException, JOSEException {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor);

        new JwksController(controllerManager, jwtBuildFeature);

        verify(controllerManager).registerController(eq("/.well-known/jwks.json"), any(JwksController.class));
    }

    @Test
    public void returnsPublicKeyAsJwks() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor);
        JwksController controller = new JwksController(controllerManager, jwtBuildFeature);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        ModelAndView result = controller.doHandle(request, response);

        assertThat(result).isNull();
        verify(response).setContentType("application/json;charset=UTF-8");

        String body = writer.toString();
        JsonObject json = JsonParser.parseString(body).getAsJsonObject();
        assertThat(json.has("keys")).isTrue();
        assertThat(json.get("keys").getAsJsonArray()).hasSize(1);

        JsonObject key = json.get("keys").getAsJsonArray().get(0).getAsJsonObject();
        assertThat(key.get("kty").getAsString()).isEqualTo("RSA");
        assertThat(key.get("use").getAsString()).isEqualTo("sig");
        assertThat(key.has("d")).isFalse();
        assertThat(key.get("kid").getAsString()).isEqualTo(jwtBuildFeature.getRsaKey().computeThumbprint().toString());
    }
}
