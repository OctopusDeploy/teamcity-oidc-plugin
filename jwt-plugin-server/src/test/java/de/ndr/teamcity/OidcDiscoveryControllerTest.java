package de.ndr.teamcity;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;
import jetbrains.buildServer.controllers.AuthorizationInterceptor;
import jetbrains.buildServer.serverSide.ServerPaths;
import jetbrains.buildServer.serverSide.SBuildServer;
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
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class OidcDiscoveryControllerTest {

    @Mock
    private WebControllerManager controllerManager;

    @Mock
    private AuthorizationInterceptor authorizationInterceptor;

    @Mock
    private SBuildServer buildServer;

    @Mock
    private ServerPaths serverPaths;

    @Mock
    private PluginDescriptor pluginDescriptor;

    @TempDir
    private File tempDir;

    @Test
    public void registersAtWellKnownPath() throws NoSuchAlgorithmException, IOException, ParseException, JOSEException {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        new OidcDiscoveryController(controllerManager, authorizationInterceptor, buildServer, jwtBuildFeature);

        verify(controllerManager).registerController(eq("/.well-known/openid-configuration"), any(OidcDiscoveryController.class));
    }

    @Test
    public void registersPathAsPubliclyAccessible() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        new OidcDiscoveryController(controllerManager, authorizationInterceptor, buildServer, jwtBuildFeature);

        verify(authorizationInterceptor).addPathNotRequiringAuth(OidcDiscoveryController.class, "/.well-known/openid-configuration");
    }

    @Test
    public void returnsDiscoveryDocument() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);
        OidcDiscoveryController controller = new OidcDiscoveryController(controllerManager, authorizationInterceptor, buildServer, jwtBuildFeature);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        ModelAndView result = controller.doHandle(request, response);

        assertThat(result).isNull();
        verify(response).setContentType("application/json;charset=UTF-8");

        String body = writer.toString();
        JsonObject json = JsonParser.parseString(body).getAsJsonObject();

        assertThat(json.get("issuer").getAsString()).isEqualTo("https://teamcity.example.com");
        assertThat(json.get("jwks_uri").getAsString()).isEqualTo("https://teamcity.example.com/.well-known/jwks.json");
        assertThat(json.get("id_token_signing_alg_values_supported").getAsJsonArray().get(0).getAsString()).isEqualTo("RS256");
        assertThat(json.get("response_types_supported").getAsJsonArray().get(0).getAsString()).isEqualTo("id_token");
        assertThat(json.get("subject_types_supported").getAsJsonArray().get(0).getAsString()).isEqualTo("public");
    }

    @Test
    public void advertisesES256AlgorithmInDiscoveryDocument() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);
        OidcDiscoveryController controller = new OidcDiscoveryController(controllerManager, authorizationInterceptor, buildServer, jwtBuildFeature);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        controller.doHandle(request, response);

        JsonObject json = JsonParser.parseString(writer.toString()).getAsJsonObject();
        var algs = json.get("id_token_signing_alg_values_supported").getAsJsonArray();
        var algNames = new java.util.ArrayList<String>();
        algs.forEach(e -> algNames.add(e.getAsString()));
        assertThat(algNames).contains("RS256", "ES256");
    }

    @Test
    public void includesClaimsSupportedInDiscoveryDocument() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);
        OidcDiscoveryController controller = new OidcDiscoveryController(controllerManager, authorizationInterceptor, buildServer, jwtBuildFeature);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        controller.doHandle(request, response);

        JsonObject json = JsonParser.parseString(writer.toString()).getAsJsonObject();
        assertThat(json.has("claims_supported")).isTrue();
        var claims = new java.util.ArrayList<String>();
        json.get("claims_supported").getAsJsonArray().forEach(e -> claims.add(e.getAsString()));
        assertThat(claims).contains("sub", "iss", "aud", "iat", "exp", "branch");
    }

    @Test
    public void setsCacheControlHeader() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);
        OidcDiscoveryController controller = new OidcDiscoveryController(controllerManager, authorizationInterceptor, buildServer, jwtBuildFeature);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(response.getWriter()).thenReturn(new PrintWriter(new StringWriter()));

        controller.doHandle(request, response);

        verify(response).setHeader("Cache-Control", "max-age=300");
    }
}
