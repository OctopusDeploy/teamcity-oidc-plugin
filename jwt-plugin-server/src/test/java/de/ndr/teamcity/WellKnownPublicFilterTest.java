package de.ndr.teamcity;

import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;
import jetbrains.buildServer.serverSide.ServerPaths;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
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
public class WellKnownPublicFilterTest {

    @Mock private ServerPaths serverPaths;
    @Mock private SBuildServer buildServer;
    @Mock private PluginDescriptor pluginDescriptor;

    @TempDir
    private File tempDir;

    @Test
    public void servesJwksWithoutCallingChain() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature feature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);
        WellKnownPublicFilter filter = new WellKnownPublicFilter(feature, buildServer);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));
        when(request.getRequestURI()).thenReturn("/.well-known/jwks.json");
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, chain);

        verify(response).setContentType("application/json;charset=UTF-8");
        verify(response).setHeader("Cache-Control", "max-age=300");
        assertThat(writer.toString()).contains("\"keys\"");
        verifyNoInteractions(chain);
    }

    @Test
    public void servesOidcDiscoveryWithoutCallingChain() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");
        JwtBuildFeature feature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);
        WellKnownPublicFilter filter = new WellKnownPublicFilter(feature, buildServer);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));
        when(request.getRequestURI()).thenReturn("/.well-known/openid-configuration");
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, chain);

        verify(response).setContentType("application/json;charset=UTF-8");
        JsonObject json = JsonParser.parseString(writer.toString()).getAsJsonObject();
        assertThat(json.get("issuer").getAsString()).isEqualTo("https://teamcity.example.com");
        verifyNoInteractions(chain);
    }

    @Test
    public void delegatesToChainForOtherPaths() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature feature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);
        WellKnownPublicFilter filter = new WellKnownPublicFilter(feature, buildServer);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        when(request.getRequestURI()).thenReturn("/admin/jwtKeyRotate.html");
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        verifyNoInteractions(response);
    }

    @Test
    public void jwksContainsBothRsaAndEcPublicKeys() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature feature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);
        WellKnownPublicFilter filter = new WellKnownPublicFilter(feature, buildServer);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.JWKS_PATH);
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, chain);

        com.nimbusds.jose.shaded.gson.JsonObject json =
                com.nimbusds.jose.shaded.gson.JsonParser.parseString(writer.toString()).getAsJsonObject();
        var keys = json.get("keys").getAsJsonArray();
        assertThat(keys).hasSize(2);
        boolean hasRsa = false, hasEc = false;
        for (int i = 0; i < keys.size(); i++) {
            var key = keys.get(i).getAsJsonObject();
            assertThat(key.has("d")).isFalse(); // no private key material
            if ("RSA".equals(key.get("kty").getAsString())) hasRsa = true;
            if ("EC".equals(key.get("kty").getAsString())) hasEc = true;
        }
        assertThat(hasRsa).isTrue();
        assertThat(hasEc).isTrue();
    }

    @Test
    public void stripsContextPathBeforeMatching() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature feature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);
        WellKnownPublicFilter filter = new WellKnownPublicFilter(feature, buildServer);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));
        when(request.getRequestURI()).thenReturn("/tc/.well-known/jwks.json");
        when(request.getContextPath()).thenReturn("/tc");

        filter.doFilter(request, response, chain);

        assertThat(writer.toString()).contains("\"keys\"");
        verifyNoInteractions(chain);
    }
}
