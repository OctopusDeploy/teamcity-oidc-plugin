package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.ServerPaths;
import jetbrains.buildServer.serverSide.SBuildServer;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class WellKnownPublicFilterTest {

    @Mock private ServerPaths serverPaths;
    @Mock private SBuildServer buildServer;
    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;
    @Mock private FilterChain chain;

    @TempDir private File tempDir;

    private WellKnownPublicFilter filter;

    @BeforeEach
    void setUp() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        filter = new WellKnownPublicFilter(TestJwtKeyManagerFactory.create(serverPaths), buildServer);
    }

    private StringWriter stubResponseWriter() throws Exception {
        final var writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));
        return writer;
    }

    private static JSONObject parseJson(final String body) throws Exception {
        return (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(body);
    }

    @Test
    public void servesJwksWithoutCallingChain() throws Exception {
        stubResponseWriter();
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.JWKS_PATH);
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, chain);

        verifyNoInteractions(chain);
    }

    @Test
    public void servesOidcDiscoveryWithoutCallingChain() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");
        stubResponseWriter();
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.OIDC_DISCOVERY_PATH);
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, chain);

        verifyNoInteractions(chain);
    }

    @Test
    public void delegatesToChainForOtherPaths() throws Exception {
        when(request.getRequestURI()).thenReturn("/admin/jwtKeyRotate.html");
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        verifyNoInteractions(response);
    }

    @Test
    public void jwksContainsBothRsaAndEcPublicKeys() throws Exception {
        final var writer = stubResponseWriter();
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.JWKS_PATH);
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, chain);

        final var keys = (JSONArray) parseJson(writer.toString()).get("keys");
        assertThat(keys).hasSize(2);
        boolean hasRsa = false, hasEc = false;
        for (var i = 0; i < keys.size(); i++) {
            final var kty = ((JSONObject) keys.get(i)).getAsString("kty");
            if ("RSA".equals(kty)) hasRsa = true;
            if ("EC".equals(kty)) hasEc = true;
        }
        assertThat(hasRsa).isTrue();
        assertThat(hasEc).isTrue();
    }

    @Test
    public void jwksExposesNoPrivateKeyMaterial() throws Exception {
        final var writer = stubResponseWriter();
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.JWKS_PATH);
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, chain);

        final var keys = (JSONArray) parseJson(writer.toString()).get("keys");
        for (var i = 0; i < keys.size(); i++) {
            assertThat(((JSONObject) keys.get(i)).containsKey("d")).isFalse();
        }
    }

    @Test
    public void trailingSlashesStrippedFromDiscoveryDocUrls() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com/");
        final var writer = stubResponseWriter();
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.OIDC_DISCOVERY_PATH);
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, chain);

        final var json = parseJson(writer.toString());
        assertThat(json.getAsString("issuer")).isEqualTo("https://teamcity.example.com");
        assertThat(json.getAsString("jwks_uri")).isEqualTo("https://teamcity.example.com/.well-known/jwks.json");
    }

    @Test
    public void discoveryDocIncludesAuthorizationEndpoint() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");
        final var writer = stubResponseWriter();
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.OIDC_DISCOVERY_PATH);
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, chain);

        final var json = parseJson(writer.toString());
        assertThat(json.containsKey("authorization_endpoint")).isTrue();
        assertThat(json.getAsString("authorization_endpoint"))
                .startsWith("https://teamcity.example.com");
    }

    @Test
    public void authorizeEndpointReturnsUnsupportedResponseType() throws Exception {
        final var writer = stubResponseWriter();
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.AUTHORIZE_PATH);
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, chain);

        verify(response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
        assertThat(writer.toString()).contains("unsupported_response_type");
    }

    @Test
    public void jwksResponseIncludesCorsWildcardHeader() throws Exception {
        stubResponseWriter();
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.JWKS_PATH);
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, chain);

        verify(response).setHeader("Access-Control-Allow-Origin", "*");
    }

    @Test
    public void discoveryResponseIncludesCorsWildcardHeader() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");
        stubResponseWriter();
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.OIDC_DISCOVERY_PATH);
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, chain);

        verify(response).setHeader("Access-Control-Allow-Origin", "*");
    }

    @Test
    public void stripsContextPathBeforeMatching() throws Exception {
        final var writer = stubResponseWriter();
        when(request.getRequestURI()).thenReturn("/tc/.well-known/jwks.json");
        when(request.getContextPath()).thenReturn("/tc");

        filter.doFilter(request, response, chain);

        assertThat(writer.toString()).contains("\"keys\"");
        verifyNoInteractions(chain);
    }
}
