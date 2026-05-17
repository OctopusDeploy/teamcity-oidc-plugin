package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.ServerPaths;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.web.DelegatingFilter;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;

import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class WellKnownPublicFilterTest {

    @Mock private ServerPaths serverPaths;
    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;
    @Mock private FilterChain chain;
    @Mock private OidcSettingsManager oidcSettingsManager;

    @TempDir private File tempDir;

    private WellKnownPublicFilter filter;

    @BeforeEach
    void setUp() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        lenient().when(oidcSettingsManager.load()).thenReturn(OidcSettings.defaults());
        filter = new WellKnownPublicFilter(TestJwtKeyManagerFactory.create(serverPaths), providerFor("https://tc.example.com"), oidcSettingsManager);
    }

    private SBuildServer buildServerWithRootUrl(final String url) {
        final var server = mock(SBuildServer.class);
        lenient().when(server.getRootUrl()).thenReturn(url);
        return server;
    }

    private OidcIssuerUrlProvider providerFor(final String issuerUrl) {
        return new OidcIssuerUrlProvider(buildServerWithRootUrl(issuerUrl), new OidcSettingsManager(tempDir));
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
    public void jwksContainsRsa2048Rsa3072AndEcPublicKeys() throws Exception {
        final var writer = stubResponseWriter();
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.JWKS_PATH);
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, chain);

        final var keys = (JSONArray) parseJson(writer.toString()).get("keys");
        final var algs = keys.stream()
                .map(k -> ((JSONObject) k).getAsString("alg"))
                .toList();
        assertThat(algs).containsExactlyInAnyOrder("RS256", "RS384", "ES256");
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
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        filter = new WellKnownPublicFilter(TestJwtKeyManagerFactory.create(serverPaths), providerFor("https://teamcity.example.com/"), oidcSettingsManager);
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
        final var writer = stubResponseWriter();
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.OIDC_DISCOVERY_PATH);
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, chain);

        final var json = parseJson(writer.toString());
        assertThat(json.containsKey("authorization_endpoint")).isTrue();
        assertThat(json.getAsString("authorization_endpoint"))
                .startsWith("https://tc.example.com");
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
        stubResponseWriter();
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.OIDC_DISCOVERY_PATH);
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, chain);

        verify(response).setHeader("Access-Control-Allow-Origin", "*");
    }

    @Test
    public void discoveryDocDoesNotEscapeForwardSlashesInUrls() throws Exception {
        final var writer = stubResponseWriter();
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.OIDC_DISCOVERY_PATH);
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, chain);

        assertThat(writer.toString()).doesNotContain("\\/");
        assertThat(writer.toString()).contains("\"https://tc.example.com\"");
    }

    @Test
    public void registersWithNamedDelegateAndUnregistersOnDestroy() throws Exception {
        try (final MockedStatic<DelegatingFilter> mocked = mockStatic(DelegatingFilter.class)) {
            final var keyManager = TestJwtKeyManagerFactory.create(serverPaths);
            final var f = new WellKnownPublicFilter(keyManager, providerFor("https://tc.example.com"), oidcSettingsManager);

            // Must use the named overload — the unnamed overload registers into a list with no
            // unregister API, leaving a ghost filter behind on plugin reload.
            mocked.verify(() -> DelegatingFilter.registerDelegate(WellKnownPublicFilter.DELEGATE_NAME, f));
            mocked.verify(() -> DelegatingFilter.registerDelegate(any(javax.servlet.Filter.class)), never());

            f.destroy();
            mocked.verify(() -> DelegatingFilter.unregisterDelegate(WellKnownPublicFilter.DELEGATE_NAME));
        }
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

    @Test
    void jwksCacheControlHeaderUsesConfiguredLifetime() throws Exception {
        when(oidcSettingsManager.load()).thenReturn(new OidcSettings(null,
                OidcSettings.DEFAULT_MAX_TOKEN_LIFETIME_MINUTES, 5));
        stubResponseWriter();
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.JWKS_PATH);
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, chain);

        verify(response).setHeader("Cache-Control", "max-age=300, stale-while-revalidate=300");
    }

    @Test
    void discoveryCacheControlHeaderUsesConfiguredLifetime() throws Exception {
        when(oidcSettingsManager.load()).thenReturn(new OidcSettings(null,
                OidcSettings.DEFAULT_MAX_TOKEN_LIFETIME_MINUTES, 5));
        stubResponseWriter();
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.OIDC_DISCOVERY_PATH);
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, chain);

        verify(response).setHeader("Cache-Control", "max-age=300, stale-while-revalidate=300");
    }

    @Test
    void cacheControlReflectsCurrentSettingOnEachRequest() throws Exception {
        when(oidcSettingsManager.load())
                .thenReturn(new OidcSettings(null, OidcSettings.DEFAULT_MAX_TOKEN_LIFETIME_MINUTES, 1))
                .thenReturn(new OidcSettings(null, OidcSettings.DEFAULT_MAX_TOKEN_LIFETIME_MINUTES, 7));
        stubResponseWriter();
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.JWKS_PATH);
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, chain);
        filter.doFilter(request, response, chain);

        final var captor = ArgumentCaptor.forClass(String.class);
        verify(response, times(2)).setHeader(eq("Cache-Control"), captor.capture());
        assertThat(captor.getAllValues()).containsExactly(
                "max-age=60, stale-while-revalidate=60",
                "max-age=420, stale-while-revalidate=420");
    }
}
