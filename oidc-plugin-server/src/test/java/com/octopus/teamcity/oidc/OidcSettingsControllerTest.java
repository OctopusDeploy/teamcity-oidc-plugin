package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.auth.Permission;
import jetbrains.buildServer.users.SUser;
import jetbrains.buildServer.web.CSRFFilter;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import jetbrains.buildServer.web.util.SessionUser;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class OidcSettingsControllerTest {

    @Mock private WebControllerManager controllerManager;
    @Mock private CSRFFilter csrfFilter;
    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;
    @Mock private HttpClient httpClient;

    @TempDir private File tempDir;

    @BeforeEach
    void setUp() {
        lenient().when(csrfFilter.validateRequest(any(), any())).thenReturn(true);
    }

    private OidcSettingsController controller(final OidcSettingsManager mgr) {
        return new OidcSettingsController(controllerManager, mgr, csrfFilter, httpClient);
    }

    private SUser adminUser() {
        final var user = mock(SUser.class);
        when(user.isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS)).thenReturn(true);
        return user;
    }

    private JSONObject parseResponse(final StringWriter writer) throws Exception {
        return (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(writer.toString());
    }

    private JSONObject postForJson(final OidcSettingsManager mgr, final String url) throws Exception {
        return postWith(mgr, java.util.Map.of("overrideIssuerUrl", url == null ? "" : url));
    }

    private JSONObject postMaxTtl(final OidcSettingsManager mgr, final String value) throws Exception {
        return postWith(mgr, java.util.Map.of("maxTokenLifetimeMinutes", value));
    }

    private JSONObject postCacheLifetime(final OidcSettingsManager mgr, final String value) throws Exception {
        return postWith(mgr, java.util.Map.of("jwksCacheLifetimeMinutes", value));
    }

    private JSONObject postWith(final OidcSettingsManager mgr, final java.util.Map<String, String> params) throws Exception {
        final var writer = new StringWriter();
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameterMap()).thenReturn(
                params.entrySet().stream().collect(java.util.stream.Collectors.toMap(
                        java.util.Map.Entry::getKey, e -> new String[]{e.getValue()})));
        params.forEach((k, v) -> lenient().when(request.getParameter(k)).thenReturn(v));
        when(response.getWriter()).thenReturn(new PrintWriter(writer));
        final var admin = adminUser();
        try (final var su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(request)).thenReturn(admin);
            controller(mgr).doHandle(request, response);
        }
        return parseResponse(writer);
    }

    @SuppressWarnings("unchecked")
    private void mockHttpStatus(final int status) throws Exception {
        final var httpResp = mock(HttpResponse.class);
        when(httpResp.statusCode()).thenReturn(status);
        when(httpClient.send(any(), any())).thenReturn(httpResp);
    }

    @Test
    void rejectsPostWithNeitherParameter() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        mgr.saveOverrideIssuerUrl("https://existing.example.com");
        // POST with no recognised parameter should not silently clear the override.
        final var writer = new StringWriter();
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameterMap()).thenReturn(java.util.Map.of());
        when(response.getWriter()).thenReturn(new PrintWriter(writer));
        final var admin = adminUser();
        try (final var su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(request)).thenReturn(admin);
            controller(mgr).doHandle(request, response);
        }
        verify(response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
        assertThat((String) parseResponse(writer).get("state")).isEqualTo("error");
        assertThat(mgr.load().findOverrideIssuerUrl()).contains("https://existing.example.com");
    }

    @Test
    void registersAtExpectedPath() {
        new OidcSettingsController(controllerManager, new OidcSettingsManager(tempDir), csrfFilter, httpClient);
        verify(controllerManager).registerController(eq(OidcSettingsController.PATH), any());
    }

    @Test
    void rejectsNonPost() throws Exception {
        when(request.getMethod()).thenReturn("GET");
        controller(new OidcSettingsManager(tempDir)).doHandle(request, response);
        verify(response).setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
    }

    @Test
    void rejectsNonHttpsUrl() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        final var json = postForJson(mgr, "http://ci.example.com");
        assertThat((String) json.get("state")).isEqualTo("error");
        assertThat((String) json.get("message")).contains("HTTPS");
        assertThat(mgr.load().findOverrideIssuerUrl()).isEmpty();
    }

    @Test
    void rejectsInvalidUrl() throws Exception {
        final var json = postForJson(new OidcSettingsManager(tempDir), "not a url");
        assertThat((String) json.get("state")).isEqualTo("error");
    }

    @Test
    void savesAndReturnsOkWhenReachableAndHttp200() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        mockHttpStatus(200);
        final var json = postForJson(mgr, "https://ci.example.com");
        assertThat((String) json.get("state")).isEqualTo("ok");
        assertThat(mgr.load().findOverrideIssuerUrl()).contains("https://ci.example.com");
    }

    @Test
    void savesWithWarningWhenUnreachable() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        when(httpClient.send(any(), any())).thenThrow(new java.net.ConnectException("refused"));
        final var json = postForJson(mgr, "https://ci.example.com");
        assertThat((String) json.get("state")).isEqualTo("warn");
        assertThat((String) json.get("message")).containsIgnoringCase("could not be verified");
        assertThat(mgr.load().findOverrideIssuerUrl()).contains("https://ci.example.com");
    }

    @Test
    void rejectsAndDoesNotSaveOnHttpError() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        mockHttpStatus(404);
        final var json = postForJson(mgr, "https://ci.example.com");
        assertThat((String) json.get("state")).isEqualTo("error");
        assertThat((String) json.get("message")).contains("404");
        assertThat(mgr.load().findOverrideIssuerUrl()).isEmpty();
    }

    @Test
    void rejectsAndDoesNotSaveOnRedirect() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        mockHttpStatus(301);
        final var json = postForJson(mgr, "https://ci.example.com");
        assertThat((String) json.get("state")).isEqualTo("error");
        assertThat((String) json.get("message")).contains("301");
        assertThat(mgr.load().findOverrideIssuerUrl()).isEmpty();
    }

    @Test
    void rejectsAndDoesNotSaveOnServerError() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        mockHttpStatus(503);
        final var json = postForJson(mgr, "https://ci.example.com");
        assertThat((String) json.get("state")).isEqualTo("error");
        assertThat((String) json.get("message")).contains("503");
        assertThat(mgr.load().findOverrideIssuerUrl()).isEmpty();
    }

    @Test
    void clearsOverrideOnBlankInput() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        mgr.saveOverrideIssuerUrl("https://ci.example.com");
        final var json = postForJson(mgr, "");
        assertThat((String) json.get("state")).isEqualTo("ok");
        assertThat(mgr.load().findOverrideIssuerUrl()).isEmpty();
    }

    @Test
    void stripsTrailingSlashBeforeSaving() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        mockHttpStatus(200);
        postForJson(mgr, "https://ci.example.com/");
        assertThat(mgr.load().findOverrideIssuerUrl()).contains("https://ci.example.com");
    }

    @Test
    void savesValidMaxTokenLifetime() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        final var json = postMaxTtl(mgr, "60");
        assertThat((String) json.get("state")).isEqualTo("ok");
        assertThat(mgr.load().maxTokenLifetimeMinutes()).isEqualTo(60);
    }

    @Test
    void rejectsNonNumericMaxTokenLifetime() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        final var json = postMaxTtl(mgr, "abc");
        assertThat((String) json.get("state")).isEqualTo("error");
        assertThat(mgr.load().maxTokenLifetimeMinutes())
                .isEqualTo(OidcSettings.DEFAULT_MAX_TOKEN_LIFETIME_MINUTES);
    }

    @Test
    void rejectsTooSmallMaxTokenLifetime() throws Exception {
        final var json = postMaxTtl(new OidcSettingsManager(tempDir), "0");
        assertThat((String) json.get("state")).isEqualTo("error");
    }

    @Test
    void rejectsTooLargeMaxTokenLifetime() throws Exception {
        final var json = postMaxTtl(new OidcSettingsManager(tempDir),
                String.valueOf(OidcSettings.ABSOLUTE_MAX_TOKEN_LIFETIME_MINUTES + 1));
        assertThat((String) json.get("state")).isEqualTo("error");
    }

    @Test
    void savingMaxTokenLifetimePreservesOverrideUrl() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        mgr.saveOverrideIssuerUrl("https://ci.example.com");
        postMaxTtl(mgr, "30");
        final var settings = mgr.load();
        assertThat(settings.findOverrideIssuerUrl()).contains("https://ci.example.com");
        assertThat(settings.maxTokenLifetimeMinutes()).isEqualTo(30);
    }

    @Test
    void savesJwksCacheLifetime() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        final var json = postCacheLifetime(mgr, "15");
        assertThat((String) json.get("state")).isEqualTo("ok");
        assertThat(mgr.load().jwksCacheLifetimeMinutes()).isEqualTo(15);
    }

    @Test
    void rejectsNonNumericJwksCacheLifetime() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        final var json = postCacheLifetime(mgr, "abc");
        assertThat((String) json.get("state")).isEqualTo("error");
        assertThat(mgr.load().jwksCacheLifetimeMinutes())
                .isEqualTo(OidcSettings.DEFAULT_JWKS_CACHE_LIFETIME_MINUTES);
    }

    @Test
    void rejectsJwksCacheLifetimeBelowMin() throws Exception {
        final var json = postCacheLifetime(new OidcSettingsManager(tempDir),
                String.valueOf(OidcSettings.MIN_JWKS_CACHE_LIFETIME_MINUTES - 1));
        assertThat((String) json.get("state")).isEqualTo("error");
    }

    @Test
    void rejectsJwksCacheLifetimeAboveMax() throws Exception {
        final var json = postCacheLifetime(new OidcSettingsManager(tempDir),
                String.valueOf(OidcSettings.MAX_JWKS_CACHE_LIFETIME_MINUTES + 1));
        assertThat((String) json.get("state")).isEqualTo("error");
    }
}
