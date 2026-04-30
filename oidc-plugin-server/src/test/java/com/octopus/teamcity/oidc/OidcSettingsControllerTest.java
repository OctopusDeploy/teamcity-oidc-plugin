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
        final var writer = new StringWriter();
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("overrideIssuerUrl")).thenReturn("http://ci.example.com");
        when(response.getWriter()).thenReturn(new PrintWriter(writer));
        final var admin = adminUser();
        try (final var su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(request)).thenReturn(admin);
            controller(new OidcSettingsManager(tempDir)).doHandle(request, response);
        }
        final var json = parseResponse(writer);
        assertThat((Boolean) json.get("ok")).isFalse();
        assertThat((String) json.get("message")).contains("HTTPS");
        assertThat(new OidcSettingsManager(tempDir).load()).isEmpty();
    }

    @Test
    void rejectsInvalidUrl() throws Exception {
        final var writer = new StringWriter();
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("overrideIssuerUrl")).thenReturn("not a url");
        when(response.getWriter()).thenReturn(new PrintWriter(writer));
        final var admin = adminUser();
        try (final var su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(request)).thenReturn(admin);
            controller(new OidcSettingsManager(tempDir)).doHandle(request, response);
        }
        final var json = parseResponse(writer);
        assertThat((Boolean) json.get("ok")).isFalse();
    }

    @SuppressWarnings("unchecked")
    @Test
    void savesAndReturnsOkWhenReachableAndHttp200() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        final var writer = new StringWriter();
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("overrideIssuerUrl")).thenReturn("https://ci.example.com");
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        final var httpResp = mock(HttpResponse.class);
        when(httpResp.statusCode()).thenReturn(200);
        when(httpClient.send(any(), any())).thenReturn(httpResp);

        final var admin = adminUser();
        try (final var su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(request)).thenReturn(admin);
            controller(mgr).doHandle(request, response);
        }
        final var json = parseResponse(writer);
        assertThat((Boolean) json.get("ok")).isTrue();
        assertThat(mgr.load()).contains("https://ci.example.com");
    }

    @SuppressWarnings("unchecked")
    @Test
    void savesWithWarningWhenUnreachable() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        final var writer = new StringWriter();
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("overrideIssuerUrl")).thenReturn("https://ci.example.com");
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        when(httpClient.send(any(), any())).thenThrow(new java.net.ConnectException("refused"));

        final var admin = adminUser();
        try (final var su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(request)).thenReturn(admin);
            controller(mgr).doHandle(request, response);
        }
        final var json = parseResponse(writer);
        assertThat((Boolean) json.get("ok")).isTrue();
        assertThat((String) json.get("message")).containsIgnoringCase("could not be verified");
        assertThat(mgr.load()).contains("https://ci.example.com");
    }

    @SuppressWarnings("unchecked")
    @Test
    void rejectsAndDoesNotSaveOnHttpError() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        final var writer = new StringWriter();
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("overrideIssuerUrl")).thenReturn("https://ci.example.com");
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        final var httpResp = mock(HttpResponse.class);
        when(httpResp.statusCode()).thenReturn(404);
        when(httpClient.send(any(), any())).thenReturn(httpResp);

        final var admin = adminUser();
        try (final var su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(request)).thenReturn(admin);
            controller(mgr).doHandle(request, response);
        }
        final var json = parseResponse(writer);
        assertThat((Boolean) json.get("ok")).isFalse();
        assertThat((String) json.get("message")).contains("404");
        assertThat(mgr.load()).isEmpty();
    }

    @SuppressWarnings("unchecked")
    @Test
    void rejectsAndDoesNotSaveOnRedirect() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        final var writer = new StringWriter();
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("overrideIssuerUrl")).thenReturn("https://ci.example.com");
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        final var httpResp = mock(HttpResponse.class);
        when(httpResp.statusCode()).thenReturn(301);
        when(httpClient.send(any(), any())).thenReturn(httpResp);

        final var admin = adminUser();
        try (final var su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(request)).thenReturn(admin);
            controller(mgr).doHandle(request, response);
        }
        final var json = parseResponse(writer);
        assertThat((Boolean) json.get("ok")).isFalse();
        assertThat((String) json.get("message")).contains("301");
        assertThat(mgr.load()).isEmpty();
    }

    @SuppressWarnings("unchecked")
    @Test
    void rejectsAndDoesNotSaveOnServerError() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        final var writer = new StringWriter();
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("overrideIssuerUrl")).thenReturn("https://ci.example.com");
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        final var httpResp = mock(HttpResponse.class);
        when(httpResp.statusCode()).thenReturn(503);
        when(httpClient.send(any(), any())).thenReturn(httpResp);

        final var admin = adminUser();
        try (final var su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(request)).thenReturn(admin);
            controller(mgr).doHandle(request, response);
        }
        final var json = parseResponse(writer);
        assertThat((Boolean) json.get("ok")).isFalse();
        assertThat((String) json.get("message")).contains("503");
        assertThat(mgr.load()).isEmpty();
    }

    @Test
    void clearsOverrideOnBlankInput() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        mgr.save("https://ci.example.com");
        final var writer = new StringWriter();
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("overrideIssuerUrl")).thenReturn("");
        when(response.getWriter()).thenReturn(new PrintWriter(writer));
        final var admin = adminUser();
        try (final var su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(request)).thenReturn(admin);
            controller(mgr).doHandle(request, response);
        }
        final var json = parseResponse(writer);
        assertThat((Boolean) json.get("ok")).isTrue();
        assertThat(mgr.load()).isEmpty();
    }

    @SuppressWarnings("unchecked")
    @Test
    void stripsTrailingSlashBeforeSaving() throws Exception {
        final var mgr = new OidcSettingsManager(tempDir);
        final var writer = new StringWriter();
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("overrideIssuerUrl")).thenReturn("https://ci.example.com/");
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        final var httpResp = mock(HttpResponse.class);
        when(httpResp.statusCode()).thenReturn(200);
        when(httpClient.send(any(), any())).thenReturn(httpResp);

        final var admin = adminUser();
        try (final var su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(request)).thenReturn(admin);
            controller(mgr).doHandle(request, response);
        }
        assertThat(mgr.load()).contains("https://ci.example.com");
    }
}
