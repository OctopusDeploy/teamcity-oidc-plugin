package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.auth.Permission;
import jetbrains.buildServer.users.SUser;
import jetbrains.buildServer.web.CSRFFilter;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import jetbrains.buildServer.web.util.SessionUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class RotationSettingsControllerTest {

    @Mock private WebControllerManager controllerManager;
    @Mock private CSRFFilter csrfFilter;
    @TempDir private File tempDir;

    @BeforeEach
    void setUp() {
        lenient().when(csrfFilter.validateRequest(any(), any())).thenReturn(true);
    }

    private RotationSettingsController controller(RotationSettingsManager mgr) {
        return new RotationSettingsController(controllerManager, mgr, csrfFilter);
    }

    private SUser adminUser() {
        SUser user = mock(SUser.class);
        when(user.isPermissionGrantedGlobally(Permission.MANAGE_SERVER_INSTALLATION)).thenReturn(true);
        return user;
    }

    @Test
    void registersAtExpectedPath() {
        new RotationSettingsController(controllerManager, new RotationSettingsManager(tempDir), csrfFilter);
        verify(controllerManager).registerController(eq(RotationSettingsController.PATH), any());
    }

    @Test
    void savesValidSettings() throws Exception {
        RotationSettingsManager mgr = new RotationSettingsManager(tempDir);
        RotationSettingsController controller = controller(mgr);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("enabled")).thenReturn("true");
        when(request.getParameter("cronSchedule")).thenReturn("0 0 2 * * *");
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        SUser admin = adminUser();
        try (MockedStatic<SessionUser> su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(request)).thenReturn(admin);
            controller.doHandle(request, response);
        }

        RotationSettings saved = mgr.load();
        assertThat(saved.enabled()).isTrue();
        assertThat(saved.cronSchedule()).isEqualTo("0 0 2 * * *");
        assertThat(writer.toString()).contains("\"ok\":true");
    }

    @Test
    void preservesLastRotatedAtWhenSaving() throws Exception {
        RotationSettingsManager mgr = new RotationSettingsManager(tempDir);
        Instant original = Instant.parse("2026-01-01T03:00:00Z");
        mgr.save(new RotationSettings(true, RotationSettings.DEFAULT_SCHEDULE, original));
        RotationSettingsController controller = controller(mgr);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("enabled")).thenReturn("false");
        when(request.getParameter("cronSchedule")).thenReturn("0 0 4 * * *");
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(response.getWriter()).thenReturn(new PrintWriter(new StringWriter()));

        SUser admin = adminUser();
        try (MockedStatic<SessionUser> su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(request)).thenReturn(admin);
            controller.doHandle(request, response);
        }

        assertThat(mgr.load().lastRotatedAt()).isEqualTo(original);
    }

    @Test
    void rejectsInvalidCronSchedule() throws Exception {
        RotationSettingsManager mgr = new RotationSettingsManager(tempDir);
        RotationSettingsController controller = controller(mgr);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("cronSchedule")).thenReturn("not a cron");
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        SUser admin = adminUser();
        try (MockedStatic<SessionUser> su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(request)).thenReturn(admin);
            controller.doHandle(request, response);
        }

        assertThat(writer.toString()).contains("\"ok\":false");
        assertThat(mgr.load().cronSchedule()).isEqualTo(RotationSettings.DEFAULT_SCHEDULE);
    }

    @Test
    void getRequestReturns405() throws Exception {
        RotationSettingsController controller = controller(new RotationSettingsManager(tempDir));
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("GET");
        HttpServletResponse response = mock(HttpServletResponse.class);
        controller.doHandle(request, response);
        verify(response).setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        verify(csrfFilter, never()).validateRequest(any(), any());
    }

    @Test
    void csrfFailureReturnsEarlyWithoutSaving() throws Exception {
        RotationSettingsManager mgr = new RotationSettingsManager(tempDir);
        when(csrfFilter.validateRequest(any(), any())).thenReturn(false);
        RotationSettingsController controller = controller(mgr);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("POST");
        HttpServletResponse response = mock(HttpServletResponse.class);
        controller.doHandle(request, response);

        verify(response, never()).setContentType(anyString());
        assertThat(mgr.load().cronSchedule()).isEqualTo(RotationSettings.DEFAULT_SCHEDULE);
    }

    @Test
    void nonAdminReturns403() throws Exception {
        RotationSettingsController controller = controller(new RotationSettingsManager(tempDir));

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("POST");
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        SUser nonAdmin = mock(SUser.class);
        when(nonAdmin.isPermissionGrantedGlobally(Permission.MANAGE_SERVER_INSTALLATION)).thenReturn(false);

        try (MockedStatic<SessionUser> su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(request)).thenReturn(nonAdmin);
            controller.doHandle(request, response);
        }

        verify(response).setStatus(HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    void nullSessionUserReturns403() throws Exception {
        RotationSettingsController controller = controller(new RotationSettingsManager(tempDir));

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("POST");
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(response.getWriter()).thenReturn(new PrintWriter(new StringWriter()));

        try (MockedStatic<SessionUser> su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(request)).thenReturn(null);
            controller.doHandle(request, response);
        }

        verify(response).setStatus(HttpServletResponse.SC_FORBIDDEN);
    }
}
