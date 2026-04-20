package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.ServerPaths;
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
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class KeyRotationControllerTest {

    @Mock private WebControllerManager controllerManager;
    @Mock private ServerPaths serverPaths;
    @Mock private CSRFFilter csrfFilter;
    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;

    @TempDir private File tempDir;

    private JwtKeyManager keyManager;
    private RotationSettingsManager settingsManager;

    @BeforeEach
    void setUp() {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        keyManager = TestJwtKeyManagerFactory.create(serverPaths);
        settingsManager = new RotationSettingsManager(new File(tempDir, "JwtBuildFeature"));
        // Default: CSRF check passes. lenient() because some tests never reach doHandle.
        lenient().when(csrfFilter.validateRequest(any(), any())).thenReturn(true);
    }

    private KeyRotationController controller() {
        return new KeyRotationController(controllerManager, keyManager, settingsManager, csrfFilter);
    }

    @Test
    public void registersAtAdminPath() {
        new KeyRotationController(controllerManager, keyManager, settingsManager, csrfFilter);
        verify(controllerManager).registerController(eq(KeyRotationController.PATH), any(KeyRotationController.class));
    }

    @Test
    public void postRequestRotatesKeyAndReturnsJson() throws Exception {
        final var originalRsaKid = keyManager.getRsaKey().getKeyID();
        final var originalEcKid = keyManager.getEcKey().getKeyID();
        final var writer = new StringWriter();
        when(request.getMethod()).thenReturn("POST");
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        final var adminUser = mock(SUser.class);
        when(adminUser.isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS)).thenReturn(true);

        try (final var sessionUser = mockStatic(SessionUser.class)) {
            sessionUser.when(() -> SessionUser.getUser(request)).thenReturn(adminUser);
            controller().doHandle(request, response);
        }

        assertThat(keyManager.getRsaKey().getKeyID()).isNotEqualTo(originalRsaKid);
        assertThat(keyManager.getEcKey().getKeyID()).isNotEqualTo(originalEcKid);
        assertThat(writer.toString()).contains("rotated");
    }

    @Test
    public void postRequestPersistsLastRotatedAt() throws Exception {
        final var writer = new StringWriter();
        when(request.getMethod()).thenReturn("POST");
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        final var adminUser = mock(SUser.class);
        when(adminUser.isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS)).thenReturn(true);

        final var before = java.time.Instant.now();
        try (final var sessionUser = mockStatic(SessionUser.class)) {
            sessionUser.when(() -> SessionUser.getUser(request)).thenReturn(adminUser);
            controller().doHandle(request, response);
        }
        final var after = java.time.Instant.now();

        final var recorded = settingsManager.load().lastRotatedAt();
        assertThat(recorded).isNotNull();
        assertThat(recorded).isAfterOrEqualTo(before).isBeforeOrEqualTo(after);
    }

    @Test
    public void warningIncludedWhenRotatingWithinMinGap() throws Exception {
        // Simulate a very recent previous rotation (1 second ago)
        settingsManager.updateLastRotatedAt(java.time.Instant.now().minusSeconds(1));

        final var writer = new StringWriter();
        when(request.getMethod()).thenReturn("POST");
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        final var adminUser = mock(SUser.class);
        when(adminUser.isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS)).thenReturn(true);

        try (final var sessionUser = mockStatic(SessionUser.class)) {
            sessionUser.when(() -> SessionUser.getUser(request)).thenReturn(adminUser);
            controller().doHandle(request, response);
        }

        assertThat(writer.toString()).contains("rotated");
        assertThat(writer.toString()).contains("warning");
    }

    @Test
    public void noWarningWhenRotatingAfterMinGap() throws Exception {
        // Simulate a previous rotation well outside the minimum gap
        settingsManager.updateLastRotatedAt(
                java.time.Instant.now().minusSeconds(KeyRotationController.MIN_ROTATION_GAP_SECONDS + 60));

        final var writer = new StringWriter();
        when(request.getMethod()).thenReturn("POST");
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        final var adminUser = mock(SUser.class);
        when(adminUser.isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS)).thenReturn(true);

        try (final var sessionUser = mockStatic(SessionUser.class)) {
            sessionUser.when(() -> SessionUser.getUser(request)).thenReturn(adminUser);
            controller().doHandle(request, response);
        }

        assertThat(writer.toString()).contains("rotated");
        assertThat(writer.toString()).doesNotContain("warning");
    }

    @Test
    public void getRequestReturns405MethodNotAllowed() throws Exception {
        when(request.getMethod()).thenReturn("GET");

        controller().doHandle(request, response);

        verify(response).setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
    }

    @Test
    public void getRequestDoesNotCheckCsrf() throws Exception {
        when(request.getMethod()).thenReturn("GET");

        controller().doHandle(request, response);

        verify(csrfFilter, never()).validateRequest(any(), any());
    }

    @Test
    public void postWithFailedCsrfCheckReturnsWithoutProcessing() throws Exception {
        final var originalRsaKid = keyManager.getRsaKey().getKeyID();
        when(request.getMethod()).thenReturn("POST");
        when(csrfFilter.validateRequest(request, response)).thenReturn(false);

        controller().doHandle(request, response);

        assertThat(keyManager.getRsaKey().getKeyID()).isEqualTo(originalRsaKid);
        verify(response, never()).setStatus(anyInt());
        verify(response, never()).setContentType(anyString());
    }

    @Test
    public void postWithNoSessionUserReturns401() throws Exception {
        when(request.getMethod()).thenReturn("POST");

        try (final var sessionUser = mockStatic(SessionUser.class)) {
            sessionUser.when(() -> SessionUser.getUser(request)).thenReturn(null);
            controller().doHandle(request, response);
        }

        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @Test
    public void postWithNonAdminUserReturns403() throws Exception {
        when(request.getMethod()).thenReturn("POST");

        final var nonAdminUser = mock(SUser.class);
        when(nonAdminUser.isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS)).thenReturn(false);

        try (final var sessionUser = mockStatic(SessionUser.class)) {
            sessionUser.when(() -> SessionUser.getUser(request)).thenReturn(nonAdminUser);
            controller().doHandle(request, response);
        }

        verify(response).setStatus(HttpServletResponse.SC_FORBIDDEN);
    }
}
