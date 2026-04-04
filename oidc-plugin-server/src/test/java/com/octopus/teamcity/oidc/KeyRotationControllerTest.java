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
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.servlet.ModelAndView;

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

    @TempDir private File tempDir;

    @BeforeEach
    void setUp() {
        // Default: CSRF check passes. lenient() because some tests never reach doHandle.
        lenient().when(csrfFilter.validateRequest(any(), any())).thenReturn(true);
    }

    private KeyRotationController controller(JwtKeyManager keyManager) {
        return new KeyRotationController(controllerManager, keyManager, csrfFilter);
    }

    @Test
    public void registersAtAdminPath() {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtKeyManager keyManager = new JwtKeyManager(serverPaths);

        new KeyRotationController(controllerManager, keyManager, csrfFilter);

        verify(controllerManager).registerController(eq(KeyRotationController.PATH), any(KeyRotationController.class));
    }

    @Test
    public void postRequestRotatesKeyAndReturnsJson() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtKeyManager keyManager = new JwtKeyManager(serverPaths);
        String originalRsaKid = keyManager.getRsaKey().getKeyID();
        String originalEcKid = keyManager.getEcKey().getKeyID();

        KeyRotationController controller = controller(keyManager);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("POST");
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        SUser adminUser = mock(SUser.class);
        when(adminUser.isPermissionGrantedGlobally(Permission.MANAGE_SERVER_INSTALLATION)).thenReturn(true);

        try (MockedStatic<SessionUser> sessionUser = mockStatic(SessionUser.class)) {
            sessionUser.when(() -> SessionUser.getUser(request)).thenReturn(adminUser);

            ModelAndView result = controller.doHandle(request, response);

            assertThat(result).isNull();
            assertThat(keyManager.getRsaKey().getKeyID()).isNotEqualTo(originalRsaKid);
            assertThat(keyManager.getEcKey().getKeyID()).isNotEqualTo(originalEcKid);
            verify(response).setContentType("application/json;charset=UTF-8");
            assertThat(writer.toString()).contains("rotated");
        }
    }

    @Test
    public void getRequestReturns405MethodNotAllowed() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        KeyRotationController controller = controller(new JwtKeyManager(serverPaths));

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("GET");
        HttpServletResponse response = mock(HttpServletResponse.class);

        controller.doHandle(request, response);

        verify(response).setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        verify(csrfFilter, never()).validateRequest(any(), any());
    }

    @Test
    public void postWithFailedCsrfCheckReturnsWithoutProcessing() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtKeyManager keyManager = new JwtKeyManager(serverPaths);
        String originalRsaKid = keyManager.getRsaKey().getKeyID();
        KeyRotationController controller = controller(keyManager);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("POST");
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(csrfFilter.validateRequest(request, response)).thenReturn(false);

        controller.doHandle(request, response);

        // Key must not have rotated
        assertThat(keyManager.getRsaKey().getKeyID()).isEqualTo(originalRsaKid);
        // No 403/200 status set by our code (CSRFFilter owns the response in this case)
        verify(response, never()).setStatus(anyInt());
        verify(response, never()).setContentType(anyString());
    }

    @Test
    public void postWithNoSessionUserReturns403() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        KeyRotationController controller = controller(new JwtKeyManager(serverPaths));

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("POST");
        HttpServletResponse response = mock(HttpServletResponse.class);

        try (MockedStatic<SessionUser> sessionUser = mockStatic(SessionUser.class)) {
            sessionUser.when(() -> SessionUser.getUser(request)).thenReturn(null);
            controller.doHandle(request, response);
            verify(response).setStatus(HttpServletResponse.SC_FORBIDDEN);
        }
    }

    @Test
    public void postWithNonAdminUserReturns403() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        KeyRotationController controller = controller(new JwtKeyManager(serverPaths));

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("POST");
        HttpServletResponse response = mock(HttpServletResponse.class);

        SUser nonAdminUser = mock(SUser.class);
        when(nonAdminUser.isPermissionGrantedGlobally(Permission.MANAGE_SERVER_INSTALLATION)).thenReturn(false);

        try (MockedStatic<SessionUser> sessionUser = mockStatic(SessionUser.class)) {
            sessionUser.when(() -> SessionUser.getUser(request)).thenReturn(nonAdminUser);
            controller.doHandle(request, response);
            verify(response).setStatus(HttpServletResponse.SC_FORBIDDEN);
        }
    }
}
