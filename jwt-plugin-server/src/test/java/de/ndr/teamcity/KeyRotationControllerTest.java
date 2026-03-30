package de.ndr.teamcity;

import jetbrains.buildServer.serverSide.ServerPaths;
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
import java.io.PrintWriter;
import java.io.StringWriter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class KeyRotationControllerTest {

    @Mock
    private WebControllerManager controllerManager;

    @Mock
    private ServerPaths serverPaths;

    @Mock
    private PluginDescriptor pluginDescriptor;

    @Mock
    private jetbrains.buildServer.serverSide.SBuildServer buildServer;

    @TempDir
    private File tempDir;

    @Test
    public void registersAtAdminPath() {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        new KeyRotationController(controllerManager, jwtBuildFeature);

        verify(controllerManager).registerController(eq(KeyRotationController.PATH), any(KeyRotationController.class));
    }

    @Test
    public void postRequestRotatesKeyAndReturnsJson() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);
        String originalRsaKid = jwtBuildFeature.getRsaKey().getKeyID();
        String originalEcKid = jwtBuildFeature.getEcKey().getKeyID();

        KeyRotationController controller = new KeyRotationController(controllerManager, jwtBuildFeature);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("POST");
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        ModelAndView result = controller.doHandle(request, response);

        assertThat(result).isNull();
        assertThat(jwtBuildFeature.getRsaKey().getKeyID()).isNotEqualTo(originalRsaKid);
        assertThat(jwtBuildFeature.getEcKey().getKeyID()).isNotEqualTo(originalEcKid);
        verify(response).setContentType("application/json;charset=UTF-8");
        assertThat(writer.toString()).contains("rotated");
    }

    @Test
    public void getRequestReturns405MethodNotAllowed() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        KeyRotationController controller = new KeyRotationController(controllerManager, jwtBuildFeature);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("GET");
        HttpServletResponse response = mock(HttpServletResponse.class);

        controller.doHandle(request, response);

        verify(response).setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
    }
}
