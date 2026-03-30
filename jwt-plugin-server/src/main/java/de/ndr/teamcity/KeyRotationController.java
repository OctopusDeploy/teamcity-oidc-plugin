package de.ndr.teamcity;

import jetbrains.buildServer.controllers.BaseController;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import org.jetbrains.annotations.NotNull;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class KeyRotationController extends BaseController {

    static final String PATH = "/admin/jwtKeyRotate.html";

    @NotNull
    private final JwtBuildFeature jwtBuildFeature;

    public KeyRotationController(@NotNull WebControllerManager controllerManager,
                                 @NotNull JwtBuildFeature jwtBuildFeature) {
        this.jwtBuildFeature = jwtBuildFeature;
        controllerManager.registerController(PATH, this);
    }

    @Override
    protected ModelAndView doHandle(@NotNull HttpServletRequest request,
                                    @NotNull HttpServletResponse response) throws IOException {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return null;
        }

        try {
            jwtBuildFeature.rotateKey();
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"status\":\"rotated\"}");
        } catch (Exception e) {
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("{\"status\":\"error\",\"message\":\"" + e.getMessage() + "\"}");
        }
        return null;
    }
}
