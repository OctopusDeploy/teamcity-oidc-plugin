package de.ndr.teamcity;

import jetbrains.buildServer.controllers.BaseController;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import org.jetbrains.annotations.NotNull;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KeyRotationController extends BaseController {
    private static final Logger LOG = Logger.getLogger(KeyRotationController.class.getName());

    static final String PATH = "/admin/jwtKeyRotate.html";

    @NotNull
    private final JwtBuildFeature jwtBuildFeature;

    public KeyRotationController(@NotNull WebControllerManager controllerManager,
                                 @NotNull JwtBuildFeature jwtBuildFeature) {
        this.jwtBuildFeature = jwtBuildFeature;
        controllerManager.registerController(PATH, this);
        LOG.info("JWT plugin: KeyRotationController registered at " + PATH);
    }

    @Override
    protected ModelAndView doHandle(@NotNull HttpServletRequest request,
                                    @NotNull HttpServletResponse response) throws IOException {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return null;
        }

        try {
            LOG.info("JWT plugin: key rotation requested");
            jwtBuildFeature.rotateKey();
            LOG.info("JWT plugin: key rotation completed successfully");
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"status\":\"rotated\"}");
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "JWT plugin: key rotation failed", e);
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("{\"status\":\"error\",\"message\":\"" + e.getMessage() + "\"}");
        }
        return null;
    }
}
