package com.octopus.teamcity.oidc;

import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.controllers.BaseController;
import jetbrains.buildServer.serverSide.auth.Permission;
import jetbrains.buildServer.web.CSRFFilter;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import jetbrains.buildServer.web.util.SessionUser;
import net.minidev.json.JSONObject;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KeyRotationController extends BaseController {
    private static final Logger LOG = Logger.getLogger(KeyRotationController.class.getName());

    static final String PATH = "/admin/jwtKeyRotate.html";

    @NotNull private final JwtKeyManager keyManager;
    @NotNull private final RotationSettingsManager settingsManager;
    @NotNull private final CSRFFilter csrfFilter;

    @Autowired
    public KeyRotationController(@NotNull final WebControllerManager controllerManager,
                                 @NotNull final JwtKeyManager keyManager,
                                 @NotNull final RotationSettingsManager settingsManager,
                                 @NotNull final ExtensionHolder extensionHolder) {
        this(controllerManager, keyManager, settingsManager, new CSRFFilter(extensionHolder));
    }

    KeyRotationController(@NotNull final WebControllerManager controllerManager,
                          @NotNull final JwtKeyManager keyManager,
                          @NotNull final RotationSettingsManager settingsManager,
                          @NotNull final CSRFFilter csrfFilter) {
        this.keyManager = keyManager;
        this.settingsManager = settingsManager;
        this.csrfFilter = csrfFilter;
        controllerManager.registerController(PATH, this);
        LOG.info("JWT plugin: KeyRotationController registered at " + PATH);
    }

    @Override
    protected ModelAndView doHandle(@NotNull final HttpServletRequest request,
                                    @NotNull final HttpServletResponse response) throws IOException {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return null;
        }

        if (!csrfFilter.validateRequest(request, response)) {
            return null;
        }

        final var user = SessionUser.getUser(request);
        if (user == null || !user.isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return null;
        }

        try {
            LOG.info("JWT plugin: key rotation requested");
            keyManager.rotateKey();
            settingsManager.updateLastRotatedAt(java.time.Instant.now());
            LOG.info("JWT plugin: key rotation completed successfully");
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"status\":\"rotated\"}");
        } catch (final Exception e) {
            LOG.log(Level.SEVERE, "JWT plugin: key rotation failed", e);
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            final var error = new JSONObject();
            error.put("status", "error");
            error.put("message", "Key rotation failed.");
            response.getWriter().write(error.toJSONString());
        }
        return null;
    }
}
