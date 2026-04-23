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
import org.springframework.scheduling.support.CronExpression;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Logger;

public class RotationSettingsController extends BaseController {
    private static final Logger LOG = Logger.getLogger(RotationSettingsController.class.getName());
    static final String PATH = "/admin/jwtRotationSettings.html";

    private final RotationSettingsManager settingsManager;
    private final CSRFFilter csrfFilter;

    @Autowired
    public RotationSettingsController(@NotNull final WebControllerManager controllerManager,
                                      @NotNull final RotationSettingsManager settingsManager,
                                      @NotNull final ExtensionHolder extensionHolder) {
        this(controllerManager, settingsManager, new CSRFFilter(extensionHolder));
    }

    RotationSettingsController(@NotNull final WebControllerManager controllerManager,
                               @NotNull final RotationSettingsManager settingsManager,
                               @NotNull final CSRFFilter csrfFilter) {
        this.settingsManager = settingsManager;
        this.csrfFilter = csrfFilter;
        controllerManager.registerController(PATH, this);
        LOG.info("JWT plugin: RotationSettingsController registered at " + PATH);
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

        response.setContentType("application/json;charset=UTF-8");

        final var user = SessionUser.getUser(request);
        if (user == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            writeJson(response, false, "Not authenticated");
            return null;
        }
        if (!user.isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            writeJson(response, false, "Access denied");
            return null;
        }

        final var cronSchedule = request.getParameter("cronSchedule");
        if (cronSchedule == null || cronSchedule.isBlank()) {
            writeJson(response, false, "Missing required parameter: cronSchedule");
            return null;
        }
        try {
            CronExpression.parse(cronSchedule);
        } catch (final IllegalArgumentException e) {
            writeJson(response, false, "Invalid cron schedule: " + e.getMessage());
            return null;
        }

        final var enabled = "true".equalsIgnoreCase(request.getParameter("enabled"));
        settingsManager.save(enabled, cronSchedule);

        LOG.info("JWT plugin: rotation settings updated (enabled=" + enabled + ", schedule=" + sanitize(cronSchedule) + ")");
        writeJson(response, true, "Settings saved");
        return null;
    }

    private static String sanitize(final String s) {
        return s == null ? "" : s.replaceAll("[\\r\\n\\t]", "_");
    }

    private static void writeJson(final HttpServletResponse response, final boolean ok, final String message) throws IOException {
        final var json = new JSONObject();
        json.put("ok", ok);
        json.put("message", message);
        response.getWriter().write(json.toJSONString());
    }
}
