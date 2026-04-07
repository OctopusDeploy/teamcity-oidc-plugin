package com.octopus.teamcity.oidc;

import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.controllers.BaseController;
import jetbrains.buildServer.serverSide.auth.Permission;
import jetbrains.buildServer.users.SUser;
import jetbrains.buildServer.web.CSRFFilter;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import jetbrains.buildServer.web.util.SessionUser;
import net.minidev.json.JSONObject;
import org.jetbrains.annotations.NotNull;
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

    public RotationSettingsController(@NotNull WebControllerManager controllerManager,
                                      @NotNull RotationSettingsManager settingsManager,
                                      @NotNull ExtensionHolder extensionHolder) {
        this(controllerManager, settingsManager, new CSRFFilter(extensionHolder));
    }

    RotationSettingsController(@NotNull WebControllerManager controllerManager,
                               @NotNull RotationSettingsManager settingsManager,
                               @NotNull CSRFFilter csrfFilter) {
        this.settingsManager = settingsManager;
        this.csrfFilter = csrfFilter;
        controllerManager.registerController(PATH, this);
        LOG.info("JWT plugin: RotationSettingsController registered at " + PATH);
    }

    @Override
    protected ModelAndView doHandle(@NotNull HttpServletRequest request,
                                    @NotNull HttpServletResponse response) throws IOException {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return null;
        }

        if (!csrfFilter.validateRequest(request, response)) {
            return null;
        }

        response.setContentType("application/json;charset=UTF-8");

        SUser user = SessionUser.getUser(request);
        if (user == null || !user.isPermissionGrantedGlobally(Permission.MANAGE_SERVER_INSTALLATION)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            writeJson(response, false, "Access denied");
            return null;
        }

        String cronSchedule = request.getParameter("cronSchedule");
        if (cronSchedule == null || cronSchedule.isBlank()) {
            writeJson(response, false, "Missing required parameter: cronSchedule");
            return null;
        }
        try {
            CronExpression.parse(cronSchedule);
        } catch (IllegalArgumentException e) {
            writeJson(response, false, "Invalid cron schedule: " + e.getMessage());
            return null;
        }

        boolean enabled = "true".equalsIgnoreCase(request.getParameter("enabled"));
        RotationSettings current = settingsManager.load();
        settingsManager.save(new RotationSettings(enabled, cronSchedule, current.lastRotatedAt()));

        LOG.info("JWT plugin: rotation settings updated (enabled=" + enabled + ", schedule=" + cronSchedule + ")");
        writeJson(response, true, "Settings saved");
        return null;
    }

    private static void writeJson(HttpServletResponse response, boolean ok, String message) throws IOException {
        JSONObject json = new JSONObject();
        json.put("ok", ok);
        json.put("message", message);
        response.getWriter().write(json.toJSONString());
    }
}
