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
import java.time.Duration;
import java.time.Instant;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KeyRotationController extends BaseController {
    private static final Logger LOG = Logger.getLogger(KeyRotationController.class.getName());

    static final String PATH = "/admin/jwtKeyRotate.html";

    @NotNull private final JwtKeyManager keyManager;
    @NotNull private final RotationSettingsManager settingsManager;
    @NotNull private final OidcSettingsManager oidcSettingsManager;
    @NotNull private final CSRFFilter csrfFilter;

    @Autowired
    public KeyRotationController(@NotNull final WebControllerManager controllerManager,
                                 @NotNull final JwtKeyManager keyManager,
                                 @NotNull final RotationSettingsManager settingsManager,
                                 @NotNull final OidcSettingsManager oidcSettingsManager,
                                 @NotNull final ExtensionHolder extensionHolder) {
        this(controllerManager, keyManager, settingsManager, oidcSettingsManager, new CSRFFilter(extensionHolder));
    }

    KeyRotationController(@NotNull final WebControllerManager controllerManager,
                          @NotNull final JwtKeyManager keyManager,
                          @NotNull final RotationSettingsManager settingsManager,
                          @NotNull final OidcSettingsManager oidcSettingsManager,
                          @NotNull final CSRFFilter csrfFilter) {
        this.keyManager = keyManager;
        this.settingsManager = settingsManager;
        this.oidcSettingsManager = oidcSettingsManager;
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
        if (user == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return null;
        }
        if (!user.isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return null;
        }

        try {
            final var cacheLifetimeMinutes = oidcSettingsManager.load().jwksCacheLifetimeMinutes();
            // Why ×2: a consumer's cache can be at most max-age + stale-while-revalidate stale.
            // We set those equal to jwksCacheLifetimeMinutes, so worst-case staleness is 2× that.
            // Rotating again inside this window can drop the retired key before stale caches refresh.
            final var minRotationGapSeconds = cacheLifetimeMinutes * 60L * 2L;

            final var lastRotatedAt = settingsManager.load().lastRotatedAt();
            final var secondsSinceLast = lastRotatedAt != null
                    ? Duration.between(lastRotatedAt, Instant.now()).getSeconds()
                    : Long.MAX_VALUE;

            LOG.info("JWT plugin: key rotation requested");
            keyManager.rotateKey();
            settingsManager.updateLastRotatedAt(Instant.now());
            LOG.info("JWT plugin: key rotation completed successfully");

            response.setContentType("application/json;charset=UTF-8");
            final var result = new JSONObject();
            result.put("status", "rotated");
            if (secondsSinceLast < minRotationGapSeconds) {
                final var warning = "Warning: Keys were rotated again after only " + secondsSinceLast + "s — verifiers "
                        + "with cached JWKS may fail to validate tokens signed by the previous key "
                        + "until their cache refreshes (up to " + minRotationGapSeconds + "s).";
                result.put("warning", warning);
                LOG.warning("JWT plugin: " + warning);
            }
            response.getWriter().write(result.toJSONString());
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
