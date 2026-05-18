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
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.logging.Level;
import java.util.logging.Logger;

public class OidcSettingsController extends BaseController {
    private static final Logger LOG = Logger.getLogger(OidcSettingsController.class.getName());
    static final String PATH = "/admin/jwtOidcSettings.html";

    private final OidcSettingsManager settingsManager;
    private final CSRFFilter csrfFilter;
    private final HttpClient httpClient;

    sealed interface ReachabilityResult permits OidcSettingsController.Ok, OidcSettingsController.Warning, OidcSettingsController.Err {
    }

    record Ok() implements ReachabilityResult {
    }

    record Warning(String message) implements ReachabilityResult {
    }

    record Err(String message) implements ReachabilityResult {
    }

    @Autowired
    public OidcSettingsController(@NotNull final WebControllerManager controllerManager,
                                  @NotNull final OidcSettingsManager settingsManager,
                                  @NotNull final ExtensionHolder extensionHolder) {
        this(controllerManager, settingsManager, new CSRFFilter(extensionHolder), HttpClient.newHttpClient());
    }

    OidcSettingsController(@NotNull final WebControllerManager controllerManager,
                           @NotNull final OidcSettingsManager settingsManager,
                           @NotNull final CSRFFilter csrfFilter,
                           @NotNull final HttpClient httpClient) {
        this.settingsManager = settingsManager;
        this.csrfFilter = csrfFilter;
        this.httpClient = httpClient;
        controllerManager.registerController(PATH, this);
        LOG.info("JWT plugin: OidcSettingsController registered at " + PATH);
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
            writeJson(response, "error", "Not authenticated");
            return null;
        }
        if (!user.isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            writeJson(response, "error", "Access denied");
            return null;
        }

        // Multiple independent sections of the admin page POST here (Issuer URL, Token
        // defaults, and JWKS — Key Rotation has its own controller). Dispatch on which
        // parameter the request carries; reject requests that include none.
        final var hasMax = request.getParameterMap().containsKey("maxTokenLifetimeMinutes");
        final var hasOverride = request.getParameterMap().containsKey("overrideIssuerUrl");
        final var hasCache = request.getParameterMap().containsKey("jwksCacheLifetimeMinutes");

        if (hasMax) {
            handleMaxTokenLifetime(response, request.getParameter("maxTokenLifetimeMinutes"));
            return null;
        }
        if (hasOverride) {
            handleOverrideIssuerUrl(response, request.getParameter("overrideIssuerUrl"));
            return null;
        }
        if (hasCache) {
            handleJwksCacheLifetime(response, request.getParameter("jwksCacheLifetimeMinutes"));
            return null;
        }

        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        writeJson(response, "error",
                "Missing parameter: expected overrideIssuerUrl, maxTokenLifetimeMinutes, or jwksCacheLifetimeMinutes");
        return null;
    }

    private void handleOverrideIssuerUrl(final HttpServletResponse response, final String rawUrl) throws IOException {
        if (rawUrl == null || rawUrl.isBlank()) {
            settingsManager.saveOverrideIssuerUrl(null);
            writeJson(response, "ok", "Override cleared");
            return;
        }

        final var normalised = OidcUrlUtils.normalizeRootUrl(rawUrl.strip());

        final URI uri;
        try {
            uri = URI.create(normalised);
        } catch (final IllegalArgumentException e) {
            writeJson(response, "error", "Invalid URL: " + e.getMessage());
            return;
        }

        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            writeJson(response, "error", "The issuer URL must use HTTPS");
            return;
        }

        final var result = checkReachability(normalised);

        switch (result) {
            case Ok ignored -> {
                settingsManager.saveOverrideIssuerUrl(normalised);
                writeJson(response, "ok", "Settings saved");
            }
            case Warning w -> {
                settingsManager.saveOverrideIssuerUrl(normalised);
                writeJson(response, "warn", w.message());
            }
            case Err err -> writeJson(response, "error", err.message());
        }
    }

    private void handleMaxTokenLifetime(final HttpServletResponse response, final String raw) throws IOException {
        final int value;
        try {
            value = Integer.parseInt(raw.strip());
        } catch (final NumberFormatException e) {
            writeJson(response, "error", "Max token lifetime must be a whole number of minutes");
            return;
        }
        if (value < OidcSettings.MIN_TOKEN_LIFETIME_MINUTES) {
            writeJson(response, "error", "Max token lifetime must be at least "
                    + OidcSettings.MIN_TOKEN_LIFETIME_MINUTES + " minute");
            return;
        }
        if (value > OidcSettings.ABSOLUTE_MAX_TOKEN_LIFETIME_MINUTES) {
            writeJson(response, "error", "Max token lifetime must not exceed "
                    + OidcSettings.ABSOLUTE_MAX_TOKEN_LIFETIME_MINUTES + " minutes (24 hours)");
            return;
        }
        settingsManager.saveMaxTokenLifetimeMinutes(value);
        writeJson(response, "ok", "Max token lifetime saved");
    }

    private void handleJwksCacheLifetime(final HttpServletResponse response, final String raw) throws IOException {
        final int value;
        try {
            value = Integer.parseInt(raw.strip());
        } catch (final NumberFormatException e) {
            writeJson(response, "error", "JWKS cache lifetime must be a whole number of minutes");
            return;
        }
        if (value < OidcSettings.MIN_JWKS_CACHE_LIFETIME_MINUTES) {
            writeJson(response, "error", "JWKS cache lifetime must be at least "
                    + OidcSettings.MIN_JWKS_CACHE_LIFETIME_MINUTES + " minute");
            return;
        }
        if (value > OidcSettings.MAX_JWKS_CACHE_LIFETIME_MINUTES) {
            writeJson(response, "error", "JWKS cache lifetime must not exceed "
                    + OidcSettings.MAX_JWKS_CACHE_LIFETIME_MINUTES + " minutes (24 hours)");
            return;
        }
        settingsManager.saveJwksCacheLifetimeMinutes(value);
        writeJson(response, "ok", "JWKS cache lifetime saved");
    }

    private ReachabilityResult checkReachability(final String baseUrl) {
        final var discoveryUrl = baseUrl + WellKnownPublicFilter.OIDC_DISCOVERY_PATH;
        try {
            final var req = HttpRequest.newBuilder()
                    .uri(URI.create(discoveryUrl))
                    .GET()
                    .timeout(Duration.ofSeconds(5))
                    .build();
            final var resp = httpClient.send(req, HttpResponse.BodyHandlers.discarding());
            final var status = resp.statusCode();
            if (status >= 200 && status < 300) {
                return new Ok();
            }
            return new Err("URL returned HTTP " + status + " — enter the final destination URL with no redirects");
        } catch (final IOException e) {
            LOG.log(Level.WARNING, "JWT plugin: reachability check failed for " + discoveryUrl, e);
            return new Warning("URL saved but could not be verified — TeamCity may not be able to reach it from inside the network");
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            LOG.log(Level.WARNING, "JWT plugin: reachability check interrupted for " + discoveryUrl, e);
            return new Warning("URL saved but could not be verified — TeamCity may not be able to reach it from inside the network");
        }
    }

    private static void writeJson(final HttpServletResponse response, final String state, final String message) throws IOException {
        final var json = new JSONObject();
        json.put("state", state);
        json.put("message", message);
        response.getWriter().write(json.toJSONString());
    }
}
