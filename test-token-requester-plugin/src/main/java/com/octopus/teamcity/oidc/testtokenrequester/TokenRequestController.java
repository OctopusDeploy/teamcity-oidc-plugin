package com.octopus.teamcity.oidc.testtokenrequester;

import jetbrains.buildServer.controllers.BaseController;
import jetbrains.buildServer.serverSide.ProjectManager;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.serverSide.connections.credentials.ConnectionCredentialsException;
import jetbrains.buildServer.serverSide.connections.credentials.ProjectConnectionCredentialsManager;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import org.jetbrains.annotations.NotNull;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Requests an edit-time OIDC token through TeamCity's {@link ProjectConnectionCredentialsManager},
 * as another plugin would, and returns the credentials' properties as JSON.
 *
 * <p>Test-only: returning the token to the HTTP caller is exactly what a real caller must not do.
 */
public class TokenRequestController extends BaseController {
    static final String PATH = "/testTokenRequester/token.html";
    private static final String BUILD_TYPE_ID_PARAM = "oidc.edit.buildTypeId";

    private final ProjectManager projectManager;
    private final ProjectConnectionCredentialsManager credentialsManager;

    public TokenRequestController(@NotNull final SBuildServer server,
                                  @NotNull final WebControllerManager controllerManager,
                                  @NotNull final ProjectManager projectManager,
                                  @NotNull final ProjectConnectionCredentialsManager credentialsManager) {
        super(server);
        this.projectManager = projectManager;
        this.credentialsManager = credentialsManager;
        controllerManager.registerController(PATH, this);
    }

    @Override
    protected ModelAndView doHandle(@NotNull final HttpServletRequest request,
                                    @NotNull final HttpServletResponse response) throws Exception {
        response.setContentType("application/json;charset=UTF-8");
        final var project = projectManager.findProjectByExternalId(request.getParameter("projectId"));
        if (project == null) {
            response.getWriter().write(json(Map.of("ok", "false", "error", "Unknown project")));
            return null;
        }
        final var buildTypeId = request.getParameter("buildTypeId");
        final Map<String, String> params = buildTypeId == null ? Map.of() : Map.of(BUILD_TYPE_ID_PARAM, buildTypeId);
        final Map<String, String> body = new LinkedHashMap<>();
        try {
            final var credentials = credentialsManager.requestConnectionCredentials(
                    project, request.getParameter("connectionId"), params);
            body.put("ok", "true");
            body.put("providerType", credentials.getProviderType());
            body.putAll(credentials.getProperties());
        } catch (final ConnectionCredentialsException e) {
            body.put("ok", "false");
            body.put("error", e.getMessage());
        }
        response.getWriter().write(json(body));
        return null;
    }

    private static String json(final Map<String, String> values) {
        return values.entrySet().stream()
                .map(entry -> quote(entry.getKey()) + ":" + quote(entry.getValue()))
                .collect(Collectors.joining(",", "{", "}"));
    }

    private static String quote(final String value) {
        return "\"" + (value == null ? "" : value.replace("\\", "\\\\").replace("\"", "\\\"")) + "\"";
    }
}
