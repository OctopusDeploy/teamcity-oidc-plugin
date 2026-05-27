package com.octopus.teamcity.oidc;

import com.nimbusds.jwt.JWTClaimsSet;
import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.controllers.BaseController;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.serverSide.auth.Permission;
import jetbrains.buildServer.users.SUser;
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
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Renders a sample-token preview for the OIDC Identity Token connection edit page.
 * Mirrors the JWT test step on the build feature editor — issues a short-lived
 * token using the connection's current form values, without saving the connection.
 */
public class OidcConnectionTestController extends BaseController {
    private static final Logger LOG = Logger.getLogger(OidcConnectionTestController.class.getName());
    static final String PATH = "/admin/oidcConnectionTest.html";
    private static final Set<String> ALLOWED_ALGORITHMS = Set.of("RS256", "RS384", "ES256");

    private final JwtKeyManager keyManager;
    private final SBuildServer buildServer;
    private final OidcIssuerUrlProvider issuerUrlProvider;
    private final CSRFFilter csrfFilter;

    @Autowired
    public OidcConnectionTestController(@NotNull final WebControllerManager controllerManager,
                                        @NotNull final JwtKeyManager keyManager,
                                        @NotNull final SBuildServer buildServer,
                                        @NotNull final OidcIssuerUrlProvider issuerUrlProvider,
                                        @NotNull final ExtensionHolder extensionHolder) {
        this(controllerManager, keyManager, buildServer, issuerUrlProvider, new CSRFFilter(extensionHolder));
    }

    OidcConnectionTestController(@NotNull final WebControllerManager controllerManager,
                                 @NotNull final JwtKeyManager keyManager,
                                 @NotNull final SBuildServer buildServer,
                                 @NotNull final OidcIssuerUrlProvider issuerUrlProvider,
                                 @NotNull final CSRFFilter csrfFilter) {
        this.keyManager = keyManager;
        this.buildServer = buildServer;
        this.issuerUrlProvider = issuerUrlProvider;
        this.csrfFilter = csrfFilter;
        controllerManager.registerController(PATH, this);
        LOG.info("JWT plugin: OidcConnectionTestController registered at " + PATH);
    }

    @Override
    protected ModelAndView doHandle(@NotNull final HttpServletRequest request,
                                    @NotNull final HttpServletResponse response) throws IOException {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return null;
        }
        if (!csrfFilter.validateRequest(request, response)) return null;
        final var user = SessionUser.getUser(request);
        if (user == null || !user.isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            writeJson(response, false, "Access denied");
            return null;
        }
        handlePreviewForTest(request, response, user);
        return null;
    }

    /** Package-visible entry point used by tests to bypass CSRF + session lookup. */
    void handlePreviewForTest(final HttpServletRequest request,
                              final HttpServletResponse response,
                              final SUser user) throws IOException {
        response.setContentType("application/json;charset=UTF-8");
        try {
            final var algorithm = request.getParameter("algorithm");
            if (algorithm == null || !ALLOWED_ALGORITHMS.contains(algorithm)) {
                writeJson(response, false, "Unsupported algorithm — must be one of: " + String.join(", ", ALLOWED_ALGORITHMS));
                return;
            }
            final var rootUrl = issuerUrlProvider.getIssuerUrl();
            if (!OidcUrlUtils.isHttpsUrl(rootUrl)) {
                writeJson(response, false, "Issuer URL is not HTTPS — OIDC endpoints won't be reachable");
                return;
            }
            final var rawAudience = request.getParameter("audience");
            final var audience = rawAudience == null || rawAudience.isBlank() ? rootUrl : rawAudience;
            final var subjectDimensionsRaw = request.getParameter("subject_dimensions");
            final var includeBranch = subjectDimensionsRaw != null && subjectDimensionsRaw.contains("branch");
            final var includeTriggerType = subjectDimensionsRaw != null && subjectDimensionsRaw.contains("trigger_type");

            final String projectId;
            final String buildTypeId;
            final var buildTypeExternalId = request.getParameter("buildTypeExternalId");
            if (buildTypeExternalId != null && !buildTypeExternalId.isBlank()) {
                final var bt = buildServer.getProjectManager().findBuildTypeByExternalId(buildTypeExternalId);
                if (bt == null) {
                    writeJson(response, false, "Build type not found: " + buildTypeExternalId);
                    return;
                }
                if (!user.isPermissionGrantedForProject(bt.getProjectId(), Permission.EDIT_PROJECT)) {
                    writeJson(response, false, "Access denied for project: " + bt.getProjectId());
                    return;
                }
                projectId = bt.getProjectId();
                buildTypeId = bt.getInternalId();
            } else {
                projectId = "<project_id>";
                buildTypeId = "<build_type_id>";
            }

            final var sb = new StringBuilder("project:").append(projectId).append(":build_type:").append(buildTypeId);
            if (includeBranch) sb.append(":branch:<branch>");
            if (includeTriggerType) sb.append(":trigger_type:<trigger_type>");
            final var subject = sb.toString();

            // Hard-cap TTL at 1 minute regardless of form input (mirrors JwtTestController):
            // even though this preview only emits a token to the admin's browser, capping the
            // TTL limits any blast radius if the value is somehow exfiltrated.
            final var ttl = 1;
            final var now = new Date();
            final var claims = new JWTClaimsSet.Builder()
                    .jwtID(UUID.randomUUID().toString())
                    .subject(subject)
                    .issuer(rootUrl)
                    .audience(List.of(audience))
                    .issueTime(now)
                    .notBeforeTime(now)
                    .expirationTime(new Date(now.getTime() + ttl * 60_000L))
                    .build();
            final var jwt = keyManager.sign(claims, algorithm);

            final var payload = new JSONObject();
            payload.put("ok", true);
            payload.put("sub", subject);
            payload.put("aud", audience);
            payload.put("alg", algorithm);
            payload.put("ttl_minutes", ttl);
            payload.put("token", jwt.serialize());
            response.getWriter().write(payload.toJSONString());
        } catch (final Exception e) {
            LOG.log(Level.WARNING, "JWT plugin: OIDC connection preview failed", e);
            writeJson(response, false, "An internal error occurred — check the TeamCity server log for details");
        }
    }

    private static void writeJson(final HttpServletResponse response, final boolean ok, final String message) throws IOException {
        final var json = new JSONObject();
        json.put("ok", ok);
        json.put("message", message);
        response.getWriter().write(json.toJSONString());
    }
}
