package de.ndr.teamcity;

import jetbrains.buildServer.controllers.BaseController;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import org.jetbrains.annotations.NotNull;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class OidcDiscoveryController extends BaseController {

    static final String PATH = "/.well-known/openid-configuration";

    @NotNull
    private final SBuildServer buildServer;

    public OidcDiscoveryController(@NotNull WebControllerManager controllerManager,
                                   @NotNull SBuildServer buildServer,
                                   @NotNull JwtBuildFeature jwtBuildFeature) {
        this.buildServer = buildServer;
        controllerManager.registerController(PATH, this);
    }

    @Override
    protected ModelAndView doHandle(@NotNull HttpServletRequest request,
                                    @NotNull HttpServletResponse response) throws IOException {
        response.setContentType("application/json;charset=UTF-8");
        response.setHeader("Cache-Control", "max-age=300");

        String issuer = buildServer.getRootUrl();
        String body = "{"
                + "\"issuer\":\"" + issuer + "\","
                + "\"jwks_uri\":\"" + issuer + JwksController.PATH + "\","
                + "\"id_token_signing_alg_values_supported\":[\"RS256\",\"ES256\"],"
                + "\"response_types_supported\":[\"id_token\"],"
                + "\"subject_types_supported\":[\"public\"],"
                + "\"claims_supported\":[\"sub\",\"iss\",\"aud\",\"iat\",\"nbf\",\"exp\","
                + "\"branch\",\"build_type_external_id\",\"project_external_id\","
                + "\"triggered_by\",\"triggered_by_id\",\"build_number\"]"
                + "}";

        response.getWriter().write(body);
        return null;
    }
}
