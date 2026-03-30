package de.ndr.teamcity;

import com.nimbusds.jose.shaded.gson.JsonArray;
import com.nimbusds.jose.shaded.gson.JsonObject;
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

    @NotNull
    private final JwtBuildFeature jwtBuildFeature;

    public OidcDiscoveryController(@NotNull WebControllerManager controllerManager,
                                   @NotNull SBuildServer buildServer,
                                   @NotNull JwtBuildFeature jwtBuildFeature) {
        this.buildServer = buildServer;
        this.jwtBuildFeature = jwtBuildFeature;
        controllerManager.registerController(PATH, this);
    }

    @Override
    protected ModelAndView doHandle(@NotNull HttpServletRequest request,
                                    @NotNull HttpServletResponse response) throws IOException {
        response.setContentType("application/json;charset=UTF-8");

        String issuer = buildServer.getRootUrl();

        JsonObject doc = new JsonObject();
        doc.addProperty("issuer", issuer);
        doc.addProperty("jwks_uri", issuer + JwksController.PATH);

        JsonArray signingAlgs = new JsonArray();
        signingAlgs.add("RS256");
        doc.add("id_token_signing_alg_values_supported", signingAlgs);

        JsonArray responseTypes = new JsonArray();
        responseTypes.add("id_token");
        doc.add("response_types_supported", responseTypes);

        JsonArray subjectTypes = new JsonArray();
        subjectTypes.add("public");
        doc.add("subject_types_supported", subjectTypes);

        response.getWriter().write(doc.toString());
        return null;
    }
}
