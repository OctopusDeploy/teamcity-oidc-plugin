package de.ndr.teamcity;

import com.nimbusds.jose.jwk.JWKSet;
import jetbrains.buildServer.controllers.BaseController;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import org.jetbrains.annotations.NotNull;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwksController extends BaseController {

    static final String PATH = "/.well-known/jwks.json";

    @NotNull
    private final JwtBuildFeature jwtBuildFeature;

    public JwksController(@NotNull WebControllerManager controllerManager,
                          @NotNull JwtBuildFeature jwtBuildFeature) {
        this.jwtBuildFeature = jwtBuildFeature;
        controllerManager.registerController(PATH, this);
    }

    @Override
    protected ModelAndView doHandle(@NotNull HttpServletRequest request,
                                    @NotNull HttpServletResponse response) throws IOException {
        response.setContentType("application/json;charset=UTF-8");
        response.setHeader("Cache-Control", "max-age=300");
        JWKSet jwks = new JWKSet(jwtBuildFeature.getPublicKeys());
        response.getWriter().write(jwks.toString());
        return null;
    }
}
