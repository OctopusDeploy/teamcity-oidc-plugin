package com.octopus.teamcity.oidc;

import com.nimbusds.jose.jwk.JWKSet;
import jetbrains.buildServer.controllers.admin.AdminPage;
import jetbrains.buildServer.serverSide.auth.Permission;
import jetbrains.buildServer.web.openapi.PagePlaces;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.PositionConstraint;
import org.jetbrains.annotations.NotNull;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

public class JwtBuildFeatureAdminPage extends AdminPage {
    private static final String PAGE = "jwtBuildFeatureSettings.jsp";
    private static final String TAB_TITLE = "JWT build feature";

    @NotNull private final JwtKeyManager keyManager;

    public JwtBuildFeatureAdminPage(@NotNull PagePlaces pagePlaces,
                                    @NotNull PluginDescriptor descriptor,
                                    @NotNull JwtKeyManager keyManager) {
        super(pagePlaces);
        this.keyManager = keyManager;
        setPluginName("jwtPlugin");
        setIncludeUrl(descriptor.getPluginResourcesPath(PAGE));
        setTabTitle(TAB_TITLE);
        setPosition(PositionConstraint.after("clouds", "email", "jabber"));
        register();
    }

    @Override
    public void fillModel(@NotNull Map<String, Object> model, @NotNull HttpServletRequest request) {
        super.fillModel(model, request);

        final var jwks = new JWKSet(keyManager.getPublicKeys());
        final var jwksJson = jwks.toString();
        model.put("jwks", jwksJson);
        model.put("jwksBase64", Base64.getEncoder().encodeToString(jwksJson.getBytes(StandardCharsets.UTF_8)));
    }

    @Override
    public boolean isAvailable(@NotNull HttpServletRequest request) {
        return super.isAvailable(request) && checkHasGlobalPermission(request, Permission.CHANGE_SERVER_SETTINGS);
    }

    @NotNull
    @Override
    public String getGroup() {
        return INTEGRATIONS_GROUP;
    }
}
