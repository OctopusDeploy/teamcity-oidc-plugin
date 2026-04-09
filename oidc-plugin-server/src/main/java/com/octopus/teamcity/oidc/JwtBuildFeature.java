package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.*;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.Collection;

public class JwtBuildFeature extends BuildFeature {

    static final String FEATURE_TYPE = "oidc-plugin";

    private final PluginDescriptor pluginDescriptor;
    private final SBuildServer buildServer;

    public JwtBuildFeature(@NotNull PluginDescriptor pluginDescriptor, @NotNull SBuildServer buildServer) {
        this.pluginDescriptor = pluginDescriptor;
        this.buildServer = buildServer;
    }

    @NotNull
    @Override
    public String getType() {
        return FEATURE_TYPE;
    }

    @NotNull
    @Override
    public String getDisplayName() {
        return "OIDC Identity Token";
    }

    @Override
    public String describeParameters(@NotNull java.util.Map<String, String> params) {
        final var algorithm = params.getOrDefault("algorithm", "RS256");
        final var ttl = params.getOrDefault("ttl_minutes", "10");
        final var audience = params.get("audience");
        final var sb = new StringBuilder();
        sb.append("alg: ").append(algorithm).append(", ttl: ").append(ttl).append("m");
        if (audience != null && !audience.isBlank()) {
            sb.append(", aud: ").append(audience);
        }
        return sb.toString();
    }

    @Nullable
    @Override
    public String getEditParametersUrl() {
        return pluginDescriptor.getPluginResourcesPath("editJwtBuildFeature.jsp");
    }

    @Override
    public boolean isRequiresAgent() {
        return false;
    }

    @Override
    public boolean isMultipleFeaturesPerBuildTypeAllowed() {
        return false;
    }

    @Override
    public PropertiesProcessor getParametersProcessor() {
        return params -> {
            Collection<InvalidProperty> errors = new ArrayList<>();
            if (!JwtKeyManager.isHttpsUrl(buildServer.getRootUrl())) {
                errors.add(new InvalidProperty("root_url",
                        "The TeamCity server root URL must use HTTPS for OIDC token issuance. " +
                        "Update it in Administration → Global Settings."));
            }
            final var ttl = params.getOrDefault("ttl_minutes", "10");
            try {
                final var ttlValue = Integer.parseInt(ttl);
                if (ttlValue <= 0 || ttlValue > 1440) {
                    errors.add(new InvalidProperty("ttl_minutes", "Token lifetime must be between 1 and 1440 minutes."));
                }
            } catch (NumberFormatException e) {
                errors.add(new InvalidProperty("ttl_minutes", "Token lifetime must be a valid integer."));
            }
            return errors;
        };
    }
}
