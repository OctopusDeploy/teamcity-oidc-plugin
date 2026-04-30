package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.*;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.Collection;

public class JwtBuildFeature extends BuildFeature {

    static final String FEATURE_TYPE = "oidc-plugin";

    private static volatile SBuildServer staticServer;
    private static volatile OidcIssuerUrlProvider staticIssuerUrlProvider;

    private final PluginDescriptor pluginDescriptor;
    private final OidcIssuerUrlProvider issuerUrlProvider;

    public JwtBuildFeature(@NotNull final PluginDescriptor pluginDescriptor,
                           @NotNull final SBuildServer buildServer,
                           @NotNull final OidcIssuerUrlProvider issuerUrlProvider) {
        this.pluginDescriptor = pluginDescriptor;
        this.issuerUrlProvider = issuerUrlProvider;
        staticServer = buildServer;
        staticIssuerUrlProvider = issuerUrlProvider;
    }

    /** Used by the edit JSP to check the issuer URL without Spring context access. */
    public static boolean isRootUrlHttps() {
        if (staticIssuerUrlProvider != null) {
            return OidcUrlUtils.isHttpsUrl(staticIssuerUrlProvider.getIssuerUrl());
        }
        return staticServer != null && OidcUrlUtils.isHttpsUrl(staticServer.getRootUrl());
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

    @NotNull
    @Override
    public String describeParameters(@NotNull final java.util.Map<String, String> params) {
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
    public PropertiesProcessor getParametersProcessor(@NotNull final BuildTypeIdentity buildTypeOrTemplate) {
        return params -> {
            final Collection<InvalidProperty> errors = new ArrayList<>();
            if (!OidcUrlUtils.isHttpsUrl(issuerUrlProvider.getIssuerUrl())) {
                errors.add(new InvalidProperty("root_url",
                        "The OIDC issuer URL must use HTTPS for OIDC token issuance. " +
                                "Update the root URL in Administration → Global Settings, or set an override in the OIDC / JWT admin page."));
            }
            final var ttl = params.getOrDefault("ttl_minutes", "10");
            try {
                final var ttlValue = Integer.parseInt(ttl);
                if (ttlValue <= 0 || ttlValue > 1440) {
                    errors.add(new InvalidProperty("ttl_minutes", "Token lifetime must be between 1 and 1440 minutes."));
                }
            } catch (final NumberFormatException e) {
                errors.add(new InvalidProperty("ttl_minutes", "Token lifetime must be a valid integer."));
            }
            return errors;
        };
    }
}
