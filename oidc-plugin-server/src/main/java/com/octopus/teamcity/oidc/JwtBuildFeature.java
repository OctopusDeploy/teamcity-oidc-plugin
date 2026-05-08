package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.*;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.Collection;

public class JwtBuildFeature extends BuildFeature {

    static final String FEATURE_TYPE = "oidc-plugin";

    private static volatile OidcIssuerUrlProvider staticIssuerUrlProvider;
    private static volatile SBuildServer staticBuildServer;
    private static volatile OidcSettingsManager staticOidcSettingsManager;

    private final PluginDescriptor pluginDescriptor;
    private final OidcIssuerUrlProvider issuerUrlProvider;
    private final OidcSettingsManager oidcSettingsManager;

    public JwtBuildFeature(@NotNull final PluginDescriptor pluginDescriptor,
                           @NotNull final SBuildServer buildServer,
                           @NotNull final OidcIssuerUrlProvider issuerUrlProvider,
                           @NotNull final OidcSettingsManager oidcSettingsManager) {
        this.pluginDescriptor = pluginDescriptor;
        this.issuerUrlProvider = issuerUrlProvider;
        this.oidcSettingsManager = oidcSettingsManager;
        staticIssuerUrlProvider = issuerUrlProvider;
        staticBuildServer = buildServer;
        staticOidcSettingsManager = oidcSettingsManager;
    }

    /** Used by the edit JSP to check the issuer URL without Spring context access. */
    public static boolean isRootUrlHttps() {
        return staticIssuerUrlProvider != null && OidcUrlUtils.isHttpsUrl(staticIssuerUrlProvider.getIssuerUrl());
    }

    /** Used by the edit JSP to render the configured upper bound in the small note. */
    public static int maxTokenLifetimeMinutes() {
        final var mgr = staticOidcSettingsManager;
        return mgr != null ? mgr.load().maxTokenLifetimeMinutes() : OidcSettings.DEFAULT_MAX_TOKEN_LIFETIME_MINUTES;
    }

    /** Sample claim values from the most recent finished build, used by the edit JSP. */
    public record SampleClaims(@NotNull String branch, @NotNull String triggerType, boolean hasVcsRoot) {}

    public static SampleClaims sampleClaimsFor(@Nullable final String buildTypeIdParam) {
        final var server = staticBuildServer;
        if (server == null || buildTypeIdParam == null || buildTypeIdParam.isBlank()) {
            return new SampleClaims("", "", false);
        }
        // The build feature edit dialog passes id as "buildType:<externalId>".
        // Strip the prefix when present so findBuildTypeByExternalId resolves it.
        final var externalId = buildTypeIdParam.startsWith("buildType:")
                ? buildTypeIdParam.substring("buildType:".length())
                : buildTypeIdParam;
        final var buildType = server.getProjectManager().findBuildTypeByExternalId(externalId);
        if (buildType == null) return new SampleClaims("", "", false);
        final var hasVcsRoot = !buildType.getVcsRoots().isEmpty();
        final var history = buildType.getHistory();
        if (history.isEmpty()) return new SampleClaims("", "", hasVcsRoot);
        final var lastBuild = history.get(0);
        final var branchName = ClaimsResolver.resolveBranchName(lastBuild);
        final var triggerType = ClaimsResolver.resolveTriggerType(lastBuild.getTriggeredBy());
        return new SampleClaims(branchName, triggerType, hasVcsRoot);
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
            final var maxTtl = oidcSettingsManager.load().maxTokenLifetimeMinutes();
            final var ttl = params.getOrDefault("ttl_minutes", "10");
            try {
                final var ttlValue = Integer.parseInt(ttl);
                if (ttlValue < OidcSettings.MIN_TOKEN_LIFETIME_MINUTES || ttlValue > maxTtl) {
                    errors.add(new InvalidProperty("ttl_minutes",
                            "Token lifetime must be between " + OidcSettings.MIN_TOKEN_LIFETIME_MINUTES
                            + " and " + maxTtl + " minutes."));
                }
            } catch (final NumberFormatException e) {
                errors.add(new InvalidProperty("ttl_minutes", "Token lifetime must be a valid integer."));
            }
            return errors;
        };
    }
}
