package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.*;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtBuildFeature extends BuildFeature {

    static final String FEATURE_TYPE = "oidc-plugin";

    /**
     * Optional dimensions that may be appended to the composite {@code sub} claim. Listed in
     * a configured-order that matches the emitted sub layout. Used by:
     * <ul>
     *   <li>{@link JwtIssuanceService} to decide which segments to compose into {@code sub}</li>
     *   <li>{@link #getParametersProcessor} to validate user input at save time</li>
     * </ul>
     */
    public static final Set<String> ALL_OPTIONAL_SUBJECT_DIMENSIONS = Set.of("branch", "trigger_type");

    private static volatile OidcIssuerUrlProvider staticIssuerUrlProvider;
    private static volatile SBuildServer staticBuildServer;
    private static volatile OidcSettingsManager staticOidcSettingsManager;
    private static volatile OidcConnectionsManager staticOidcConnectionsManager;

    private final PluginDescriptor pluginDescriptor;
    private final OidcIssuerUrlProvider issuerUrlProvider;
    private final OidcSettingsManager oidcSettingsManager;
    private final OidcConnectionsManager oidcConnectionsManager;

    public JwtBuildFeature(@NotNull final PluginDescriptor pluginDescriptor,
                           @NotNull final SBuildServer buildServer,
                           @NotNull final OidcIssuerUrlProvider issuerUrlProvider,
                           @NotNull final OidcSettingsManager oidcSettingsManager,
                           @NotNull final OidcConnectionsManager oidcConnectionsManager) {
        this.pluginDescriptor = pluginDescriptor;
        this.issuerUrlProvider = issuerUrlProvider;
        this.oidcSettingsManager = oidcSettingsManager;
        this.oidcConnectionsManager = oidcConnectionsManager;
        staticIssuerUrlProvider = issuerUrlProvider;
        staticBuildServer = buildServer;
        staticOidcSettingsManager = oidcSettingsManager;
        staticOidcConnectionsManager = oidcConnectionsManager;
    }

    /** Used by the edit JSP to check the issuer URL without Spring context access. */
    public static boolean isRootUrlHttps() {
        return staticIssuerUrlProvider != null && OidcUrlUtils.isHttpsUrl(staticIssuerUrlProvider.getIssuerUrl());
    }

    /** Used by the edit JSP to display the resolved issuer URL as a readonly field. */
    public static @NotNull String issuerUrl() {
        final var provider = staticIssuerUrlProvider;
        return provider == null ? "" : provider.getIssuerUrl();
    }

    /**
     * Used by the edit JSP to read the configured max token lifetime without going through
     * Spring's {@code WebApplicationContextUtils}, which only sees TC's root web context and
     * not the plugin's child context.
     */
    public static int maxTokenLifetimeMinutes() {
        final var manager = staticOidcSettingsManager;
        return manager == null
                ? OidcSettings.DEFAULT_MAX_TOKEN_LIFETIME_MINUTES
                : manager.load().maxTokenLifetimeMinutes();
    }

    /**
     * Sample claim values from the most recent finished build, plus the build type's
     * internal IDs — all used by the edit JSP to populate the subject preview. The
     * internal IDs are exposed here because {@code EditBuildTypeForm} only exposes the
     * external ID; we need the internal IDs to render the composite {@code sub} preview.
     */
    public record SampleClaims(@NotNull String branch,
                               @NotNull String triggerType,
                               boolean hasVcsRoot,
                               @NotNull String projectInternalId,
                               @NotNull String projectExternalId,
                               @NotNull String buildTypeInternalId) {

        /** Blank claims, used when there's no build context to resolve sample values from. */
        public static SampleClaims empty() {
            return new SampleClaims("", "", false, "", "", "");
        }
    }

    public static SampleClaims sampleClaimsFor(@Nullable final String buildTypeIdParam) {
        final var server = staticBuildServer;
        if (server == null || buildTypeIdParam == null || buildTypeIdParam.isBlank()) {
            return SampleClaims.empty();
        }
        // On a template, the dialog passes id as "template:<externalId>". Templates apply
        // to many build configurations, so there is no single build history or build type
        // id — expose the owning project and leave the build-specific values blank.
        if (buildTypeIdParam.startsWith("template:")) {
            final var externalId = buildTypeIdParam.substring("template:".length());
            final var template = server.getProjectManager().findBuildTypeTemplateByExternalId(externalId);
            if (template == null) return SampleClaims.empty();
            final var project = template.getProject();
            return new SampleClaims("", "", !template.getVcsRoots().isEmpty(),
                    project.getProjectId(), project.getExternalId(), "");
        }
        // The build feature edit dialog passes id as "buildType:<externalId>".
        // Strip the prefix when present so findBuildTypeByExternalId resolves it.
        final var externalId = buildTypeIdParam.startsWith("buildType:")
                ? buildTypeIdParam.substring("buildType:".length())
                : buildTypeIdParam;
        final var buildType = server.getProjectManager().findBuildTypeByExternalId(externalId);
        if (buildType == null) return SampleClaims.empty();
        final var hasVcsRoot = !buildType.getVcsRoots().isEmpty();
        final var projectInternalId = buildType.getProjectId();
        final var projectExternalId = buildType.getProjectExternalId();
        final var buildTypeInternalId = buildType.getInternalId();
        final var history = buildType.getHistory();
        if (history.isEmpty()) {
            return new SampleClaims("", "", hasVcsRoot, projectInternalId, projectExternalId, buildTypeInternalId);
        }
        final var lastBuild = history.get(0);
        final var branchName = ClaimsResolver.resolveBranchName(lastBuild);
        final var triggerType = ClaimsResolver.resolveTriggerType(lastBuild.getTriggeredBy());
        return new SampleClaims(branchName, triggerType, hasVcsRoot, projectInternalId, projectExternalId, buildTypeInternalId);
    }

    /** Used by the edit JSP to populate the connection dropdown. */
    public static @NotNull java.util.List<OidcConnection> availableConnectionsFor(@Nullable final String buildTypeIdParam) {
        final var server = staticBuildServer;
        final var manager = staticOidcConnectionsManager;
        if (server == null || manager == null || buildTypeIdParam == null || buildTypeIdParam.isBlank()) {
            return java.util.List.of();
        }
        final var project = resolveEditedProject(server, buildTypeIdParam);
        if (project == null) return java.util.List.of();
        return manager.listAvailable(project);
    }

    /**
     * Resolves the project owning the build configuration or template currently being
     * edited. The build feature edit dialog passes id as "buildType:<externalId>" for a
     * build configuration and "template:<externalId>" for a template.
     */
    @Nullable
    private static SProject resolveEditedProject(@NotNull final SBuildServer server,
                                                 @NotNull final String buildTypeIdParam) {
        final var projectManager = server.getProjectManager();
        if (buildTypeIdParam.startsWith("template:")) {
            final var externalId = buildTypeIdParam.substring("template:".length());
            final var template = projectManager.findBuildTypeTemplateByExternalId(externalId);
            return template == null ? null : template.getProject();
        }
        final var externalId = buildTypeIdParam.startsWith("buildType:")
                ? buildTypeIdParam.substring("buildType:".length())
                : buildTypeIdParam;
        final var buildType = projectManager.findBuildTypeByExternalId(externalId);
        return buildType == null ? null : buildType.getProject();
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
        final var connectionId = params.getOrDefault("connection_id", "").trim();
        if (!connectionId.isEmpty() && staticOidcConnectionsManager != null && staticBuildServer != null) {
            return describeConnection(connectionId, params);
        }
        return describeInline(params);
    }

    @NotNull
    private static String describeConnection(@NotNull final String connectionId,
                                             @NotNull final java.util.Map<String, String> params) {
        final var resolved = resolveConnectionFromProjectOrAncestor(connectionId);
        final var variableName = TokenVariableNameResolver.resolve(params, resolved);
        if (resolved.isEmpty()) {
            return "connection: <unknown id " + connectionId + ">\nvar: %" + variableName + "%";
        }
        final var conn = resolved.get();
        final var sb = new StringBuilder("connection: ").append(conn.displayName());
        // Show the sub claim's template form — concrete IDs and runtime values aren't
        // available here, but the template matches what the consumer will see.
        sb.append("\nsub: ").append(subjectTemplate(String.join(",", conn.settings().subjectDimensions())));
        sb.append("\naud: ").append(conn.settings().audience());
        // Variable name last, wrapped in % so it reads like the reference admins use.
        sb.append("\nvar: %").append(variableName).append('%');
        return sb.toString();
    }

    @NotNull
    private static String describeInline(@NotNull final java.util.Map<String, String> params) {
        final var audience = params.get("audience");
        final var variableName = TokenVariableNameResolver.resolve(params, Optional.empty());
        // Show the sub claim's template form — concrete project/build_type IDs and the
        // branch/trigger values aren't available here (no build context), but the template
        // matches what the consumer (e.g. Octopus) will see and helps admins differentiate
        // features with different subject scoping.
        final var sb = new StringBuilder("sub: ").append(subjectTemplate(params.get("subject_dimensions")));
        if (audience != null && !audience.isBlank()) {
            sb.append("\naud: ").append(audience);
        }
        // Variable name last, wrapped in % so it reads like the reference admins use.
        sb.append("\nvar: %").append(variableName).append('%');
        return sb.toString();
    }

    /**
     * {@code describeParameters} has only the params map — no build/project context — so the
     * connection cannot be resolved against a known project. Connections are inherited
     * downward, and TC's {@code findConnectionById} walks upward (project + ancestors), so a
     * connection is only visible from its owning project or a descendant. Hence this scans
     * every project and returns the first that can resolve the id. (Resolving against root
     * alone would only find connections defined directly at root.)
     */
    private static Optional<OidcConnection> resolveConnectionFromProjectOrAncestor(final String connectionId) {
        final var manager = staticOidcConnectionsManager;
        final var server = staticBuildServer;
        if (manager == null || server == null) return Optional.empty();
        for (final var project : server.getProjectManager().getProjects()) {
            final var resolved = manager.resolve(project, connectionId);
            if (resolved.isPresent()) return resolved;
        }
        return Optional.empty();
    }

    static String subjectTemplate(@Nullable final String subjectDimensionsParam) {
        final var raw = subjectDimensionsParam == null ? "" : subjectDimensionsParam.trim();
        final boolean includeBranch;
        final boolean includeTriggerType;
        if (raw.isEmpty()) {
            includeBranch = includeTriggerType = false;
        } else {
            final var dims = java.util.Arrays.asList(raw.split("\\s*,\\s*"));
            includeBranch = dims.contains("branch");
            includeTriggerType = dims.contains("trigger_type");
        }
        final var sb = new StringBuilder("project:<project_id>:build_type:<build_type_id>");
        if (includeBranch) sb.append(":branch:<branch>");
        if (includeTriggerType) sb.append(":trigger_type:<trigger_type>");
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
        return true;
    }

    @Override
    public PropertiesProcessor getParametersProcessor(@NotNull final BuildTypeIdentity buildTypeOrTemplate) {
        final var buildType = buildTypeOrTemplate instanceof final SBuildType bt ? bt : null;
        return params -> {
            final Collection<InvalidProperty> errors = new ArrayList<>();
            validateVariableNameIsUnique(buildType, params, errors);
            validateIssuerIsHttps(errors);
            if (usesConnection(params)) {
                validateConnectionExists(buildType, params, errors);
            } else {
                validateTokenLifetime(params, errors);
                validateSubjectDimensions(params, errors);
            }
            return errors;
        };
    }

    private static boolean usesConnection(@NotNull final java.util.Map<String, String> params) {
        return !params.getOrDefault("connection_id", "").trim().isEmpty();
    }

    private void validateIssuerIsHttps(@NotNull final Collection<InvalidProperty> errors) {
        if (!OidcUrlUtils.isHttpsUrl(issuerUrlProvider.getIssuerUrl())) {
            errors.add(new InvalidProperty("root_url",
                    "The OIDC issuer URL must use HTTPS for OIDC token issuance. " +
                            "Update the root URL in Administration → Global Settings, or set an override in the OIDC / JWT admin page."));
        }
    }

    /** When a connection is selected it supplies the settings, so just verify it still resolves. */
    private void validateConnectionExists(@Nullable final SBuildType bt,
                                          @NotNull final java.util.Map<String, String> params,
                                          @NotNull final Collection<InvalidProperty> errors) {
        if (bt == null) {
            return;
        }
        final var connectionId = params.getOrDefault("connection_id", "").trim();
        if (oidcConnectionsManager.resolve(bt.getProject(), connectionId).isEmpty()) {
            errors.add(new InvalidProperty("connection_id",
                    "Selected connection no longer exists in this project. "
                            + "Pick another connection or clear the field to configure inline settings."));
        }
    }

    /** Rejects saving if another feature on this build config already emits the same variable. */
    private void validateVariableNameIsUnique(@Nullable final SBuildType bt,
                                              @NotNull final java.util.Map<String, String> params,
                                              @NotNull final Collection<InvalidProperty> errors) {
        if (bt == null) {
            return;
        }
        // self_feature_id (rendered by the edit JSP) is the id of the feature being edited; remove
        // it so it isn't persisted, and skip the matching sibling so a feature isn't flagged
        // against its own still-persisted copy.
        final var selfFeatureId = params.remove("self_feature_id");
        final var candidateName = TokenVariableNameResolver.resolve(params, oidcConnectionsManager, bt.getProject());
        for (final var sibling : bt.getBuildFeaturesOfType(FEATURE_TYPE)) {
            if (sibling.getId().equals(selfFeatureId)) {
                continue;
            }
            if (TokenVariableNameResolver.resolve(sibling.getParameters(), oidcConnectionsManager, bt.getProject()).equals(candidateName)) {
                errors.add(new InvalidProperty("token_variable_name",
                        "Another OIDC build feature on this build configuration already emits the "
                                + "variable '" + candidateName + "'. Set a different variable name."));
                return;
            }
        }
    }

    /** Validates the inline token lifetime used when no connection is selected. */
    private void validateTokenLifetime(@NotNull final java.util.Map<String, String> params,
                                       @NotNull final Collection<InvalidProperty> errors) {
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
    }

    /** Validates the inline subject dimensions used when no connection is selected. */
    private void validateSubjectDimensions(@NotNull final java.util.Map<String, String> params,
                                           @NotNull final Collection<InvalidProperty> errors) {
        final var subjectDimensions = params.getOrDefault("subject_dimensions", "");
        if (subjectDimensions.isBlank()) {
            return;
        }
        final var unknown = Arrays.stream(subjectDimensions.split("\\s*,\\s*"))
                .filter(s -> !s.isBlank())
                .filter(s -> !ALL_OPTIONAL_SUBJECT_DIMENSIONS.contains(s))
                .collect(Collectors.toCollection(java.util.LinkedHashSet::new));
        if (!unknown.isEmpty()) {
            errors.add(new InvalidProperty("subject_dimensions",
                    "Unknown subject dimension(s): " + String.join(", ", unknown)
                            + ". Allowed values: " + String.join(", ", ALL_OPTIONAL_SUBJECT_DIMENSIONS)
                            + ", or leave blank for no optional dimensions."));
        }
    }
}
