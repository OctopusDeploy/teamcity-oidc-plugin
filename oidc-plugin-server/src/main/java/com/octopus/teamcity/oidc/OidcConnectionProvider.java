package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.InvalidProperty;
import jetbrains.buildServer.serverSide.PropertiesProcessor;
import jetbrains.buildServer.serverSide.oauth.OAuthConnectionDescriptor;
import jetbrains.buildServer.serverSide.oauth.OAuthProvider;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Registers a TeamCity {@link OAuthProvider} of type {@value #TYPE} so admins can
 * configure reusable OIDC Identity Token settings under Project Admin → Connections.
 * The {@link JwtBuildFeature} can then reference a connection by id instead of
 * restating audience / TTL / signing algorithm / subject scoping inline.
 */
public class OidcConnectionProvider extends OAuthProvider {

    public static final String TYPE = "oidc-identity-token";
    public static final String DISPLAY_NAME = "OIDC Identity Token";

    private static final Set<String> ALLOWED_ALGORITHMS = Set.of("RS256", "RS384", "ES256");

    private final PluginDescriptor pluginDescriptor;
    private final OidcSettingsManager oidcSettingsManager;

    public OidcConnectionProvider(@NotNull final PluginDescriptor pluginDescriptor,
                                  @NotNull final OidcSettingsManager oidcSettingsManager) {
        this.pluginDescriptor = pluginDescriptor;
        this.oidcSettingsManager = oidcSettingsManager;
    }

    @NotNull
    @Override
    public String getType() {
        return TYPE;
    }

    @NotNull
    @Override
    public String getDisplayName() {
        return DISPLAY_NAME;
    }

    @NotNull
    @Override
    public String getEditParametersUrl() {
        return pluginDescriptor.getPluginResourcesPath("editOidcConnection.jsp");
    }

    @NotNull
    @Override
    public Map<String, String> getDefaultProperties() {
        final var defaults = new LinkedHashMap<String, String>();
        defaults.put("algorithm", "RS256");
        defaults.put("ttl_minutes", "10");
        return defaults;
    }

    @NotNull
    @Override
    public String describeConnection(@NotNull final OAuthConnectionDescriptor descriptor) {
        return describeConnection(descriptor.getParameters());
    }

    @NotNull
    public String describeConnection(@NotNull final Map<String, String> params) {
        final var audience = params.getOrDefault("audience", "");
        final var ttl = params.getOrDefault("ttl_minutes", "10");
        final var algorithm = params.getOrDefault("algorithm", "RS256");
        final var variableName = TokenVariableNameResolver.resolve(params, Optional.empty());
        return "sub: " + JwtBuildFeature.subjectTemplate(params.get("subject_dimensions"))
                + "\naud: " + (audience.isBlank() ? "(issuer URL)" : audience)
                + "\nttl: " + ttl + "m"
                + "\nalg: " + algorithm
                + "\nvar: %" + variableName + "%";
    }

    @Override
    public PropertiesProcessor getPropertiesProcessor() {
        return this::validate;
    }

    private Collection<InvalidProperty> validate(final Map<String, String> params) {
        final Collection<InvalidProperty> errors = new ArrayList<>();

        final var displayName = params.getOrDefault("displayName", "");
        if (displayName.isBlank()) {
            errors.add(new InvalidProperty("displayName", "Display name is required."));
        }

        final var algorithm = params.getOrDefault("algorithm", "RS256");
        if (!ALLOWED_ALGORITHMS.contains(algorithm)) {
            errors.add(new InvalidProperty("algorithm",
                    "Signing algorithm must be one of: " + String.join(", ", ALLOWED_ALGORITHMS)));
        }

        final var maxTtl = oidcSettingsManager.load().maxTokenLifetimeMinutes();
        final var ttlRaw = params.getOrDefault("ttl_minutes", "10");
        try {
            final var ttl = Integer.parseInt(ttlRaw);
            if (ttl < OidcSettings.MIN_TOKEN_LIFETIME_MINUTES || ttl > maxTtl) {
                errors.add(new InvalidProperty("ttl_minutes",
                        "Token lifetime must be between " + OidcSettings.MIN_TOKEN_LIFETIME_MINUTES
                                + " and " + maxTtl + " minutes."));
            }
        } catch (final NumberFormatException e) {
            errors.add(new InvalidProperty("ttl_minutes", "Token lifetime must be a valid integer."));
        }

        final var subjectDimensions = params.getOrDefault("subject_dimensions", "");
        if (!subjectDimensions.isBlank()) {
            final var unknown = Arrays.stream(subjectDimensions.split("\\s*,\\s*"))
                    .filter(s -> !s.isBlank())
                    .filter(s -> !JwtBuildFeature.ALL_OPTIONAL_SUBJECT_DIMENSIONS.contains(s))
                    .collect(Collectors.toCollection(java.util.LinkedHashSet::new));
            if (!unknown.isEmpty()) {
                errors.add(new InvalidProperty("subject_dimensions",
                        "Unknown subject dimension(s): " + String.join(", ", unknown)
                                + ". Allowed: " + String.join(", ", JwtBuildFeature.ALL_OPTIONAL_SUBJECT_DIMENSIONS)));
            }
        }

        return errors;
    }

    @Override
    public boolean isAvailable() {
        return true;
    }
}
