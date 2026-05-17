package com.octopus.teamcity.oidc;

import com.nimbusds.jose.jwk.JWKSet;
import jetbrains.buildServer.controllers.admin.AdminPage;
import jetbrains.buildServer.serverSide.auth.Permission;
import jetbrains.buildServer.web.openapi.PagePlaces;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.PositionConstraint;
import org.jetbrains.annotations.NotNull;
import org.springframework.scheduling.support.CronExpression;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Map;

public class JwtBuildFeatureAdminPage extends AdminPage {
    private static final String PAGE = "jwtBuildFeatureSettings.jsp";
    private static final String TAB_TITLE = "OIDC / JWT";
    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneOffset.UTC);

    @NotNull private final JwtKeyManager keyManager;
    @NotNull private final RotationSettingsManager settingsManager;
    @NotNull private final OidcIssuerUrlProvider issuerUrlProvider;
    @NotNull private final OidcSettingsManager oidcSettingsManager;

    public JwtBuildFeatureAdminPage(@NotNull final PagePlaces pagePlaces,
                                    @NotNull final PluginDescriptor descriptor,
                                    @NotNull final JwtKeyManager keyManager,
                                    @NotNull final RotationSettingsManager settingsManager,
                                    @NotNull final OidcIssuerUrlProvider issuerUrlProvider,
                                    @NotNull final OidcSettingsManager oidcSettingsManager) {
        super(pagePlaces);
        this.keyManager = keyManager;
        this.settingsManager = settingsManager;
        this.issuerUrlProvider = issuerUrlProvider;
        this.oidcSettingsManager = oidcSettingsManager;
        setPluginName("jwtPlugin");
        setIncludeUrl(descriptor.getPluginResourcesPath(PAGE));
        setTabTitle(TAB_TITLE);
        setPosition(PositionConstraint.after("clouds", "email", "jabber"));
        register();
    }

    @Override
    public void fillModel(@NotNull final Map<String, Object> model, @NotNull final HttpServletRequest request) {
        super.fillModel(model, request);
        populateModel(model, keyManager, settingsManager, issuerUrlProvider, oidcSettingsManager);
    }

    static void populateModel(@NotNull final Map<String, Object> model,
                              @NotNull final JwtKeyManager keyManager,
                              @NotNull final RotationSettingsManager settingsManager,
                              @NotNull final OidcIssuerUrlProvider issuerUrlProvider,
                              @NotNull final OidcSettingsManager oidcSettingsManager) {
        if (keyManager.isReady()) {
            final var jwks = new JWKSet(keyManager.getPublicKeys());
            final var jwksJson = jwks.toString();
            model.put("jwks", jwksJson);
            model.put("jwksBase64", Base64.getEncoder().encodeToString(jwksJson.getBytes(StandardCharsets.UTF_8)));
        } else {
            model.put("jwks", "(server startup in progress — keys not yet available)");
            model.put("jwksBase64", "");
        }

        final var settings = settingsManager.load();
        model.put("rotationEnabled", settings.enabled());
        model.put("cronSchedule", settings.cronSchedule());

        if (settings.lastRotatedAt() != null) {
            model.put("lastRotatedAt", FMT.format(settings.lastRotatedAt()) + " UTC");
        } else {
            model.put("lastRotatedAt", "Never");
        }

        if (settings.enabled()) {
            try {
                final var cron = CronExpression.parse(settings.cronSchedule());
                final var lastInstant = settings.lastRotatedAt() != null
                        ? settings.lastRotatedAt()
                        : java.time.Instant.now();
                final var last = lastInstant.atZone(ZoneOffset.UTC).toLocalDateTime();
                final var next = cron.next(last);
                model.put("nextDue", next != null
                        ? FMT.format(next.atZone(ZoneOffset.UTC).toInstant()) + " UTC"
                        : null);
            } catch (final IllegalArgumentException e) {
                model.put("nextDue", null);
            }
        } else {
            model.put("nextDue", null);
        }

        model.put("overrideIssuerUrl", issuerUrlProvider.getOverrideUrl().orElse(""));
        model.put("effectiveIssuerUrl", issuerUrlProvider.getIssuerUrl());
        final var oidcSettings = oidcSettingsManager.load();
        model.put("maxTokenLifetimeMinutes", oidcSettings.maxTokenLifetimeMinutes());
        model.put("maxTokenLifetimeAbsoluteMax", OidcSettings.ABSOLUTE_MAX_TOKEN_LIFETIME_MINUTES);
        model.put("jwksCacheLifetimeMinutes", oidcSettings.jwksCacheLifetimeMinutes());
        model.put("jwksCacheLifetimeMin", OidcSettings.MIN_JWKS_CACHE_LIFETIME_MINUTES);
        model.put("jwksCacheLifetimeMax", OidcSettings.MAX_JWKS_CACHE_LIFETIME_MINUTES);
        model.put("jwksCacheLifetimeDefault", OidcSettings.DEFAULT_JWKS_CACHE_LIFETIME_MINUTES);
    }

    @Override
    public boolean isAvailable(@NotNull final HttpServletRequest request) {
        return super.isAvailable(request) && checkHasGlobalPermission(request, Permission.CHANGE_SERVER_SETTINGS);
    }

    @NotNull
    @Override
    public String getGroup() {
        return INTEGRATIONS_GROUP;
    }
}
