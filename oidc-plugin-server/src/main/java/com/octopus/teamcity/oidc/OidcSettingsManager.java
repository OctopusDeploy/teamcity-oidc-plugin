package com.octopus.teamcity.oidc;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.apache.commons.io.FileUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Loads and saves {@link OidcSettings} to {@code oidc-settings.json} in the given
 * directory. Thread-safe: load and save are both synchronized.
 */
public class OidcSettingsManager {
    private static final Logger LOG = Logger.getLogger(OidcSettingsManager.class.getName());
    private static final String FILE_NAME = "oidc-settings.json";

    private final File settingsFile;

    public OidcSettingsManager(@NotNull final File keyDirectory) {
        this.settingsFile = new File(keyDirectory, FILE_NAME);
    }

    public synchronized @NotNull OidcSettings load() {
        if (!settingsFile.exists()) {
            return OidcSettings.defaults();
        }
        try {
            final var json = FileUtils.readFileToString(settingsFile, StandardCharsets.UTF_8);
            final var obj = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(json);
            final var defaults = OidcSettings.defaults();

            final var rawOverride = obj.get("overrideIssuerUrl");
            final var override = rawOverride instanceof final String s && !s.isBlank() ? s : null;

            var maxTtl = defaults.maxTokenLifetimeMinutes();
            final var rawMax = obj.get("maxTokenLifetimeMinutes");
            if (rawMax instanceof final Number n) {
                maxTtl = clampMaxTtl(n.intValue());
            } else if (rawMax instanceof final String s) {
                try {
                    maxTtl = clampMaxTtl(Integer.parseInt(s));
                } catch (final NumberFormatException ignored) {
                    LOG.warning("JWT plugin: invalid maxTokenLifetimeMinutes '" + s
                            + "' in oidc-settings.json — falling back to default ("
                            + defaults.maxTokenLifetimeMinutes() + ").");
                }
            }

            return new OidcSettings(override, maxTtl, defaults.jwksCacheLifetimeMinutes());
        } catch (final Exception e) {
            LOG.log(Level.SEVERE, "JWT plugin: failed to load OIDC settings from "
                    + settingsFile.getAbsolutePath()
                    + " — file may be corrupt. Using safe defaults.", e);
            return OidcSettings.defaults();
        }
    }

    /**
     * Atomically updates the override issuer URL while preserving all other fields.
     * Prefer this over {@link #save(OidcSettings)} from external callers — using a
     * separate load+save sequence races with concurrent updates to other fields.
     */
    public synchronized void saveOverrideIssuerUrl(@Nullable final String url) {
        save(load().withOverrideIssuerUrl(url));
    }

    /**
     * Atomically updates the max token lifetime while preserving all other fields.
     * See {@link #saveOverrideIssuerUrl} for why this is preferable to load+save.
     */
    public synchronized void saveMaxTokenLifetimeMinutes(final int minutes) {
        save(load().withMaxTokenLifetimeMinutes(minutes));
    }

    synchronized void save(@NotNull final OidcSettings settings) {
        final var obj = new JSONObject();
        if (settings.overrideIssuerUrl() != null && !settings.overrideIssuerUrl().isBlank()) {
            obj.put("overrideIssuerUrl", settings.overrideIssuerUrl());
        }
        obj.put("maxTokenLifetimeMinutes", settings.maxTokenLifetimeMinutes());
        try {
            FileUtils.writeStringToFile(settingsFile, obj.toJSONString(), StandardCharsets.UTF_8);
            if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                Files.setPosixFilePermissions(settingsFile.toPath(), Set.of(
                        PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
            }
        } catch (final IOException e) {
            LOG.log(Level.SEVERE, "JWT plugin: failed to save OIDC settings", e);
        }
    }

    private static int clampMaxTtl(final int value) {
        return Math.clamp(value,
                OidcSettings.MIN_TOKEN_LIFETIME_MINUTES,
                OidcSettings.ABSOLUTE_MAX_TOKEN_LIFETIME_MINUTES);
    }
}
