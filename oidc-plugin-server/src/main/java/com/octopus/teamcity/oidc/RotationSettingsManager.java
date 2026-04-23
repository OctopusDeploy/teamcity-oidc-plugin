package com.octopus.teamcity.oidc;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.apache.commons.io.FileUtils;
import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Loads and saves {@link RotationSettings} to {@code rotation-settings.json}
 * in the given directory. Thread-safe: load and save are both synchronized.
 */
public class RotationSettingsManager {
    private static final Logger LOG = Logger.getLogger(RotationSettingsManager.class.getName());
    private static final String FILE_NAME = "rotation-settings.json";

    private final File settingsFile;

    public RotationSettingsManager(@NotNull final File keyDirectory) {
        this.settingsFile = new File(keyDirectory, FILE_NAME);
    }

    public synchronized @NotNull RotationSettings load() {
        if (!settingsFile.exists()) {
            return RotationSettings.defaults();
        }
        try {
            final var json = FileUtils.readFileToString(settingsFile, StandardCharsets.UTF_8);
            final var obj = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(json);
            final var defaults = RotationSettings.defaults();
            final var enabledValue = obj.get("enabled");
            final var enabled = enabledValue instanceof Boolean ? (Boolean) enabledValue : defaults.enabled();
            final var schedule = obj.containsKey("cronSchedule")
                    ? (String) obj.get("cronSchedule")
                    : defaults.cronSchedule();
            final var lastRotatedAt = obj.containsKey("lastRotatedAt") && obj.get("lastRotatedAt") != null
                    ? Instant.parse((String) obj.get("lastRotatedAt"))
                    : null;
            return new RotationSettings(enabled, schedule, lastRotatedAt);
        } catch (final Exception e) {
            LOG.log(Level.WARNING, "JWT plugin: failed to load rotation settings, using defaults", e);
            return RotationSettings.defaults();
        }
    }

    public synchronized void updateLastRotatedAt(@NotNull final Instant lastRotatedAt) {
        final var current = load();
        save(new RotationSettings(current.enabled(), current.cronSchedule(), lastRotatedAt));
    }

    /**
     * Atomically updates the enabled flag and cron schedule while preserving the current
     * {@code lastRotatedAt} value. Using this method avoids the load→save race where a
     * concurrent {@link #updateLastRotatedAt} call between a separate load and save would
     * have its timestamp silently overwritten.
     */
    public synchronized void save(final boolean enabled,
                                  @NotNull final String cronSchedule) {
        final var current = load();
        save(new RotationSettings(enabled, cronSchedule, current.lastRotatedAt()));
    }

    public synchronized void save(@NotNull final RotationSettings settings) {
        final var obj = new JSONObject();
        obj.put("enabled", settings.enabled());
        obj.put("cronSchedule", settings.cronSchedule());
        obj.put("lastRotatedAt", settings.lastRotatedAt() != null ? settings.lastRotatedAt().toString() : null);
        try {
            FileUtils.writeStringToFile(settingsFile, obj.toJSONString(), StandardCharsets.UTF_8);
            if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                Files.setPosixFilePermissions(settingsFile.toPath(), Set.of(
                        PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
            }
        } catch (final IOException e) {
            LOG.log(Level.SEVERE, "JWT plugin: failed to save rotation settings", e);
        }
    }
}
