package com.octopus.teamcity.oidc;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.apache.commons.io.FileUtils;
import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
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

    public RotationSettingsManager(@NotNull File keyDirectory) {
        this.settingsFile = new File(keyDirectory, FILE_NAME);
    }

    public synchronized @NotNull RotationSettings load() {
        if (!settingsFile.exists()) {
            return RotationSettings.defaults();
        }
        try {
            String json = FileUtils.readFileToString(settingsFile, StandardCharsets.UTF_8);
            JSONObject obj = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(json);
            boolean enabled = Boolean.TRUE.equals(obj.get("enabled"));
            String schedule = obj.containsKey("cronSchedule")
                    ? (String) obj.get("cronSchedule")
                    : RotationSettings.DEFAULT_SCHEDULE;
            Instant lastRotatedAt = obj.containsKey("lastRotatedAt") && obj.get("lastRotatedAt") != null
                    ? Instant.parse((String) obj.get("lastRotatedAt"))
                    : null;
            return new RotationSettings(enabled, schedule, lastRotatedAt);
        } catch (Exception e) {
            LOG.log(Level.WARNING, "JWT plugin: failed to load rotation settings, using defaults", e);
            return RotationSettings.defaults();
        }
    }

    public synchronized void save(@NotNull RotationSettings settings) {
        JSONObject obj = new JSONObject();
        obj.put("enabled", settings.enabled());
        obj.put("cronSchedule", settings.cronSchedule());
        obj.put("lastRotatedAt", settings.lastRotatedAt() != null ? settings.lastRotatedAt().toString() : null);
        try {
            FileUtils.writeStringToFile(settingsFile, obj.toJSONString(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            LOG.log(Level.SEVERE, "JWT plugin: failed to save rotation settings", e);
        }
    }
}
