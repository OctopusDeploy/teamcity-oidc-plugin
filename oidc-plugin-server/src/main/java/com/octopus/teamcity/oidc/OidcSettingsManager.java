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
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public class OidcSettingsManager {
    private static final Logger LOG = Logger.getLogger(OidcSettingsManager.class.getName());
    private static final String FILE_NAME = "oidc-settings.json";

    private final File settingsFile;

    public OidcSettingsManager(@NotNull final File keyDirectory) {
        this.settingsFile = new File(keyDirectory, FILE_NAME);
    }

    public synchronized @NotNull Optional<String> load() {
        if (!settingsFile.exists()) {
            return Optional.empty();
        }
        try {
            final var json = FileUtils.readFileToString(settingsFile, StandardCharsets.UTF_8);
            final var obj = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(json);
            if (!obj.containsKey("overrideIssuerUrl") || obj.get("overrideIssuerUrl") == null) {
                return Optional.empty();
            }
            final var value = (String) obj.get("overrideIssuerUrl");
            if (value.isBlank()) {
                return Optional.empty();
            }
            return Optional.of(value);
        } catch (final Exception e) {
            LOG.log(Level.SEVERE, "JWT plugin: failed to load OIDC settings from "
                    + settingsFile.getAbsolutePath()
                    + " — file may be corrupt. Ignoring override issuer URL.", e);
            return Optional.empty();
        }
    }

    public synchronized void save(@Nullable final String overrideIssuerUrl) {
        final var obj = new JSONObject();
        if (overrideIssuerUrl != null && !overrideIssuerUrl.isBlank()) {
            obj.put("overrideIssuerUrl", overrideIssuerUrl);
        }
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
}
