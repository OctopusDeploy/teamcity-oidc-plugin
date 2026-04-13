package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.BuildServerAdapter;
import jetbrains.buildServer.serverSide.SBuildServer;
import org.jetbrains.annotations.NotNull;
import org.springframework.scheduling.support.CronExpression;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KeyRotationScheduler extends BuildServerAdapter {
    private static final Logger LOG = Logger.getLogger(KeyRotationScheduler.class.getName());

    private final JwtKeyManager keyManager;
    private final RotationSettingsManager settingsManager;
    private final ScheduledExecutorService executor;

    public KeyRotationScheduler(@NotNull SBuildServer buildServer,
                                @NotNull JwtKeyManager keyManager,
                                @NotNull RotationSettingsManager settingsManager) {
        this.keyManager = keyManager;
        this.settingsManager = settingsManager;
        this.executor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "jwt-key-rotation-scheduler");
            t.setDaemon(true);
            return t;
        });
        buildServer.addListener(this);
    }

    @Override
    public void serverStartup() {
        LOG.info("JWT plugin: key rotation scheduler starting (hourly check)");
        executor.scheduleAtFixedRate(() -> {
            try {
                checkAndRotateIfDue();
            } catch (Exception e) {
                LOG.log(Level.SEVERE, "JWT plugin: unexpected error during rotation check", e);
            }
        }, 0, 1, TimeUnit.HOURS);
    }

    @Override
    public void serverShutdown() {
        LOG.info("JWT plugin: key rotation scheduler stopping");
        executor.shutdownNow();
    }

    /** Package-private for testing. */
    void checkAndRotateIfDue() {
        RotationSettings settings = settingsManager.load();
        if (!settings.enabled()) {
            return;
        }

        CronExpression cron;
        try {
            cron = CronExpression.parse(settings.cronSchedule());
        } catch (IllegalArgumentException e) {
            LOG.warning("JWT plugin: invalid cron schedule \"" + settings.cronSchedule() + "\": " + e.getMessage());
            return;
        }

        LocalDateTime lastRotated = settings.lastRotatedAt() != null
                ? settings.lastRotatedAt().atZone(ZoneOffset.UTC).toLocalDateTime()
                : LocalDateTime.ofEpochSecond(0, 0, ZoneOffset.UTC);

        LocalDateTime nextDue = cron.next(lastRotated);
        if (nextDue == null) {
            return;
        }

        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        if (now.isBefore(nextDue)) {
            return;
        }

        LOG.info("JWT plugin: auto-rotating keys (next was due " + nextDue + " UTC)");
        try {
            keyManager.rotateKey();
            settingsManager.save(new RotationSettings(
                    settings.enabled(),
                    settings.cronSchedule(),
                    Instant.now()
            ));
            LOG.info("JWT plugin: auto key rotation completed successfully");
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "JWT plugin: auto key rotation failed", e);
        }
    }
}
