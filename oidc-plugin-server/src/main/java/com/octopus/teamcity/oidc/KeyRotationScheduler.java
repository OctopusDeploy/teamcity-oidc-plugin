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

    public KeyRotationScheduler(@NotNull final SBuildServer buildServer,
                                @NotNull final JwtKeyManager keyManager,
                                @NotNull final RotationSettingsManager settingsManager) {
        this.keyManager = keyManager;
        this.settingsManager = settingsManager;
        this.executor = Executors.newSingleThreadScheduledExecutor(r -> {
            final var t = new Thread(r, "jwt-key-rotation-scheduler");
            t.setDaemon(true);
            return t;
        });
        buildServer.addListener(this);
        if (buildServer.isStarted()) {
            // Plugin hot-deployed into a running server — serverStartup() will never fire,
            // so start the scheduler now. No initial delay needed; TC is already fully up.
            startScheduler(0);
        }
    }

    @Override
    public void serverStartup() {
        // Delay by 1 minute to let TC finish initialising before the first rotation check.
        startScheduler(1);
    }

    private void startScheduler(final long initialDelayMinutes) {
        LOG.info("JWT plugin: key rotation scheduler starting (hourly check)");
        executor.scheduleAtFixedRate(() -> {
            try {
                checkAndRotateIfDue();
            } catch (final Exception e) {
                LOG.log(Level.SEVERE, "JWT plugin: unexpected error during rotation check", e);
            }
        }, initialDelayMinutes, 60, TimeUnit.MINUTES);
    }

    @Override
    public void serverShutdown() {
        LOG.info("JWT plugin: key rotation scheduler stopping");
        executor.shutdownNow();
    }

    /** Package-private for testing. */
    void checkAndRotateIfDue() {
        final var settings = settingsManager.load();
        if (!settings.enabled()) {
            return;
        }

        final CronExpression cron;
        try {
            cron = CronExpression.parse(settings.cronSchedule());
        } catch (final IllegalArgumentException e) {
            LOG.warning("JWT plugin: invalid cron schedule \"" + settings.cronSchedule() + "\": " + e.getMessage());
            return;
        }

        final var lastRotated = settings.lastRotatedAt() != null
                ? settings.lastRotatedAt().atZone(ZoneOffset.UTC).toLocalDateTime()
                : LocalDateTime.ofEpochSecond(0, 0, ZoneOffset.UTC);

        final var nextDue = cron.next(lastRotated);
        if (nextDue == null) {
            return;
        }

        final var now = LocalDateTime.now(ZoneOffset.UTC);
        if (now.isBefore(nextDue)) {
            return;
        }

        LOG.info("JWT plugin: auto-rotating keys (next was due " + nextDue + " UTC)");
        try {
            keyManager.rotateKey();
            settingsManager.updateLastRotatedAt(Instant.now());
            LOG.info("JWT plugin: auto key rotation completed successfully");
        } catch (final Exception e) {
            LOG.log(Level.SEVERE, "JWT plugin: auto key rotation failed", e);
        }
    }
}
