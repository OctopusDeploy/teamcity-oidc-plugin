package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.serverSide.ServerPaths;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class KeyRotationSchedulerTest {

    @Mock SBuildServer buildServer;
    @Mock ServerPaths serverPaths;

    @TempDir File tempDir;

    private JwtKeyManager keyManager() {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        return TestJwtKeyManagerFactory.create(serverPaths);
    }

    private RotationSettingsManager settingsManager() {
        return new RotationSettingsManager(new File(tempDir, "JwtBuildFeature"));
    }

    @Test
    void registersAsBuildServerListener() {
        new KeyRotationScheduler(buildServer, keyManager(), settingsManager());
        verify(buildServer).addListener(any(KeyRotationScheduler.class));
    }

    @Test
    void doesNotRotateWhenDisabled() throws Exception {
        final var km = keyManager();
        final var mgr = settingsManager();
        mgr.save(new RotationSettings(false, RotationSettings.DEFAULT_SCHEDULE, null));
        final var originalKid = km.getRsaKey().getKeyID();

        new KeyRotationScheduler(buildServer, km, mgr).checkAndRotateIfDue();

        assertThat(km.getRsaKey().getKeyID()).isEqualTo(originalKid);
    }

    @Test
    void rotatesWhenEnabledAndOverdue() throws Exception {
        final var km = keyManager();
        final var mgr = settingsManager();
        mgr.save(new RotationSettings(true, RotationSettings.DEFAULT_SCHEDULE,
                Instant.parse("2000-01-01T00:00:00Z")));
        final var originalKid = km.getRsaKey().getKeyID();

        new KeyRotationScheduler(buildServer, km, mgr).checkAndRotateIfDue();

        assertThat(km.getRsaKey().getKeyID()).isNotEqualTo(originalKid);
    }

    @Test
    void doesNotRotateWhenEnabledButNotYetDue() throws Exception {
        final var km = keyManager();
        final var mgr = settingsManager();
        // lastRotatedAt is now → next fire is months away
        mgr.save(new RotationSettings(true, RotationSettings.DEFAULT_SCHEDULE, Instant.now()));
        final var originalKid = km.getRsaKey().getKeyID();

        new KeyRotationScheduler(buildServer, km, mgr).checkAndRotateIfDue();

        assertThat(km.getRsaKey().getKeyID()).isEqualTo(originalKid);
    }

    @Test
    void updatesLastRotatedAtAfterRotation() throws Exception {
        final var km = keyManager();
        final var mgr = settingsManager();
        mgr.save(new RotationSettings(true, RotationSettings.DEFAULT_SCHEDULE,
                Instant.parse("2000-01-01T00:00:00Z")));

        final var before = Instant.now();
        new KeyRotationScheduler(buildServer, km, mgr).checkAndRotateIfDue();
        final var after = Instant.now();

        final var recorded = mgr.load().lastRotatedAt();
        assertThat(recorded).isNotNull();
        assertThat(recorded).isAfterOrEqualTo(before).isBeforeOrEqualTo(after);
    }

    @Test
    void shuttingDownStopsExecutor() {
        final var scheduler = new KeyRotationScheduler(buildServer, keyManager(), settingsManager());
        scheduler.serverStartup();
        scheduler.serverShutdown(); // must not throw or hang
    }
}
