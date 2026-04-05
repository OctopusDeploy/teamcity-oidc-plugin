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
        return new JwtKeyManager(serverPaths);
    }

    @Test
    void registersAsBuildServerListener() {
        JwtKeyManager km = keyManager();
        RotationSettingsManager mgr = new RotationSettingsManager(new File(tempDir, "JwtBuildFeature"));
        new KeyRotationScheduler(buildServer, km, mgr);
        verify(buildServer).addListener(any(KeyRotationScheduler.class));
    }

    @Test
    void doesNotRotateWhenDisabled() throws Exception {
        JwtKeyManager km = keyManager();
        File keyDir = new File(tempDir, "JwtBuildFeature");
        RotationSettingsManager mgr = new RotationSettingsManager(keyDir);
        // disabled by default
        String originalKid = km.getRsaKey().getKeyID();

        KeyRotationScheduler scheduler = new KeyRotationScheduler(buildServer, km, mgr);
        scheduler.checkAndRotateIfDue();

        assertThat(km.getRsaKey().getKeyID()).isEqualTo(originalKid);
    }

    @Test
    void rotatesWhenEnabledAndOverdue() throws Exception {
        JwtKeyManager km = keyManager();
        File keyDir = new File(tempDir, "JwtBuildFeature");
        RotationSettingsManager mgr = new RotationSettingsManager(keyDir);
        // lastRotatedAt in the distant past → overdue
        mgr.save(new RotationSettings(true, RotationSettings.DEFAULT_SCHEDULE,
                Instant.parse("2000-01-01T00:00:00Z")));
        String originalKid = km.getRsaKey().getKeyID();

        KeyRotationScheduler scheduler = new KeyRotationScheduler(buildServer, km, mgr);
        scheduler.checkAndRotateIfDue();

        assertThat(km.getRsaKey().getKeyID()).isNotEqualTo(originalKid);
    }

    @Test
    void doesNotRotateWhenEnabledButNotYetDue() throws Exception {
        JwtKeyManager km = keyManager();
        File keyDir = new File(tempDir, "JwtBuildFeature");
        RotationSettingsManager mgr = new RotationSettingsManager(keyDir);
        // lastRotatedAt is now → next fire is months away
        mgr.save(new RotationSettings(true, RotationSettings.DEFAULT_SCHEDULE, Instant.now()));
        String originalKid = km.getRsaKey().getKeyID();

        KeyRotationScheduler scheduler = new KeyRotationScheduler(buildServer, km, mgr);
        scheduler.checkAndRotateIfDue();

        assertThat(km.getRsaKey().getKeyID()).isEqualTo(originalKid);
    }

    @Test
    void updatesLastRotatedAtAfterRotation() throws Exception {
        JwtKeyManager km = keyManager();
        File keyDir = new File(tempDir, "JwtBuildFeature");
        RotationSettingsManager mgr = new RotationSettingsManager(keyDir);
        mgr.save(new RotationSettings(true, RotationSettings.DEFAULT_SCHEDULE,
                Instant.parse("2000-01-01T00:00:00Z")));

        KeyRotationScheduler scheduler = new KeyRotationScheduler(buildServer, km, mgr);
        Instant before = Instant.now();
        scheduler.checkAndRotateIfDue();
        Instant after = Instant.now();

        Instant recorded = mgr.load().lastRotatedAt();
        assertThat(recorded).isNotNull();
        assertThat(recorded).isAfterOrEqualTo(before);
        assertThat(recorded).isBeforeOrEqualTo(after);
    }

    @Test
    void shuttingDownStopsExecutor() {
        JwtKeyManager km = keyManager();
        RotationSettingsManager mgr = new RotationSettingsManager(new File(tempDir, "JwtBuildFeature"));
        KeyRotationScheduler scheduler = new KeyRotationScheduler(buildServer, km, mgr);
        scheduler.serverStartup();
        scheduler.serverShutdown(); // must not throw or hang
    }
}
