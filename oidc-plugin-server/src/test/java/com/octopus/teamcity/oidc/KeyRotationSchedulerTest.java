package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.serverSide.ServerPaths;
import jetbrains.buildServer.serverSide.TeamCityNode;
import jetbrains.buildServer.serverSide.TeamCityNodes;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class KeyRotationSchedulerTest {

    @Mock SBuildServer buildServer;
    @Mock ServerPaths serverPaths;
    @Mock TeamCityNodes nodes;
    @Mock TeamCityNode currentNode;

    @TempDir File tempDir;

    @BeforeEach
    void stubMainNode() {
        lenient().when(nodes.getCurrentNode()).thenReturn(currentNode);
        lenient().when(currentNode.isMainNode()).thenReturn(true);
    }

    private JwtKeyManager keyManager() {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        return TestJwtKeyManagerFactory.create(serverPaths);
    }

    private RotationSettingsManager settingsManager() {
        return new RotationSettingsManager(new File(tempDir, "JwtBuildFeature"));
    }

    @Test
    void registersAsBuildServerListener() {
        new KeyRotationScheduler(buildServer, keyManager(), settingsManager(), nodes);
        verify(buildServer).addListener(any(KeyRotationScheduler.class));
    }

    @Test
    void doesNotRotateWhenDisabled() throws Exception {
        final var km = keyManager();
        final var mgr = settingsManager();
        mgr.save(new RotationSettings(false, RotationSettings.DEFAULT_SCHEDULE, null));
        final var originalKid = km.getRsaKey().getKeyID();

        new KeyRotationScheduler(buildServer, km, mgr, nodes).checkAndRotateIfDue();

        assertThat(km.getRsaKey().getKeyID()).isEqualTo(originalKid);
    }

    @Test
    void rotatesWhenEnabledAndOverdue() throws Exception {
        final var km = keyManager();
        final var mgr = settingsManager();
        mgr.save(new RotationSettings(true, RotationSettings.DEFAULT_SCHEDULE,
                Instant.parse("2000-01-01T00:00:00Z")));
        final var originalKid = km.getRsaKey().getKeyID();

        new KeyRotationScheduler(buildServer, km, mgr, nodes).checkAndRotateIfDue();

        // Rotation now creates a pending key; force activation to verify the rotation occurred.
        km.__testOverridePendingActivateAt(Instant.EPOCH);
        km.sign(new com.nimbusds.jwt.JWTClaimsSet.Builder().subject("x").build(), "RS256");
        assertThat(km.getRsaKey().getKeyID()).isNotEqualTo(originalKid);
    }

    @Test
    void doesNotRotateWhenEnabledButNotYetDue() throws Exception {
        final var km = keyManager();
        final var mgr = settingsManager();
        // lastRotatedAt is now → next fire is months away
        mgr.save(new RotationSettings(true, RotationSettings.DEFAULT_SCHEDULE, Instant.now()));
        final var originalKid = km.getRsaKey().getKeyID();

        new KeyRotationScheduler(buildServer, km, mgr, nodes).checkAndRotateIfDue();

        assertThat(km.getRsaKey().getKeyID()).isEqualTo(originalKid);
    }

    @Test
    void updatesLastRotatedAtAfterRotation() throws Exception {
        final var km = keyManager();
        final var mgr = settingsManager();
        mgr.save(new RotationSettings(true, RotationSettings.DEFAULT_SCHEDULE,
                Instant.parse("2000-01-01T00:00:00Z")));

        final var before = Instant.now();
        new KeyRotationScheduler(buildServer, km, mgr, nodes).checkAndRotateIfDue();
        final var after = Instant.now();

        final var recorded = mgr.load().lastRotatedAt();
        assertThat(recorded).isNotNull();
        assertThat(recorded).isAfterOrEqualTo(before).isBeforeOrEqualTo(after);
    }

    @Test
    void doesNotRotateImmediatelyOnFreshInstall() throws Exception {
        // On first install no settings file exists, so load() returns defaults().
        // defaults() must not cause an immediate rotation — lastRotatedAt should
        // not be treated as epoch 0 (which would make every cron fire appear overdue).
        final var km = keyManager();
        final var mgr = settingsManager(); // no file → load() returns defaults()
        final var originalKid = km.getRsaKey().getKeyID();

        new KeyRotationScheduler(buildServer, km, mgr, nodes).checkAndRotateIfDue();

        assertThat(km.getRsaKey().getKeyID()).isEqualTo(originalKid);
    }

    @Test
    void schedulerStartsImmediatelyWhenServerAlreadyRunning() throws Exception {
        // When the plugin is hot-deployed into a running TC server, serverStartup() is never
        // called by TC (that event already fired). The scheduler must start itself in the
        // constructor when isStarted() is true, so auto-rotation still works.
        when(buildServer.isStarted()).thenReturn(true);
        final var km = keyManager();
        final var mgr = settingsManager();
        mgr.save(new RotationSettings(true, RotationSettings.DEFAULT_SCHEDULE,
                Instant.parse("2000-01-01T00:00:00Z")));
        final var originalKid = km.getRsaKey().getKeyID();

        new KeyRotationScheduler(buildServer, km, mgr, nodes); // no serverStartup() call

        Thread.sleep(3000);
        // Rotation now creates a pending key; force activation to verify the rotation occurred.
        km.__testOverridePendingActivateAt(Instant.EPOCH);
        km.sign(new com.nimbusds.jwt.JWTClaimsSet.Builder().subject("x").build(), "RS256");
        assertThat(km.getRsaKey().getKeyID()).isNotEqualTo(originalKid);
    }

    @Test
    void doesNotRotateOnSecondaryNodeEvenWhenOverdue() throws Exception {
        // In TC HA, every node runs the scheduler, but only the main node should rotate.
        // Otherwise multiple nodes race on disk writes and end up with divergent in-memory keys.
        when(currentNode.isMainNode()).thenReturn(false);
        final var km = keyManager();
        final var mgr = settingsManager();
        mgr.save(new RotationSettings(true, RotationSettings.DEFAULT_SCHEDULE,
                Instant.parse("2000-01-01T00:00:00Z")));
        final var originalKid = km.getRsaKey().getKeyID();

        new KeyRotationScheduler(buildServer, km, mgr, nodes).checkAndRotateIfDue();

        assertThat(km.getRsaKey().getKeyID()).isEqualTo(originalKid);
        assertThat(mgr.load().lastRotatedAt()).isEqualTo(Instant.parse("2000-01-01T00:00:00Z"));
    }

    @Test
    void cronTickDuringWarmupLogsInfoAndContinues() throws Exception {
        // Arrange: cron is due, rotation throws PendingRotationInProgressException.
        final var mockKeyManager = mock(JwtKeyManager.class);
        final var mockSettingsManager = mock(RotationSettingsManager.class);
        when(mockSettingsManager.load()).thenReturn(new RotationSettings(true,
                RotationSettings.DEFAULT_SCHEDULE, Instant.parse("2000-01-01T00:00:00Z")));
        doThrow(new PendingRotationInProgressException(Instant.now().plus(Duration.ofMinutes(5))))
                .when(mockKeyManager).rotateKey();

        // Act
        new KeyRotationScheduler(buildServer, mockKeyManager, mockSettingsManager, nodes)
                .checkAndRotateIfDue();

        // Assert: lastRotatedAt was NOT updated (rotation didn't happen).
        verify(mockSettingsManager, never()).updateLastRotatedAt(any());
    }

    @Test
    void shuttingDownStopsExecutor() {
        final var scheduler = new KeyRotationScheduler(buildServer, keyManager(), settingsManager(), nodes);
        scheduler.serverStartup();
        scheduler.serverShutdown(); // must not throw or hang
    }
}
