package com.octopus.teamcity.oidc;

import com.nimbusds.jose.JOSEException;
import jetbrains.buildServer.serverSide.ServerPaths;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class JwtKeyManagerTest {

    @Mock
    private ServerPaths serverPaths;

    @TempDir
    private File tempDir;

    @Test
    public void keyFileIsReadableAndWritableByOwnerOnly() throws IOException {
        final var pluginDirectory = new File(tempDir, "foobar");
        if (!pluginDirectory.mkdirs()) throw new RuntimeException("Unable to create pluginDirectory '" + pluginDirectory + "'");
        when(serverPaths.getPluginDataDirectory()).thenReturn(pluginDirectory);
        final var keyFile = new File(pluginDirectory, "JwtBuildFeature/rsa-key.json");

        TestJwtKeyManagerFactory.create(serverPaths).getRsaKey();

        final var permissions = Files.getPosixFilePermissions(keyFile.toPath());
        assertThat(permissions).containsExactlyInAnyOrder(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE
        );
    }

    @Test
    public void keyIdIsThumbprintOfPublicKey() throws JOSEException {
        final var pluginDirectory = new File(tempDir, "foobar");
        if (!pluginDirectory.mkdirs()) throw new RuntimeException("Unable to create pluginDirectory '" + pluginDirectory + "'");
        when(serverPaths.getPluginDataDirectory()).thenReturn(pluginDirectory);

        final var keyManager = TestJwtKeyManagerFactory.create(serverPaths);
        final var key = keyManager.getRsaKey();

        assertThat(key.getKeyID()).isEqualTo(key.computeThumbprint().toString());
        assertThat(key.getKeyID()).isNotEqualTo("teamcity");
    }

    @Test
    public void testGetRsaKeyReusesFile() throws IOException {
        final var pluginDirectory = new File(tempDir, "foobar");
        if (!pluginDirectory.mkdirs()) throw new RuntimeException("Unable to create pluginDirectory '" + pluginDirectory + "'");
        when(serverPaths.getPluginDataDirectory()).thenReturn(pluginDirectory);
        final var keyFile = new File(pluginDirectory, "JwtBuildFeature/rsa-key.json");

        TestJwtKeyManagerFactory.create(serverPaths).getRsaKey();
        final var keyFileContents = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);

        TestJwtKeyManagerFactory.create(serverPaths).getRsaKey();
        final var keyFileContents2 = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);
        assertThat(keyFileContents2).isEqualTo(keyFileContents);
    }

    @Test
    public void constructorThrowsRuntimeExceptionWithClearMessageWhenKeyFileIsCorrupt() throws Exception {
        final var pluginDirectory = new File(tempDir, "corrupt");
        if (!pluginDirectory.mkdirs()) throw new RuntimeException("Unable to create pluginDirectory '" + pluginDirectory + "'");
        when(serverPaths.getPluginDataDirectory()).thenReturn(pluginDirectory);

        final var keyDir = new File(pluginDirectory, "JwtBuildFeature");
        if (!keyDir.mkdirs()) throw new RuntimeException("Unable to create keyDir '" + keyDir + "'");
        FileUtils.writeStringToFile(new File(keyDir, "rsa-key.json"), "not-valid-json", StandardCharsets.UTF_8);

        assertThatThrownBy(() -> TestJwtKeyManagerFactory.create(serverPaths).getRsaKey())
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("JwtKeyManager");
    }

    @Test
    public void ecKeyIdIsThumbprintOfPublicKey() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        final var keyManager = TestJwtKeyManagerFactory.create(serverPaths);
        final var ecKey = keyManager.getEcKey();
        assertThat(ecKey.getKeyID()).isEqualTo(ecKey.computeThumbprint().toString());
    }

    @Test
    public void startupDeletesTempFilesLeftByPreviousCrash() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        // Pre-create orphaned temp files that a crashed rotation would leave behind
        final var keyDir = new File(tempDir, "JwtBuildFeature");
        assertThat(keyDir.mkdirs()).isTrue();
        final var leftover1 = new File(keyDir, "key-abc123.tmp");
        final var leftover2 = new File(keyDir, "key-def456.tmp");
        FileUtils.writeStringToFile(leftover1, "orphaned", StandardCharsets.UTF_8);
        FileUtils.writeStringToFile(leftover2, "orphaned", StandardCharsets.UTF_8);

        TestJwtKeyManagerFactory.create(serverPaths); // calls notifyTeamCityServerStartupCompleted()

        assertThat(leftover1).doesNotExist();
        assertThat(leftover2).doesNotExist();
    }

    @Test
    public void signThrowsForUnsupportedAlgorithm() {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        final var keyManager = TestJwtKeyManagerFactory.create(serverPaths);
        final var claims = new com.nimbusds.jwt.JWTClaimsSet.Builder()
                .subject("test").build();

        assertThatThrownBy(() -> keyManager.sign(claims, "HS256"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("HS256");

        assertThatThrownBy(() -> keyManager.sign(claims, "none"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("none");
    }
}
