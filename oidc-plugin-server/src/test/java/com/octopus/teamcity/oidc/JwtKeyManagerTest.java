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
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;

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
    public void throwsWhenRsaKeyFileContainsEcKey() throws Exception {
        final var pluginDirectory = new File(tempDir, "swapped");
        if (!pluginDirectory.mkdirs()) throw new RuntimeException("Unable to create pluginDirectory");
        when(serverPaths.getPluginDataDirectory()).thenReturn(pluginDirectory);

        // Generate a valid key set so both files exist with real encrypted content.
        TestJwtKeyManagerFactory.create(serverPaths);

        // Replace rsa-key.json with the contents of ec-key.json.
        final var keyDir = new File(pluginDirectory, "JwtBuildFeature");
        final var rsaFile = new File(keyDir, "rsa-key.json");
        final var ecFile  = new File(keyDir, "ec-key.json");
        FileUtils.copyFile(ecFile, rsaFile);

        assertThatThrownBy(() -> TestJwtKeyManagerFactory.create(serverPaths).getRsaKey())
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("JwtKeyManager");
    }

    @Test
    public void throwsWhenEcKeyFileContainsRsaKey() throws Exception {
        final var pluginDirectory = new File(tempDir, "swapped2");
        if (!pluginDirectory.mkdirs()) throw new RuntimeException("Unable to create pluginDirectory");
        when(serverPaths.getPluginDataDirectory()).thenReturn(pluginDirectory);

        // Generate a valid key set so both files exist with real encrypted content.
        TestJwtKeyManagerFactory.create(serverPaths);

        // Replace ec-key.json with the contents of rsa-key.json.
        final var keyDir = new File(pluginDirectory, "JwtBuildFeature");
        final var rsaFile = new File(keyDir, "rsa-key.json");
        final var ecFile  = new File(keyDir, "ec-key.json");
        FileUtils.copyFile(rsaFile, ecFile);

        assertThatThrownBy(() -> TestJwtKeyManagerFactory.create(serverPaths).getEcKey())
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
    public void refreshesKeysAfterAnotherWriterRotates() throws Exception {
        // In TC HA, every node loads keys from the shared filesystem at startup but only
        // the main node rotates. Secondaries must notice when the files change underneath
        // them — otherwise they keep signing builds with retired keys whose kid no longer
        // appears as "current" in the JWKS endpoint, and verifiers fetching JWKS from a
        // secondary won't see the previous-current key in the published list.
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        final var nodeA = TestJwtKeyManagerFactory.create(serverPaths);
        final var nodeB = TestJwtKeyManagerFactory.create(serverPaths);
        final var initialKid = nodeA.getRsaKey().getKeyID();

        nodeB.rotateKey();

        // Bump mtimes to a known later instant so the test is robust against filesystem
        // timestamp granularity (rotation finishing within the same millisecond as load).
        final var future = FileTime.from(Instant.now().plusSeconds(2));
        final var keyDir = new File(tempDir, "JwtBuildFeature");
        for (final var f : keyDir.listFiles((d, n) -> n.endsWith(".json"))) {
            Files.setLastModifiedTime(f.toPath(), future);
        }

        assertThat(nodeA.getRsaKey().getKeyID())
                .isNotEqualTo(initialKid)
                .isEqualTo(nodeB.getRsaKey().getKeyID());
        final var publicKids = nodeA.getPublicKeys().stream().map(k -> k.getKeyID()).toList();
        assertThat(publicKids).contains(initialKid);
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
