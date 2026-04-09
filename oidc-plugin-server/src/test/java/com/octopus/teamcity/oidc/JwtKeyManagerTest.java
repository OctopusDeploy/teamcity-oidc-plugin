package com.octopus.teamcity.oidc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import jetbrains.buildServer.serverSide.ServerPaths;
import jetbrains.buildServer.serverSide.crypt.EncryptUtil;
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
import java.text.ParseException;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class JwtKeyManagerTest {

    @Mock
    private ServerPaths serverPaths;

    @TempDir
    private File tempDir;

    @Test
    public void testGetRsaKeyCreatesFile() throws IOException, ParseException, JOSEException {
        File pluginDirectory = new File(tempDir, "foobar");
        pluginDirectory.mkdirs();
        when(serverPaths.getPluginDataDirectory()).thenReturn(pluginDirectory);
        File keyFile = new File(pluginDirectory, "JwtBuildFeature/key.json");

        JwtKeyManager keyManager = new JwtKeyManager(serverPaths);

        assertTrue(keyFile.exists());
        String fileContents = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);
        assertThat(fileContents).startsWith("scrambled:");
        assertThat(EncryptUtil.unscramble(fileContents)).isEqualTo(keyManager.getRsaKey().toString());
    }

    @Test
    public void keyFileIsReadableAndWritableByOwnerOnly() throws IOException {
        File pluginDirectory = new File(tempDir, "foobar");
        pluginDirectory.mkdirs();
        when(serverPaths.getPluginDataDirectory()).thenReturn(pluginDirectory);
        File keyFile = new File(pluginDirectory, "JwtBuildFeature/key.json");

        new JwtKeyManager(serverPaths);

        Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(keyFile.toPath());
        assertThat(permissions).containsExactlyInAnyOrder(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE
        );
    }

    @Test
    public void keyIdIsThumbprintOfPublicKey() throws IOException, ParseException, JOSEException {
        File pluginDirectory = new File(tempDir, "foobar");
        pluginDirectory.mkdirs();
        when(serverPaths.getPluginDataDirectory()).thenReturn(pluginDirectory);

        JwtKeyManager keyManager = new JwtKeyManager(serverPaths);
        RSAKey key = keyManager.getRsaKey();

        assertThat(key.getKeyID()).isEqualTo(key.computeThumbprint().toString());
        assertThat(key.getKeyID()).isNotEqualTo("teamcity");
    }

    @Test
    public void testGetRsaKeyReusesFile() throws IOException {
        File pluginDirectory = new File(tempDir, "foobar");
        pluginDirectory.mkdirs();
        when(serverPaths.getPluginDataDirectory()).thenReturn(pluginDirectory);
        File keyFile = new File(pluginDirectory, "JwtBuildFeature/key.json");

        new JwtKeyManager(serverPaths);
        String keyFileContents = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);

        new JwtKeyManager(serverPaths);
        String keyFileContents2 = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);
        assertThat(keyFileContents2).isEqualTo(keyFileContents);
    }

    @Test
    public void constructorThrowsRuntimeExceptionWithClearMessageWhenKeyFileIsCorrupt() throws Exception {
        File pluginDirectory = new File(tempDir, "corrupt");
        pluginDirectory.mkdirs();
        when(serverPaths.getPluginDataDirectory()).thenReturn(pluginDirectory);

        File keyDir = new File(pluginDirectory, "JwtBuildFeature");
        keyDir.mkdirs();
        FileUtils.writeStringToFile(new File(keyDir, "key.json"), "not-valid-json", StandardCharsets.UTF_8);

        assertThatThrownBy(() -> new JwtKeyManager(serverPaths))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("JwtKeyManager");
    }

    @Test
    public void ecKeyIdIsThumbprintOfPublicKey() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtKeyManager keyManager = new JwtKeyManager(serverPaths);
        final var ecKey = keyManager.getEcKey();
        assertThat(ecKey.getKeyID()).isEqualTo(ecKey.computeThumbprint().toString());
    }

    @Test
    public void isHttpsUrlReturnsTrueForHttps() {
        assertThat(JwtKeyManager.isHttpsUrl("https://example.com")).isTrue();
    }

    @Test
    public void isHttpsUrlReturnsFalseForHttp() {
        assertThat(JwtKeyManager.isHttpsUrl("http://example.com")).isFalse();
    }

    @Test
    public void isHttpsUrlReturnsFalseForNull() {
        assertThat(JwtKeyManager.isHttpsUrl(null)).isFalse();
    }

    @Test
    public void normalizeRootUrlStripsTrailingSlash() {
        assertThat(JwtKeyManager.normalizeRootUrl("https://example.com/")).isEqualTo("https://example.com");
    }

    @Test
    public void normalizeRootUrlStripsMultipleTrailingSlashes() {
        assertThat(JwtKeyManager.normalizeRootUrl("https://example.com///")).isEqualTo("https://example.com");
    }

    @Test
    public void normalizeRootUrlLeavesCleanUrlUnchanged() {
        assertThat(JwtKeyManager.normalizeRootUrl("https://example.com")).isEqualTo("https://example.com");
    }

    @Test
    public void normalizeRootUrlReturnsNullForNull() {
        assertThat(JwtKeyManager.normalizeRootUrl(null)).isNull();
    }

    @Test
    public void signThrowsForUnsupportedAlgorithm() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtKeyManager keyManager = new JwtKeyManager(serverPaths);
        com.nimbusds.jwt.JWTClaimsSet claims = new com.nimbusds.jwt.JWTClaimsSet.Builder()
                .subject("test").build();

        assertThatThrownBy(() -> keyManager.sign(claims, "HS256"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("HS256");

        assertThatThrownBy(() -> keyManager.sign(claims, "none"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("none");
    }
}
