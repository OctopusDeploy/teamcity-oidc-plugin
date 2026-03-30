package de.ndr.teamcity;

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
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class JwtBuildFeatureTest {

    @Mock
    private ServerPaths serverPaths;

    @TempDir
    private File tempDir;

    @Test
    public void testGetRsaKeyCreatesFile() throws NoSuchAlgorithmException, IOException, ParseException {
        File pluginDirectory = new File(tempDir + File.separator + new File("foobar"));
        pluginDirectory.mkdirs();
        when(serverPaths.getPluginDataDirectory()).thenReturn(pluginDirectory);
        File keyFile = new File(pluginDirectory + File.separator + "JwtBuildFeature" + File.separator + "key.json");
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths);
        assertTrue(keyFile.exists());
        String fileContents = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);
        assertThat(fileContents).startsWith("scrambled:");
        assertThat(EncryptUtil.unscramble(fileContents)).isEqualTo(jwtBuildFeature.getRsaKey().toString());
    }

    @Test
    public void keyFileIsReadableAndWritableByOwnerOnly() throws NoSuchAlgorithmException, IOException, ParseException {
        File pluginDirectory = new File(tempDir + File.separator + new File("foobar"));
        pluginDirectory.mkdirs();
        when(serverPaths.getPluginDataDirectory()).thenReturn(pluginDirectory);
        File keyFile = new File(pluginDirectory + File.separator + "JwtBuildFeature" + File.separator + "key.json");

        new JwtBuildFeature(serverPaths);

        Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(keyFile.toPath());
        assertThat(permissions).containsExactlyInAnyOrder(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE
        );
    }

    @Test
    public void testGetRsaKeyReusesFile() throws NoSuchAlgorithmException, IOException, ParseException {

        File pluginDirectory = new File(tempDir + File.separator + new File("foobar"));
        pluginDirectory.mkdirs();
        when(serverPaths.getPluginDataDirectory()).thenReturn(pluginDirectory);
        File keyFile = new File(pluginDirectory + File.separator + "JwtBuildFeature" + File.separator + "key.json");

        new JwtBuildFeature(serverPaths);
        String keyFileContents = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);

        new JwtBuildFeature(serverPaths);
        String keyFileContents2 = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);
        assertThat(keyFileContents2).isEqualTo(keyFileContents);
    }

}
