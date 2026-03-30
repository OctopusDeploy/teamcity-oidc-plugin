package de.ndr.teamcity;

import com.nimbusds.jose.jwk.RSAKey;
import jetbrains.buildServer.serverSide.ServerPaths;
import jetbrains.buildServer.serverSide.crypt.EncryptUtil;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
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
import com.nimbusds.jose.JOSEException;
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

    @Mock
    private PluginDescriptor pluginDescriptor;

    @TempDir
    private File tempDir;

    @Test
    public void testGetRsaKeyCreatesFile() throws NoSuchAlgorithmException, IOException, ParseException, JOSEException {
        File pluginDirectory = new File(tempDir + File.separator + new File("foobar"));
        pluginDirectory.mkdirs();
        when(serverPaths.getPluginDataDirectory()).thenReturn(pluginDirectory);
        File keyFile = new File(pluginDirectory + File.separator + "JwtBuildFeature" + File.separator + "key.json");
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor);
        assertTrue(keyFile.exists());
        String fileContents = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);
        assertThat(fileContents).startsWith("scrambled:");
        assertThat(EncryptUtil.unscramble(fileContents)).isEqualTo(jwtBuildFeature.getRsaKey().toString());
    }

    @Test
    public void keyFileIsReadableAndWritableByOwnerOnly() throws NoSuchAlgorithmException, IOException, ParseException, JOSEException {
        File pluginDirectory = new File(tempDir + File.separator + new File("foobar"));
        pluginDirectory.mkdirs();
        when(serverPaths.getPluginDataDirectory()).thenReturn(pluginDirectory);
        File keyFile = new File(pluginDirectory + File.separator + "JwtBuildFeature" + File.separator + "key.json");

        new JwtBuildFeature(serverPaths, pluginDescriptor);

        Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(keyFile.toPath());
        assertThat(permissions).containsExactlyInAnyOrder(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE
        );
    }

    @Test
    public void keyIdIsThumbprintOfPublicKey() throws NoSuchAlgorithmException, IOException, ParseException, JOSEException {
        File pluginDirectory = new File(tempDir + File.separator + new File("foobar"));
        pluginDirectory.mkdirs();
        when(serverPaths.getPluginDataDirectory()).thenReturn(pluginDirectory);

        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor);
        RSAKey key = jwtBuildFeature.getRsaKey();

        assertThat(key.getKeyID()).isEqualTo(key.computeThumbprint().toString());
        assertThat(key.getKeyID()).isNotEqualTo("teamcity");
    }

    @Test
    public void testGetRsaKeyReusesFile() throws NoSuchAlgorithmException, IOException, ParseException, JOSEException {

        File pluginDirectory = new File(tempDir + File.separator + new File("foobar"));
        pluginDirectory.mkdirs();
        when(serverPaths.getPluginDataDirectory()).thenReturn(pluginDirectory);
        File keyFile = new File(pluginDirectory + File.separator + "JwtBuildFeature" + File.separator + "key.json");

        new JwtBuildFeature(serverPaths, pluginDescriptor);
        String keyFileContents = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);

        new JwtBuildFeature(serverPaths, pluginDescriptor);
        String keyFileContents2 = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);
        assertThat(keyFileContents2).isEqualTo(keyFileContents);
    }

}
