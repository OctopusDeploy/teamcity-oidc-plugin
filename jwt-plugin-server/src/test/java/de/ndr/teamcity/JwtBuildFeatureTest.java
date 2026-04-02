package de.ndr.teamcity;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import jetbrains.buildServer.serverSide.InvalidProperty;
import jetbrains.buildServer.serverSide.PropertiesProcessor;
import jetbrains.buildServer.serverSide.SBuildServer;
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
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class JwtBuildFeatureTest {

    @Mock
    private ServerPaths serverPaths;

    @Mock
    private PluginDescriptor pluginDescriptor;

    @Mock
    private SBuildServer buildServer;

    @TempDir
    private File tempDir;

    @Test
    public void testGetRsaKeyCreatesFile() throws NoSuchAlgorithmException, IOException, ParseException, JOSEException {
        File pluginDirectory = new File(tempDir + File.separator + new File("foobar"));
        pluginDirectory.mkdirs();
        when(serverPaths.getPluginDataDirectory()).thenReturn(pluginDirectory);
        File keyFile = new File(pluginDirectory + File.separator + "JwtBuildFeature" + File.separator + "key.json");
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);
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

        new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

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

        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);
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

        new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);
        String keyFileContents = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);

        new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);
        String keyFileContents2 = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);
        assertThat(keyFileContents2).isEqualTo(keyFileContents);
    }

    @Test
    public void constructorThrowsRuntimeExceptionWithClearMessageWhenKeyFileIsCorrupt() throws Exception {
        File pluginDirectory = new File(tempDir + File.separator + "corrupt");
        pluginDirectory.mkdirs();
        when(serverPaths.getPluginDataDirectory()).thenReturn(pluginDirectory);

        File keyDir = new File(pluginDirectory, "JwtBuildFeature");
        keyDir.mkdirs();
        FileUtils.writeStringToFile(new File(keyDir, "key.json"), "not-valid-json", StandardCharsets.UTF_8);

        assertThatThrownBy(() -> new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("JwtBuildFeature");
    }

    @Test
    public void validationRejectsHttpRootUrl() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("http://teamcity.example.com");

        JwtBuildFeature feature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);
        PropertiesProcessor processor = feature.getParametersProcessor();
        Collection<InvalidProperty> errors = processor.process(Map.of());

        assertThat(errors).hasSize(1);
        assertThat(errors.iterator().next().getInvalidReason()).contains("HTTPS");
    }

    @Test
    public void validationAcceptsHttpsRootUrl() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");

        JwtBuildFeature feature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);
        PropertiesProcessor processor = feature.getParametersProcessor();
        Collection<InvalidProperty> errors = processor.process(Map.of());

        assertThat(errors).isEmpty();
    }

    @Test
    public void validationRejectsNonNumericTtl() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");

        JwtBuildFeature feature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);
        PropertiesProcessor processor = feature.getParametersProcessor();
        Collection<InvalidProperty> errors = processor.process(Map.of("ttl_minutes", "notanumber"));

        assertThat(errors).hasSize(1);
        assertThat(errors.iterator().next().getPropertyName()).isEqualTo("ttl_minutes");
    }

    @Test
    public void validationRejectsNonPositiveTtl() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");

        JwtBuildFeature feature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);
        PropertiesProcessor processor = feature.getParametersProcessor();
        Collection<InvalidProperty> errors = processor.process(Map.of("ttl_minutes", "0"));

        assertThat(errors).hasSize(1);
        assertThat(errors.iterator().next().getPropertyName()).isEqualTo("ttl_minutes");
    }

    @Test
    public void describeParametersIncludesAlgorithmAndTtl() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature feature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        String description = feature.describeParameters(Map.of("algorithm", "ES256", "ttl_minutes", "5"));

        assertThat(description).contains("ES256").contains("5m");
    }

    @Test
    public void describeParametersIncludesAudienceWhenPresent() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature feature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        String description = feature.describeParameters(
                Map.of("algorithm", "RS256", "ttl_minutes", "10", "audience", "api://my-app"));

        assertThat(description).contains("RS256").contains("10m").contains("api://my-app");
    }

    @Test
    public void describeParametersOmitsAudienceWhenBlank() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature feature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        String description = feature.describeParameters(Map.of("algorithm", "RS256", "ttl_minutes", "10"));

        assertThat(description).doesNotContain("aud:");
    }

    @Test
    public void describeParametersDefaultsToRS256AndTenMinutesWhenParamsMissing() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature feature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);

        String description = feature.describeParameters(Map.of());

        assertThat(description).contains("RS256").contains("10m");
    }
}
