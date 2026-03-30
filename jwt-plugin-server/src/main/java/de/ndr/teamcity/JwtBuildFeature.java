package de.ndr.teamcity;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import jetbrains.buildServer.log.Loggers;
import jetbrains.buildServer.serverSide.*;
import jetbrains.buildServer.serverSide.crypt.EncryptUtil;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import org.apache.commons.io.FileUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;


public class JwtBuildFeature extends BuildFeature {

    private final ServerPaths serverPaths;
    private final PluginDescriptor pluginDescriptor;
    private volatile RSAKey rsaKey;
    @Nullable
    private volatile RSAKey retiredKey;

    public JwtBuildFeature(@NotNull ServerPaths serverPaths, @NotNull PluginDescriptor pluginDescriptor) throws NoSuchAlgorithmException, IOException, ParseException, JOSEException {
        this.serverPaths = serverPaths;
        this.pluginDescriptor = pluginDescriptor;
        this.rsaKey = loadOrGenerateKey();
        this.retiredKey = loadRetiredKey();
    }

    public RSAKey getRsaKey() {
        return rsaKey;
    }

    public List<JWK> getPublicKeys() {
        List<JWK> keys = new ArrayList<>();
        keys.add(rsaKey.toPublicJWK());
        RSAKey retired = retiredKey;
        if (retired != null) {
            keys.add(retired.toPublicJWK());
        }
        return Collections.unmodifiableList(keys);
    }

    public void rotateKey() throws NoSuchAlgorithmException, JOSEException, IOException {
        RSAKey newKey = generateFreshKey();
        RSAKey previousKey = this.rsaKey;

        saveKeyToFile(newKey, "key.json");
        saveKeyToFile(previousKey, "retired-key.json");

        this.retiredKey = previousKey;
        this.rsaKey = newKey;
    }

    @NotNull
    @Override
    public String getType() {
        return "JWT-Plugin";
    }

    @NotNull
    @Override
    public String getDisplayName() {
        return "JWT";
    }

    @Nullable
    @Override
    public String getEditParametersUrl() {
        return pluginDescriptor.getPluginResourcesPath("editJwtBuildFeature.jsp");
    }

    @Override
    public boolean isRequiresAgent() {
        return false;
    }

    @Override
    public boolean isMultipleFeaturesPerBuildTypeAllowed() {
        return false;
    }

    private File getKeyDirectory() {
        File directory = new File(serverPaths.getPluginDataDirectory() + File.separator + "JwtBuildFeature");
        directory.mkdirs();
        return directory;
    }

    private RSAKey loadOrGenerateKey() throws IOException, NoSuchAlgorithmException, ParseException, JOSEException {
        File keyFile = new File(getKeyDirectory() + File.separator + "key.json");
        if (keyFile.exists()) {
            Loggers.SERVER.info("Read existing key from: " + keyFile);
            String encrypted = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);
            return JWK.parse(EncryptUtil.unscramble(encrypted)).toRSAKey();
        } else {
            Loggers.SERVER.info("Generate new key to: " + keyFile);
            RSAKey newKey = generateFreshKey();
            saveKeyToFile(newKey, "key.json");
            return newKey;
        }
    }

    @Nullable
    private RSAKey loadRetiredKey() throws IOException, ParseException {
        File retiredKeyFile = new File(getKeyDirectory() + File.separator + "retired-key.json");
        if (retiredKeyFile.exists()) {
            Loggers.SERVER.info("Read retired key from: " + retiredKeyFile);
            String encrypted = FileUtils.readFileToString(retiredKeyFile, StandardCharsets.UTF_8);
            return JWK.parse(EncryptUtil.unscramble(encrypted)).toRSAKey();
        }
        return null;
    }

    private RSAKey generateFreshKey() throws NoSuchAlgorithmException, JOSEException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair keyPair = gen.generateKeyPair();

        RSAKey newKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build();
        return new RSAKey.Builder(newKey)
                .keyID(newKey.computeThumbprint().toString())
                .build();
    }

    private void saveKeyToFile(RSAKey key, String fileName) throws IOException {
        File keyFile = new File(getKeyDirectory() + File.separator + fileName);
        FileUtils.writeStringToFile(keyFile, EncryptUtil.scramble(key.toString()), StandardCharsets.UTF_8);
        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            Files.setPosixFilePermissions(keyFile.toPath(), Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
            ));
        }
    }
}
