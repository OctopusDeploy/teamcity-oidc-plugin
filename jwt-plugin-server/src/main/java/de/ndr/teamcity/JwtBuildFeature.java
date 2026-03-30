package de.ndr.teamcity;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import jetbrains.buildServer.log.Loggers;
import jetbrains.buildServer.serverSide.*;
import jetbrains.buildServer.serverSide.crypt.EncryptUtil;
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
import java.util.Set;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;


public class JwtBuildFeature extends BuildFeature {

    private final ServerPaths serverPaths;
    private final RSAKey rsaKey;

    public JwtBuildFeature(@NotNull ServerPaths serverPaths) throws NoSuchAlgorithmException, IOException, ParseException {
        this.serverPaths = serverPaths;
        rsaKey = this.generateRSAKey();
    }

    public RSAKey getRsaKey() {
        return rsaKey;
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
        return "";
    }

    @Override
    public boolean isRequiresAgent() {
        return false;
    }

    @Override
    public boolean isMultipleFeaturesPerBuildTypeAllowed() {
        return false;
    }

    private RSAKey generateRSAKey() throws IOException, NoSuchAlgorithmException, ParseException {
        File directory = new File(serverPaths.getPluginDataDirectory() + File.separator + "JwtBuildFeature");
        directory.mkdirs();
        File keyFile = new File(directory + File.separator + "key.json");
        JWK jwk;
        if (keyFile.exists()) {
            Loggers.SERVER.info("Read existing key from: " + keyFile);
            String encrypted = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);
            jwk = JWK.parse(EncryptUtil.unscramble(encrypted));
        } else {
            Loggers.SERVER.info("Generate new key to: " + keyFile);
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair keyPair = gen.generateKeyPair();

            jwk = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                    .privateKey((RSAPrivateKey) keyPair.getPrivate())
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID("teamcity")
                    .algorithm(JWSAlgorithm.RS256)
                    .build();
            FileUtils.writeStringToFile(keyFile, EncryptUtil.scramble(jwk.toString()), StandardCharsets.UTF_8);
            if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                Files.setPosixFilePermissions(keyFile.toPath(), Set.of(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE
                ));
            }
        }
        return jwk.toRSAKey();
    }
}
