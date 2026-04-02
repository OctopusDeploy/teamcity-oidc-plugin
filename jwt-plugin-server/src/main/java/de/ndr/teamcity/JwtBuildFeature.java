package de.ndr.teamcity;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import jetbrains.buildServer.serverSide.*;
import jetbrains.buildServer.serverSide.InvalidProperty;
import jetbrains.buildServer.serverSide.PropertiesProcessor;
import jetbrains.buildServer.serverSide.crypt.EncryptUtil;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import org.apache.commons.io.FileUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
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
import java.util.concurrent.atomic.AtomicReference;


public class JwtBuildFeature extends BuildFeature {
    private static final java.util.logging.Logger LOG = java.util.logging.Logger.getLogger(JwtBuildFeature.class.getName());

    record KeyMaterial(
            RSAKey rsa,
            @Nullable RSAKey retiredRsa,
            ECKey ec,
            @Nullable ECKey retiredEc
    ) {}

    private final PluginDescriptor pluginDescriptor;
    private final SBuildServer buildServer;
    private final File keyDirectory;
    private final AtomicReference<KeyMaterial> keys;

    public JwtBuildFeature(@NotNull ServerPaths serverPaths, @NotNull PluginDescriptor pluginDescriptor, @NotNull SBuildServer buildServer) {
        this.pluginDescriptor = pluginDescriptor;
        this.buildServer = buildServer;
        this.keyDirectory = new File(serverPaths.getPluginDataDirectory() + File.separator + "JwtBuildFeature");
        this.keyDirectory.mkdirs();
        try {
            this.keys = new AtomicReference<>(new KeyMaterial(
                    loadOrGenerateRsaKey(),
                    loadRetiredRsaKey(),
                    loadOrGenerateEcKey(),
                    loadRetiredEcKey()
            ));
        } catch (NoSuchAlgorithmException | IOException | ParseException | JOSEException | IllegalArgumentException e) {
            throw new RuntimeException(
                    "JwtBuildFeature failed to load or generate keys from " + keyDirectory + ": " + e.getMessage(), e);
        }
    }

    public RSAKey getRsaKey() {
        return keys.get().rsa();
    }

    public ECKey getEcKey() {
        return keys.get().ec();
    }

    public List<JWK> getPublicKeys() {
        KeyMaterial snapshot = keys.get();
        List<JWK> result = new ArrayList<>();
        result.add(snapshot.rsa().toPublicJWK());
        if (snapshot.retiredRsa() != null) {
            result.add(snapshot.retiredRsa().toPublicJWK());
        }
        result.add(snapshot.ec().toPublicJWK());
        if (snapshot.retiredEc() != null) {
            result.add(snapshot.retiredEc().toPublicJWK());
        }
        return Collections.unmodifiableList(result);
    }

    public void rotateKey() throws NoSuchAlgorithmException, JOSEException, IOException {
        KeyMaterial current = keys.get();
        RSAKey newRsa = generateFreshRsaKey();
        ECKey newEc = generateFreshEcKey();

        saveKeyToFile(current.rsa(), "retired-key.json");
        saveKeyToFile(current.ec(), "retired-ec-key.json");
        saveKeyToFile(newRsa, "key.json");
        saveKeyToFile(newEc, "ec-key.json");

        keys.set(new KeyMaterial(newRsa, current.rsa(), newEc, current.ec()));
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

    @Override
    public PropertiesProcessor getParametersProcessor() {
        return params -> {
            Collection<InvalidProperty> errors = new ArrayList<>();

            String rootUrl = buildServer.getRootUrl();
            if (rootUrl == null || !rootUrl.startsWith("https://")) {
                errors.add(new InvalidProperty("root_url",
                        "The TeamCity server root URL must use HTTPS for OIDC token issuance. " +
                        "Update it in Administration → Global Settings."));
            }

            String ttl = params.getOrDefault("ttl_minutes", "10");
            try {
                int ttlValue = Integer.parseInt(ttl);
                if (ttlValue <= 0) {
                    errors.add(new InvalidProperty("ttl_minutes", "Token lifetime must be a positive integer."));
                }
            } catch (NumberFormatException e) {
                errors.add(new InvalidProperty("ttl_minutes", "Token lifetime must be a valid integer."));
            }

            return errors;
        };
    }

    private RSAKey loadOrGenerateRsaKey() throws IOException, NoSuchAlgorithmException, ParseException, JOSEException {
        File keyFile = new File(keyDirectory + File.separator + "key.json");
        if (keyFile.exists()) {
            LOG.info("Read existing RSA key from: " + keyFile);
            String encrypted = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);
            return JWK.parse(EncryptUtil.unscramble(encrypted)).toRSAKey();
        } else {
            LOG.info("Generate new RSA key to: " + keyFile);
            RSAKey newKey = generateFreshRsaKey();
            saveKeyToFile(newKey, "key.json");
            return newKey;
        }
    }

    @Nullable
    private RSAKey loadRetiredRsaKey() throws IOException, ParseException {
        File retiredKeyFile = new File(keyDirectory + File.separator + "retired-key.json");
        if (retiredKeyFile.exists()) {
            LOG.info("Read retired RSA key from: " + retiredKeyFile);
            String encrypted = FileUtils.readFileToString(retiredKeyFile, StandardCharsets.UTF_8);
            return JWK.parse(EncryptUtil.unscramble(encrypted)).toRSAKey();
        }
        return null;
    }

    @Nullable
    private ECKey loadRetiredEcKey() throws IOException, ParseException {
        File retiredKeyFile = new File(keyDirectory + File.separator + "retired-ec-key.json");
        if (retiredKeyFile.exists()) {
            LOG.info("Read retired EC key from: " + retiredKeyFile);
            String encrypted = FileUtils.readFileToString(retiredKeyFile, StandardCharsets.UTF_8);
            return JWK.parse(EncryptUtil.unscramble(encrypted)).toECKey();
        }
        return null;
    }

    private ECKey loadOrGenerateEcKey() throws IOException, ParseException, JOSEException {
        File keyFile = new File(keyDirectory + File.separator + "ec-key.json");
        if (keyFile.exists()) {
            LOG.info("Read existing EC key from: " + keyFile);
            String encrypted = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);
            return JWK.parse(EncryptUtil.unscramble(encrypted)).toECKey();
        } else {
            LOG.info("Generate new EC key to: " + keyFile);
            ECKey newKey = generateFreshEcKey();
            saveKeyToFile(newKey, "ec-key.json");
            return newKey;
        }
    }

    private RSAKey generateFreshRsaKey() throws NoSuchAlgorithmException, JOSEException {
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

    private ECKey generateFreshEcKey() throws JOSEException {
        ECKey newKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.ES256)
                .generate();
        return new ECKey.Builder(newKey)
                .keyID(newKey.computeThumbprint().toString())
                .build();
    }

    private void saveKeyToFile(JWK key, String fileName) throws IOException {
        File keyFile = new File(keyDirectory + File.separator + fileName);
        FileUtils.writeStringToFile(keyFile, EncryptUtil.scramble(key.toString()), StandardCharsets.UTF_8);
        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            Files.setPosixFilePermissions(keyFile.toPath(), Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
            ));
        }
    }
}
