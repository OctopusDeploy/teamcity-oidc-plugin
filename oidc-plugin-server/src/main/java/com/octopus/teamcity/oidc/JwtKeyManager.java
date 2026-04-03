package com.octopus.teamcity.oidc;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jetbrains.buildServer.serverSide.ServerPaths;
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
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

public class JwtKeyManager {
    private static final Logger LOG = Logger.getLogger(JwtKeyManager.class.getName());

    record KeyMaterial(
            RSAKey rsa,
            @Nullable RSAKey retiredRsa,
            ECKey ec,
            @Nullable ECKey retiredEc
    ) {}

    private final File keyDirectory;
    private final AtomicReference<KeyMaterial> keys;

    public JwtKeyManager(@NotNull ServerPaths serverPaths) {
        this.keyDirectory = new File(serverPaths.getPluginDataDirectory(), "JwtBuildFeature");
        this.keyDirectory.mkdirs();
        try {
            this.keys = new AtomicReference<>(new KeyMaterial(
                    loadOrGenerateRsaKey(),
                    loadRetiredRsaKey(),
                    loadOrGenerateEcKey(),
                    loadRetiredEcKey()
            ));
        } catch (IOException | ParseException | JOSEException | IllegalArgumentException e) {
            throw new RuntimeException(
                    "JwtKeyManager failed to load or generate keys from " + keyDirectory + ": " + e.getMessage(), e);
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
        if (snapshot.retiredRsa() != null) result.add(snapshot.retiredRsa().toPublicJWK());
        result.add(snapshot.ec().toPublicJWK());
        if (snapshot.retiredEc() != null) result.add(snapshot.retiredEc().toPublicJWK());
        return Collections.unmodifiableList(result);
    }

    public void rotateKey() throws JOSEException, IOException {
        KeyMaterial current = keys.get();
        RSAKey newRsa = generateFreshRsaKey();
        ECKey newEc = generateFreshEcKey();

        saveKeyToFile(current.rsa(), "retired-key.json");
        saveKeyToFile(current.ec(), "retired-ec-key.json");
        saveKeyToFile(newRsa, "key.json");
        saveKeyToFile(newEc, "ec-key.json");

        keys.set(new KeyMaterial(newRsa, current.rsa(), newEc, current.ec()));
    }

    /**
     * Signs the given claims using the key for the requested algorithm.
     * Includes {@code typ: JWT} in the header per RFC 7519.
     */
    public SignedJWT sign(@NotNull JWTClaimsSet claims, @NotNull String algorithm) throws JOSEException {
        JWSHeader header;
        JWSSigner signer;
        if ("ES256".equals(algorithm)) {
            ECKey ecKey = getEcKey();
            header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(JOSEObjectType.JWT)
                    .keyID(ecKey.getKeyID())
                    .build();
            signer = new ECDSASigner(ecKey);
        } else {
            RSAKey rsaKey = getRsaKey();
            header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .type(JOSEObjectType.JWT)
                    .keyID(rsaKey.getKeyID())
                    .build();
            signer = new RSASSASigner(rsaKey);
        }
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(signer);
        return jwt;
    }

    static boolean isHttpsUrl(@Nullable String url) {
        return url != null && url.startsWith("https://");
    }

    private RSAKey loadOrGenerateRsaKey() throws IOException, ParseException, JOSEException {
        File keyFile = new File(keyDirectory, "key.json");
        if (keyFile.exists()) {
            LOG.info("Read existing RSA key from: " + keyFile);
            return JWK.parse(EncryptUtil.unscramble(FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8))).toRSAKey();
        }
        LOG.info("Generate new RSA key to: " + keyFile);
        RSAKey newKey = generateFreshRsaKey();
        saveKeyToFile(newKey, "key.json");
        return newKey;
    }

    @Nullable
    private RSAKey loadRetiredRsaKey() throws IOException, ParseException {
        File f = new File(keyDirectory, "retired-key.json");
        if (!f.exists()) return null;
        LOG.info("Read retired RSA key from: " + f);
        return JWK.parse(EncryptUtil.unscramble(FileUtils.readFileToString(f, StandardCharsets.UTF_8))).toRSAKey();
    }

    private ECKey loadOrGenerateEcKey() throws IOException, ParseException, JOSEException {
        File keyFile = new File(keyDirectory, "ec-key.json");
        if (keyFile.exists()) {
            LOG.info("Read existing EC key from: " + keyFile);
            return JWK.parse(EncryptUtil.unscramble(FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8))).toECKey();
        }
        LOG.info("Generate new EC key to: " + keyFile);
        ECKey newKey = generateFreshEcKey();
        saveKeyToFile(newKey, "ec-key.json");
        return newKey;
    }

    @Nullable
    private ECKey loadRetiredEcKey() throws IOException, ParseException {
        File f = new File(keyDirectory, "retired-ec-key.json");
        if (!f.exists()) return null;
        LOG.info("Read retired EC key from: " + f);
        return JWK.parse(EncryptUtil.unscramble(FileUtils.readFileToString(f, StandardCharsets.UTF_8))).toECKey();
    }

    private static RSAKey generateFreshRsaKey() throws JOSEException {
        return new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyIDFromThumbprint(true)
                .generate();
    }

    private static ECKey generateFreshEcKey() throws JOSEException {
        return new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.ES256)
                .keyIDFromThumbprint(true)
                .generate();
    }

    private void saveKeyToFile(@NotNull JWK key, @NotNull String fileName) throws IOException {
        File keyFile = new File(keyDirectory, fileName);
        FileUtils.writeStringToFile(keyFile, EncryptUtil.scramble(key.toString()), StandardCharsets.UTF_8);
        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            Files.setPosixFilePermissions(keyFile.toPath(), Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
            ));
        }
    }
}
