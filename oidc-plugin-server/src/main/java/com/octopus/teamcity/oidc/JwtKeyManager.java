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
import jetbrains.buildServer.serverSide.crypt.Encryption;
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
    private final Encryption encryption;
    private final AtomicReference<KeyMaterial> keys;

    /**
     * Production constructor — Spring autowires {@code encryptionManager} (which implements
     * {@link Encryption}) and uses the server-specific key configured via
     * {@code TEAMCITY_ENCRYPTION_KEYS}. When no custom key is set the server falls back to its
     * default scramble strategy; file permissions (0600) remain the primary protection in that
     * case.
     */
    public JwtKeyManager(@NotNull final ServerPaths serverPaths, @NotNull final Encryption encryption) {
        this.encryption = encryption;
        this.keyDirectory = new File(serverPaths.getPluginDataDirectory(), "JwtBuildFeature");
        final var createDirectoryResult = this.keyDirectory.exists() || this.keyDirectory.mkdirs();
        if (!createDirectoryResult)
            throw new RuntimeException("Failed to create key directory");

        try {
            this.keys = new AtomicReference<>(new KeyMaterial(
                    loadOrGenerateRsaKey(),
                    loadRetiredRsaKey(),
                    loadOrGenerateEcKey(),
                    loadRetiredEcKey()
            ));
        } catch (final IOException | ParseException | JOSEException | IllegalArgumentException e) {
            throw new RuntimeException(
                    "JwtKeyManager failed to load or generate keys from " + keyDirectory + ": " + e.getMessage(), e);
        }
    }

    /**
     * Package-private: for unit tests only. Uses {@link EncryptUtil} scramble so tests have no
     * external dependency on the TC server's encryption infrastructure.
     */
    JwtKeyManager(@NotNull final ServerPaths serverPaths) {
        this(serverPaths, new Encryption() {
            @Override public String encrypt(String value) { return EncryptUtil.scramble(value); }
            @Override public String decrypt(String value) { return EncryptUtil.unscramble(value); }
            @Override public boolean isEncrypted(String value) { return EncryptUtil.isScrambled(value); }
        });
    }

    /** Spring factory-method: creates a {@link RotationSettingsManager} sharing the same key directory. */
    public RotationSettingsManager createRotationSettingsManager() {
        return new RotationSettingsManager(keyDirectory);
    }

    public RSAKey getRsaKey() {
        return keys.get().rsa();
    }

    public ECKey getEcKey() {
        return keys.get().ec();
    }

    public @NotNull List<JWK> getPublicKeys() {
        final var snapshot = keys.get();
        final List<JWK> result = new ArrayList<>();
        result.add(snapshot.rsa().toPublicJWK());
        if (snapshot.retiredRsa() != null) result.add(snapshot.retiredRsa().toPublicJWK());
        result.add(snapshot.ec().toPublicJWK());
        if (snapshot.retiredEc() != null) result.add(snapshot.retiredEc().toPublicJWK());
        return Collections.unmodifiableList(result);
    }

    public void rotateKey() throws JOSEException, IOException {
        final var current = keys.get();
        final var newRsa = generateFreshRsaKey();
        final var newEc = generateFreshEcKey();

        saveKeyToFile(current.rsa(), "retired-rsa-key.json");
        saveKeyToFile(current.ec(), "retired-ec-key.json");
        saveKeyToFile(newRsa, "rsa-key.json");
        saveKeyToFile(newEc, "ec-key.json");

        keys.set(new KeyMaterial(newRsa, current.rsa(), newEc, current.ec()));
    }

    /**
     * Signs the given claims using the key for the requested algorithm.
     * Includes {@code typ: JWT} in the header per RFC 7519.
     *
     * @throws IllegalArgumentException if {@code algorithm} is not {@code "RS256"} or {@code "ES256"}
     */
    public SignedJWT sign(@NotNull final JWTClaimsSet claims, @NotNull final String algorithm) throws JOSEException {
        final JWSHeader header;
        final JWSSigner signer;
        if ("ES256".equals(algorithm)) {
            final var ecKey = getEcKey();
            header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(JOSEObjectType.JWT)
                    .keyID(ecKey.getKeyID())
                    .build();
            signer = new ECDSASigner(ecKey);
        } else if ("RS256".equals(algorithm)) {
            final var rsaKey = getRsaKey();
            header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .type(JOSEObjectType.JWT)
                    .keyID(rsaKey.getKeyID())
                    .build();
            signer = new RSASSASigner(rsaKey);
        } else {
            throw new IllegalArgumentException(
                    "Unsupported signing algorithm: \"" + algorithm + "\". Supported values: RS256, ES256");
        }
        final var jwt = new SignedJWT(header, claims);
        jwt.sign(signer);
        return jwt;
    }

    static boolean isHttpsUrl(@Nullable final String url) {
        return url != null && url.startsWith("https://");
    }

    /** Strips trailing slashes from a root URL. Cloud providers compare issuer by exact string. */
    static String normalizeRootUrl(@Nullable final String url) {
        if (url == null) return null;
        return url.replaceAll("/+$", "");
    }

    private RSAKey loadOrGenerateRsaKey() throws IOException, ParseException, JOSEException {
        final var keyFile = new File(keyDirectory, "rsa-key.json");
        if (keyFile.exists()) {
            LOG.info("Read existing RSA key from: " + keyFile);
            final var content = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);
            final var key = JWK.parse(decryptFromFile(content)).toRSAKey();
            if (isLegacyFormat(content)) {
                LOG.info("Migrating RSA key to server encryption: " + keyFile);
                saveKeyToFile(key, "rsa-key.json");
            }
            return key;
        }
        LOG.info("Generate new RSA key to: " + keyFile);
        final var newKey = generateFreshRsaKey();
        saveKeyToFile(newKey, "rsa-key.json");
        return newKey;
    }

    @Nullable
    private RSAKey loadRetiredRsaKey() throws IOException, ParseException {
        final var f = new File(keyDirectory, "retired-rsa-key.json");
        if (!f.exists()) return null;
        LOG.info("Read retired RSA key from: " + f);
        final var content = FileUtils.readFileToString(f, StandardCharsets.UTF_8);
        final var key = JWK.parse(decryptFromFile(content)).toRSAKey();
        if (isLegacyFormat(content)) {
            LOG.info("Migrating retired RSA key to server encryption: " + f);
            saveKeyToFile(key, "retired-rsa-key.json");
        }
        return key;
    }

    private ECKey loadOrGenerateEcKey() throws IOException, ParseException, JOSEException {
        final var keyFile = new File(keyDirectory, "ec-key.json");
        if (keyFile.exists()) {
            LOG.info("Read existing EC key from: " + keyFile);
            final var content = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);
            final var key = JWK.parse(decryptFromFile(content)).toECKey();
            if (isLegacyFormat(content)) {
                LOG.info("Migrating EC key to server encryption: " + keyFile);
                saveKeyToFile(key, "ec-key.json");
            }
            return key;
        }
        LOG.info("Generate new EC key to: " + keyFile);
        final var newKey = generateFreshEcKey();
        saveKeyToFile(newKey, "ec-key.json");
        return newKey;
    }

    @Nullable
    private ECKey loadRetiredEcKey() throws IOException, ParseException {
        final var f = new File(keyDirectory, "retired-ec-key.json");
        if (!f.exists()) return null;
        LOG.info("Read retired EC key from: " + f);
        final var content = FileUtils.readFileToString(f, StandardCharsets.UTF_8);
        final var key = JWK.parse(decryptFromFile(content)).toECKey();
        if (isLegacyFormat(content)) {
            LOG.info("Migrating retired EC key to server encryption: " + f);
            saveKeyToFile(key, "retired-ec-key.json");
        }
        return key;
    }

    /**
     * Detects and decrypts a key file's content. If the file was written by an older version of
     * this plugin (3DES with the TC-wide hardcoded key, prefix {@code zxx}), the content is
     * decrypted via {@link EncryptUtil} for backward compatibility. All other values are passed to
     * the server {@link Encryption} instance.
     */
    private String decryptFromFile(final String content) {
        if (isLegacyFormat(content)) {
            return EncryptUtil.unscramble(content);
        }
        return encryption.decrypt(content);
    }

    /** Returns {@code true} if the content was written by the legacy {@code EncryptUtil.scramble} (prefix {@code zxx}). */
    private boolean isLegacyFormat(final String content) {
        return !encryption.isEncrypted(content) && EncryptUtil.isScrambled(content);
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

    private void saveKeyToFile(@NotNull final JWK key, @NotNull final String fileName) throws IOException {
        final var keyFile = new File(keyDirectory, fileName);
        FileUtils.writeStringToFile(keyFile, encryption.encrypt(key.toString()), StandardCharsets.UTF_8);
        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            Files.setPosixFilePermissions(keyFile.toPath(), Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
            ));
        }
    }
}
