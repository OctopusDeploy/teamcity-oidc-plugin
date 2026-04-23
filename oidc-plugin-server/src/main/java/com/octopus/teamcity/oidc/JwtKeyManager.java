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
import org.apache.commons.io.FileUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

public class JwtKeyManager {
    private static final Logger LOG = Logger.getLogger(JwtKeyManager.class.getName());

    record KeyMaterial(
            RSAKey rsa,
            @Nullable RSAKey retiredRsa,
            ECKey ec,
            @Nullable ECKey retiredEc,
            RSAKey rsa3072,
            @Nullable RSAKey retiredRsa3072
    ) {}

    private final File keyDirectory;
    private final Encryption encryption;

    /**
     * Keys are null until {@link #notifyTeamCityServerStartupCompleted()} fires. All callers must check
     * {@link #isReady()} or will receive an {@link IllegalStateException}.
     */
    private final AtomicReference<KeyMaterial> keys = new AtomicReference<>();

    /**
     * Spring autowires {@link Encryption} (resolved to TC's {@code EncryptionManager}). Key
     * loading is deferred to {@link #notifyTeamCityServerStartupCompleted()} because {@code EncryptionManager} sets its
     * encryption strategy during TC server startup — after all plugin Spring contexts are
     * initialized — so calling {@code encrypt()} before that point throws
     * {@code IllegalStateException}.
     */
    public JwtKeyManager(@NotNull final ServerPaths serverPaths,
                         @NotNull final Encryption encryption) {
        this.encryption = encryption;
        this.keyDirectory = new File(serverPaths.getPluginDataDirectory(), "JwtBuildFeature");
        if (!this.keyDirectory.exists() && !this.keyDirectory.mkdirs())
            throw new RuntimeException("Failed to create key directory");
    }

    /**
     * Called by TC after full server startup, by which time {@code EncryptionManager} has its
     * encryption strategy set and {@code encrypt()} / {@code decrypt()} are safe to call.
     */
    public void notifyTeamCityServerStartupCompleted() {
        cleanupOrphanedTempFiles();
        try {
            loadKeys();
        } catch (final Exception e) {
            LOG.log(Level.SEVERE, "JWT plugin: failed to load/generate keys on serverStartup — "
                    + "OIDC endpoints will remain unavailable", e);
        }
    }

    private void cleanupOrphanedTempFiles() {
        final var tmpFiles = keyDirectory.listFiles(
                (dir, name) -> name.startsWith("key-") && name.endsWith(".tmp"));
        if (tmpFiles == null) return;
        for (final var f : tmpFiles) {
            if (f.delete()) {
                LOG.info("JWT plugin: cleaned up orphaned temp file: " + f.getName());
            } else {
                LOG.warning("JWT plugin: failed to delete orphaned temp file: " + f.getName());
            }
        }
    }

    /** Returns {@code true} once keys are loaded and available. */
    public boolean isReady() {
        return keys.get() != null;
    }

    /** Spring factory-method: creates a {@link RotationSettingsManager} sharing the same key directory. */
    public RotationSettingsManager createRotationSettingsManager() {
        return new RotationSettingsManager(keyDirectory);
    }

    public RSAKey getRsaKey() {
        return requireReady().rsa();
    }

    public RSAKey getRsa3072Key() {
        return requireReady().rsa3072();
    }

    public ECKey getEcKey() {
        return requireReady().ec();
    }

    public @NotNull List<JWK> getPublicKeys() {
        final var snapshot = requireReady();
        final List<JWK> result = new ArrayList<>();
        result.add(snapshot.rsa().toPublicJWK());
        if (snapshot.retiredRsa() != null) result.add(snapshot.retiredRsa().toPublicJWK());
        result.add(snapshot.rsa3072().toPublicJWK());
        if (snapshot.retiredRsa3072() != null) result.add(snapshot.retiredRsa3072().toPublicJWK());
        result.add(snapshot.ec().toPublicJWK());
        if (snapshot.retiredEc() != null) result.add(snapshot.retiredEc().toPublicJWK());
        return Collections.unmodifiableList(result);
    }

    public synchronized void rotateKey() throws JOSEException, IOException {
        final var current = requireReady();
        // Generate all new keys before touching the filesystem so a key-generation
        // failure leaves the current keys intact.
        final var newRsa = generateFreshRsaKey();
        final var newRsa3072 = generateFreshRsa3072Key();
        final var newEc = generateFreshEcKey();

        // Write new keys to temp files then rename atomically so no reader ever sees
        // a partially-written key file, even if the JVM is killed mid-rotation.
        saveKeyToFile(current.rsa(), "retired-rsa-key.json");
        saveKeyToFile(current.rsa3072(), "retired-rsa3072-key.json");
        saveKeyToFile(current.ec(), "retired-ec-key.json");
        saveKeyToFile(newRsa, "rsa-key.json");
        saveKeyToFile(newRsa3072, "rsa3072-key.json");
        saveKeyToFile(newEc, "ec-key.json");

        keys.set(new KeyMaterial(newRsa, current.rsa(), newEc, current.ec(), newRsa3072, current.rsa3072()));
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
        } else if ("RS384".equals(algorithm)) {
            final var rsaKey = getRsa3072Key();
            header = new JWSHeader.Builder(JWSAlgorithm.RS384)
                    .type(JOSEObjectType.JWT)
                    .keyID(rsaKey.getKeyID())
                    .build();
            signer = new RSASSASigner(rsaKey);
        } else {
            throw new IllegalArgumentException(
                    "Unsupported signing algorithm: \"" + algorithm + "\". Supported values: RS256, RS384, ES256");
        }
        final var jwt = new SignedJWT(header, claims);
        jwt.sign(signer);
        return jwt;
    }

    private KeyMaterial requireReady() {
        final var k = keys.get();
        if (k == null) throw new IllegalStateException(
                "JWT plugin: key manager not yet initialized — server startup is still in progress");
        return k;
    }

    private void loadKeys() throws IOException, ParseException, JOSEException {
        keys.set(new KeyMaterial(
                loadOrGenerateRsaKey(),
                loadRetiredRsaKey(),
                loadOrGenerateEcKey(),
                loadRetiredEcKey(),
                loadOrGenerateRsa3072Key(),
                loadRetiredRsa3072Key()
        ));
        LOG.info("JWT plugin: JwtKeyManager initialized, keys loaded from " + keyDirectory);
    }

    private RSAKey loadOrGenerateRsaKey() throws IOException, ParseException, JOSEException {
        final var keyFile = new File(keyDirectory, "rsa-key.json");
        if (keyFile.exists()) {
            LOG.info("JWT plugin: reading existing RSA key from " + keyFile);
            return JWK.parse(encryption.decrypt(FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8))).toRSAKey();
        }
        LOG.info("JWT plugin: generating new RSA key to " + keyFile);
        final var newKey = generateFreshRsaKey();
        saveKeyToFile(newKey, "rsa-key.json");
        return newKey;
    }

    @Nullable
    private RSAKey loadRetiredRsaKey() throws IOException, ParseException {
        final var f = new File(keyDirectory, "retired-rsa-key.json");
        if (!f.exists()) return null;
        LOG.info("JWT plugin: reading retired RSA key from " + f);
        return JWK.parse(encryption.decrypt(FileUtils.readFileToString(f, StandardCharsets.UTF_8))).toRSAKey();
    }

    private ECKey loadOrGenerateEcKey() throws IOException, ParseException, JOSEException {
        final var keyFile = new File(keyDirectory, "ec-key.json");
        if (keyFile.exists()) {
            LOG.info("JWT plugin: reading existing EC key from " + keyFile);
            return JWK.parse(encryption.decrypt(FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8))).toECKey();
        }
        LOG.info("JWT plugin: generating new EC key to " + keyFile);
        final var newKey = generateFreshEcKey();
        saveKeyToFile(newKey, "ec-key.json");
        return newKey;
    }

    @Nullable
    private ECKey loadRetiredEcKey() throws IOException, ParseException {
        final var f = new File(keyDirectory, "retired-ec-key.json");
        if (!f.exists()) return null;
        LOG.info("JWT plugin: reading retired EC key from " + f);
        return JWK.parse(encryption.decrypt(FileUtils.readFileToString(f, StandardCharsets.UTF_8))).toECKey();
    }

    private static RSAKey generateFreshRsaKey() throws JOSEException {
        return new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyIDFromThumbprint(true)
                .generate();
    }

    private static RSAKey generateFreshRsa3072Key() throws JOSEException {
        return new RSAKeyGenerator(3072)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS384)
                .keyIDFromThumbprint(true)
                .generate();
    }

    private RSAKey loadOrGenerateRsa3072Key() throws IOException, ParseException, JOSEException {
        final var keyFile = new File(keyDirectory, "rsa3072-key.json");
        if (keyFile.exists()) {
            LOG.info("JWT plugin: reading existing RSA-3072 key from " + keyFile);
            return JWK.parse(encryption.decrypt(FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8))).toRSAKey();
        }
        LOG.info("JWT plugin: generating new RSA-3072 key to " + keyFile);
        final var newKey = generateFreshRsa3072Key();
        saveKeyToFile(newKey, "rsa3072-key.json");
        return newKey;
    }

    @Nullable
    private RSAKey loadRetiredRsa3072Key() throws IOException, ParseException {
        final var f = new File(keyDirectory, "retired-rsa3072-key.json");
        if (!f.exists()) return null;
        LOG.info("JWT plugin: reading retired RSA-3072 key from " + f);
        return JWK.parse(encryption.decrypt(FileUtils.readFileToString(f, StandardCharsets.UTF_8))).toRSAKey();
    }

    private static ECKey generateFreshEcKey() throws JOSEException {
        return new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.ES256)
                .keyIDFromThumbprint(true)
                .generate();
    }

    private void saveKeyToFile(@NotNull final JWK key, @NotNull final String fileName) throws IOException {
        final var target = new File(keyDirectory, fileName);
        final var temp = File.createTempFile("key-", ".tmp", keyDirectory);
        try {
            FileUtils.writeStringToFile(temp, encryption.encrypt(key.toString()), StandardCharsets.UTF_8);
            if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                Files.setPosixFilePermissions(temp.toPath(), Set.of(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE
                ));
            }
            Files.move(temp.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } catch (final IOException e) {
            temp.delete();
            throw e;
        }
    }
}
