package com.octopus.teamcity.oidc;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jetbrains.buildServer.serverSide.BuildServerAdapter;
import jetbrains.buildServer.serverSide.SBuildServer;
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
import java.util.logging.Level;
import java.util.logging.Logger;

public class JwtKeyManager extends BuildServerAdapter {
    private static final Logger LOG = Logger.getLogger(JwtKeyManager.class.getName());

    record KeyMaterial(
            RSAKey rsa,
            @Nullable RSAKey retiredRsa,
            ECKey ec,
            @Nullable ECKey retiredEc
    ) {}

    private final File keyDirectory;
    private final Encryption encryption;
    private final SBuildServer buildServer;

    /**
     * Keys are null until {@link #serverStartup()} fires. All callers must check
     * {@link #isReady()} or will receive an {@link IllegalStateException}.
     */
    private final AtomicReference<KeyMaterial> keys = new AtomicReference<>();

    /**
     * Production constructor. Spring autowires {@link Encryption} (resolved to TC's
     * {@code EncryptionManager}) and {@link ExtensionHolder}. Key loading is deferred to
     * {@link #serverStartup()} because {@code EncryptionManager} sets its encryption strategy
     * during TC server startup — after all plugin Spring contexts are initialized — so calling
     * {@code encrypt()} before that point throws {@code IllegalStateException}.
     */
    public JwtKeyManager(@NotNull final ServerPaths serverPaths,
                         @NotNull final Encryption encryption,
                         @NotNull final SBuildServer buildServer) {
        this.encryption = encryption;
        this.buildServer = buildServer;
        this.keyDirectory = new File(serverPaths.getPluginDataDirectory(), "JwtBuildFeature");
        if (!this.keyDirectory.exists() && !this.keyDirectory.mkdirs())
            throw new RuntimeException("Failed to create key directory");
    }

    /** Called by Spring {@code init-method} — registers this bean as a {@link BuildServerAdapter}. */
    public void register() {
        buildServer.addListener(this);
        LOG.info("JWT plugin: JwtKeyManager registered as BuildServerListener — keys will load on serverStartup");
    }

    /**
     * Called by TC after full server startup, by which time {@code EncryptionManager} has its
     * encryption strategy set and {@code encrypt()} / {@code decrypt()} are safe to call.
     */
    @Override
    public void serverStartup() {
        try {
            loadKeys();
        } catch (final Exception e) {
            LOG.log(Level.SEVERE, "JWT plugin: failed to load/generate keys on serverStartup — "
                    + "OIDC endpoints will remain unavailable", e);
        }
    }

    /** Returns {@code true} once {@link #serverStartup()} has successfully loaded keys. */
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

    public ECKey getEcKey() {
        return requireReady().ec();
    }

    public @NotNull List<JWK> getPublicKeys() {
        final var snapshot = requireReady();
        final List<JWK> result = new ArrayList<>();
        result.add(snapshot.rsa().toPublicJWK());
        if (snapshot.retiredRsa() != null) result.add(snapshot.retiredRsa().toPublicJWK());
        result.add(snapshot.ec().toPublicJWK());
        if (snapshot.retiredEc() != null) result.add(snapshot.retiredEc().toPublicJWK());
        return Collections.unmodifiableList(result);
    }

    public void rotateKey() throws JOSEException, IOException {
        final var current = requireReady();
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
        if (url == null) return false;
        try {
            final var uri = new java.net.URI(url);
            return "https".equals(uri.getScheme())
                    && uri.getHost() != null && !uri.getHost().isEmpty();
        } catch (final java.net.URISyntaxException e) {
            return false;
        }
    }

    /** Strips trailing slashes from a root URL. Cloud providers compare issuer by exact string. */
    static String normalizeRootUrl(@Nullable final String url) {
        if (url == null) return null;
        return url.replaceAll("/+$", "");
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
                loadRetiredEcKey()
        ));
        LOG.info("JWT plugin: JwtKeyManager initialized, keys loaded from " + keyDirectory);
    }

    private RSAKey loadOrGenerateRsaKey() throws IOException, ParseException, JOSEException {
        final var keyFile = new File(keyDirectory, "rsa-key.json");
        if (keyFile.exists()) {
            LOG.info("JWT plugin: reading existing RSA key from " + keyFile);
            final var content = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);
            final var key = JWK.parse(decryptFromFile(content)).toRSAKey();
            if (isLegacyFormat(content)) {
                LOG.info("JWT plugin: migrating RSA key to server encryption");
                saveKeyToFile(key, "rsa-key.json");
            }
            return key;
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
        final var content = FileUtils.readFileToString(f, StandardCharsets.UTF_8);
        final var key = JWK.parse(decryptFromFile(content)).toRSAKey();
        if (isLegacyFormat(content)) {
            LOG.info("JWT plugin: migrating retired RSA key to server encryption");
            saveKeyToFile(key, "retired-rsa-key.json");
        }
        return key;
    }

    private ECKey loadOrGenerateEcKey() throws IOException, ParseException, JOSEException {
        final var keyFile = new File(keyDirectory, "ec-key.json");
        if (keyFile.exists()) {
            LOG.info("JWT plugin: reading existing EC key from " + keyFile);
            final var content = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);
            final var key = JWK.parse(decryptFromFile(content)).toECKey();
            if (isLegacyFormat(content)) {
                LOG.info("JWT plugin: migrating EC key to server encryption");
                saveKeyToFile(key, "ec-key.json");
            }
            return key;
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
        final var content = FileUtils.readFileToString(f, StandardCharsets.UTF_8);
        final var key = JWK.parse(decryptFromFile(content)).toECKey();
        if (isLegacyFormat(content)) {
            LOG.info("JWT plugin: migrating retired EC key to server encryption");
            saveKeyToFile(key, "retired-ec-key.json");
        }
        return key;
    }

    /**
     * Decrypts a key file's content. Files written by {@link EncryptUtil#scramble} (legacy, prefix
     * {@code zxx}) are decrypted via {@link EncryptUtil}; all others via the server
     * {@link Encryption} instance.
     */
    private String decryptFromFile(final String content) {
        return isLegacyFormat(content) ? EncryptUtil.unscramble(content) : encryption.decrypt(content);
    }

    /** Returns {@code true} if the content was written by the legacy {@link EncryptUtil#scramble} (prefix {@code zxx}). */
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
