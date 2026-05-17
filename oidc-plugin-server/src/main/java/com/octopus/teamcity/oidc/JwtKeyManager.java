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
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

public class JwtKeyManager {
    private static final Logger LOG = Logger.getLogger(JwtKeyManager.class.getName());

    private static final String[] KEY_FILE_NAMES = {
            "rsa-key.json", "ec-key.json", "rsa3072-key.json",
            "retired-rsa-key.json", "retired-ec-key.json", "retired-rsa3072-key.json"
    };

    record KeyMaterial(
            @NotNull KeySlot rsa,
            @Nullable KeySlot retiredRsa,
            @NotNull KeySlot ec,
            @Nullable KeySlot retiredEc,
            @NotNull KeySlot rsa3072,
            @Nullable KeySlot retiredRsa3072
    ) {
        // Convenience accessors so existing call sites keep their shape.
        @NotNull RSAKey rsaKey() { return (RSAKey) rsa.jwk(); }
        @Nullable RSAKey retiredRsaKey() { return retiredRsa == null ? null : (RSAKey) retiredRsa.jwk(); }
        @NotNull ECKey ecKey() { return (ECKey) ec.jwk(); }
        @Nullable ECKey retiredEcKey() { return retiredEc == null ? null : (ECKey) retiredEc.jwk(); }
        @NotNull RSAKey rsa3072Key() { return (RSAKey) rsa3072.jwk(); }
        @Nullable RSAKey retiredRsa3072Key() { return retiredRsa3072 == null ? null : (RSAKey) retiredRsa3072.jwk(); }
    }

    private final File keyDirectory;
    private final Encryption encryption;

    /**
     * Keys are null until {@link #notifyTeamCityServerStartupCompleted()} fires. All callers must check
     * {@link #isReady()} or will receive an {@link IllegalStateException}.
     */
    private final AtomicReference<KeyMaterial> keys = new AtomicReference<>();

    /**
     * Max {@code lastModified} across the key files at the time {@link #keys} was last loaded.
     * In TC HA only the main node rotates (gated in {@link KeyRotationScheduler}), but every
     * node serves JWKS and signs build tokens. Secondaries keep their in-memory
     * {@link KeyMaterial} aligned with the shared filesystem by reloading whenever
     * {@link #maxKeyFileMtime()} changes — see {@link #refreshIfStale()}. Comparison uses
     * inequality, not greater-than, so clock skew on shared storage cannot mask a change.
     */
    private volatile long lastLoadedMaxMtime = 0L;

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

    /** Spring factory-method: creates an {@link OidcSettingsManager} sharing the same key directory. */
    public OidcSettingsManager createOidcSettingsManager() {
        return new OidcSettingsManager(keyDirectory);
    }

    public RSAKey getRsaKey() {
        return requireReady().rsaKey();
    }

    public RSAKey getRsa3072Key() {
        return requireReady().rsa3072Key();
    }

    public ECKey getEcKey() {
        return requireReady().ecKey();
    }

    /** Package-private — for tests only. */
    @NotNull KeySlot getRsaKeySlot() { return requireReady().rsa(); }
    /** Package-private — for tests only. */
    @NotNull KeySlot getEcKeySlot() { return requireReady().ec(); }
    /** Package-private — for tests only. */
    @NotNull KeySlot getRsa3072KeySlot() { return requireReady().rsa3072(); }

    public @NotNull List<JWK> getPublicKeys() {
        final var snapshot = requireReady();
        final List<JWK> result = new ArrayList<>();
        result.add(snapshot.rsaKey().toPublicJWK());
        if (snapshot.retiredRsaKey() != null) result.add(snapshot.retiredRsaKey().toPublicJWK());
        result.add(snapshot.rsa3072Key().toPublicJWK());
        if (snapshot.retiredRsa3072Key() != null) result.add(snapshot.retiredRsa3072Key().toPublicJWK());
        result.add(snapshot.ecKey().toPublicJWK());
        if (snapshot.retiredEcKey() != null) result.add(snapshot.retiredEcKey().toPublicJWK());
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
        saveKeyToFile(current.rsaKey(), "retired-rsa-key.json", current.rsa().activateAt());
        saveKeyToFile(current.rsa3072Key(), "retired-rsa3072-key.json", current.rsa3072().activateAt());
        saveKeyToFile(current.ecKey(), "retired-ec-key.json", current.ec().activateAt());
        final var now = Instant.now();
        saveKeyToFile(newRsa, "rsa-key.json", now);
        saveKeyToFile(newRsa3072, "rsa3072-key.json", now);
        saveKeyToFile(newEc, "ec-key.json", now);

        keys.set(new KeyMaterial(
                new KeySlot(newRsa, now),
                new KeySlot(current.rsaKey(), current.rsa().activateAt()),
                new KeySlot(newEc, now),
                new KeySlot(current.ecKey(), current.ec().activateAt()),
                new KeySlot(newRsa3072, now),
                new KeySlot(current.rsa3072Key(), current.rsa3072().activateAt())));
        // Record that this node's in-memory state matches what we just wrote, so the next
        // refreshIfStale() doesn't misread our own writes as an external change.
        lastLoadedMaxMtime = maxKeyFileMtime();
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
        refreshIfStale();
        return keys.get();
    }

    /**
     * If a writer (typically the main node in TC HA, or another thread on this node) has updated
     * the key files on the shared filesystem since the last load, reload them. Fast-path is a
     * single volatile read plus a few {@code stat()} syscalls; only takes the lock when a real
     * change is detected.
     */
    private void refreshIfStale() {
        if (maxKeyFileMtime() == lastLoadedMaxMtime) return;
        synchronized (this) {
            final var observed = maxKeyFileMtime();
            if (observed == lastLoadedMaxMtime) return;
            try {
                LOG.info("JWT plugin: detected key file change on disk — reloading keys");
                loadKeys();
                lastLoadedMaxMtime = observed;
            } catch (final Exception e) {
                LOG.log(Level.SEVERE, "JWT plugin: failed to reload keys after detecting filesystem"
                        + " change — continuing to serve previously-loaded keys", e);
            }
        }
    }

    private long maxKeyFileMtime() {
        var max = 0L;
        for (final var name : KEY_FILE_NAMES) {
            final var m = new File(keyDirectory, name).lastModified();
            if (m > max) max = m;
        }
        return max;
    }

    private void loadKeys() throws IOException, ParseException, JOSEException {
        final var rsa = loadOrGenerateRsaKey();
        final var retiredRsa = loadRetiredRsaKey();
        final var ec = loadOrGenerateEcKey();
        final var retiredEc = loadRetiredEcKey();
        final var rsa3072 = loadOrGenerateRsa3072Key();
        final var retiredRsa3072 = loadRetiredRsa3072Key();

        keys.set(new KeyMaterial(
                new KeySlot(rsa.jwk(), rsa.activateAt()),
                retiredRsa == null ? null : new KeySlot(retiredRsa.jwk(), retiredRsa.activateAt()),
                new KeySlot(ec.jwk(), ec.activateAt()),
                retiredEc == null ? null : new KeySlot(retiredEc.jwk(), retiredEc.activateAt()),
                new KeySlot(rsa3072.jwk(), rsa3072.activateAt()),
                retiredRsa3072 == null ? null : new KeySlot(retiredRsa3072.jwk(), retiredRsa3072.activateAt())));
        lastLoadedMaxMtime = maxKeyFileMtime();
        LOG.info("JWT plugin: JwtKeyManager initialized, keys loaded from " + keyDirectory);
    }

    private ParsedKey loadOrGenerateRsaKey() throws IOException, ParseException, JOSEException {
        final var keyFile = new File(keyDirectory, "rsa-key.json");
        if (keyFile.exists()) {
            LOG.info("JWT plugin: reading existing RSA key from " + keyFile);
            final var parsed = parseKeyEnvelope(keyFile);
            if (!(parsed.jwk() instanceof RSAKey)) {
                throw new IOException("Expected RSA key in rsa-key.json");
            }
            return parsed;
        }
        LOG.info("JWT plugin: generating new RSA key to " + keyFile);
        final var newKey = generateFreshRsaKey();
        final var now = Instant.now();
        saveKeyToFile(newKey, "rsa-key.json", now);
        return new ParsedKey(newKey, now);
    }

    @Nullable
    private ParsedKey loadRetiredRsaKey() throws IOException, ParseException {
        final var f = new File(keyDirectory, "retired-rsa-key.json");
        if (!f.exists()) return null;
        LOG.info("JWT plugin: reading retired RSA key from " + f);
        final var parsed = parseKeyEnvelope(f);
        if (!(parsed.jwk() instanceof RSAKey)) {
            throw new IOException("Expected RSA key in retired-rsa-key.json");
        }
        return parsed;
    }

    private ParsedKey loadOrGenerateEcKey() throws IOException, ParseException, JOSEException {
        final var keyFile = new File(keyDirectory, "ec-key.json");
        if (keyFile.exists()) {
            LOG.info("JWT plugin: reading existing EC key from " + keyFile);
            final var parsed = parseKeyEnvelope(keyFile);
            if (!(parsed.jwk() instanceof ECKey)) {
                throw new IOException("Expected EC key in ec-key.json");
            }
            return parsed;
        }
        LOG.info("JWT plugin: generating new EC key to " + keyFile);
        final var newKey = generateFreshEcKey();
        final var now = Instant.now();
        saveKeyToFile(newKey, "ec-key.json", now);
        return new ParsedKey(newKey, now);
    }

    @Nullable
    private ParsedKey loadRetiredEcKey() throws IOException, ParseException {
        final var f = new File(keyDirectory, "retired-ec-key.json");
        if (!f.exists()) return null;
        LOG.info("JWT plugin: reading retired EC key from " + f);
        final var parsed = parseKeyEnvelope(f);
        if (!(parsed.jwk() instanceof ECKey)) {
            throw new IOException("Expected EC key in retired-ec-key.json");
        }
        return parsed;
    }

    private ParsedKey loadOrGenerateRsa3072Key() throws IOException, ParseException, JOSEException {
        final var keyFile = new File(keyDirectory, "rsa3072-key.json");
        if (keyFile.exists()) {
            LOG.info("JWT plugin: reading existing RSA-3072 key from " + keyFile);
            final var parsed = parseKeyEnvelope(keyFile);
            if (!(parsed.jwk() instanceof RSAKey)) {
                throw new IOException("Expected RSA key in rsa3072-key.json");
            }
            return parsed;
        }
        LOG.info("JWT plugin: generating new RSA-3072 key to " + keyFile);
        final var newKey = generateFreshRsa3072Key();
        final var now = Instant.now();
        saveKeyToFile(newKey, "rsa3072-key.json", now);
        return new ParsedKey(newKey, now);
    }

    @Nullable
    private ParsedKey loadRetiredRsa3072Key() throws IOException, ParseException {
        final var f = new File(keyDirectory, "retired-rsa3072-key.json");
        if (!f.exists()) return null;
        LOG.info("JWT plugin: reading retired RSA-3072 key from " + f);
        final var parsed = parseKeyEnvelope(f);
        if (!(parsed.jwk() instanceof RSAKey)) {
            throw new IOException("Expected RSA key in retired-rsa3072-key.json");
        }
        return parsed;
    }

    private static RSAKey generateFreshRsaKey() throws JOSEException {
        final var key = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyIDFromThumbprint(true)
                .generate();
        return new RSAKey.Builder(key).issueTime(new java.util.Date()).build();
    }

    private static RSAKey generateFreshRsa3072Key() throws JOSEException {
        final var key = new RSAKeyGenerator(3072)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS384)
                .keyIDFromThumbprint(true)
                .generate();
        return new RSAKey.Builder(key).issueTime(new java.util.Date()).build();
    }

    private static ECKey generateFreshEcKey() throws JOSEException {
        final var key = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.ES256)
                .keyIDFromThumbprint(true)
                .generate();
        return new ECKey.Builder(key).issueTime(new java.util.Date()).build();
    }

    /**
     * Wraps a JWK and an activateAt instant into the on-disk envelope JSON shape.
     * Why envelope rather than a custom JWK field: Nimbus's JWK.toPublicJWK() copies
     * custom JWK parameters into the public output. If activateAt were a custom JWK
     * member, it would leak into the public JWKS and reveal our internal rotation
     * cadence to every consumer. The envelope keeps activateAt outside the JWK
     * boundary so the public render path can never serialise it.
     */
    private static String toEnvelopeJson(@NotNull final JWK jwk, @NotNull final Instant activateAt) {
        final var obj = new net.minidev.json.JSONObject();
        obj.put("jwk", net.minidev.json.JSONValue.parse(jwk.toString()));
        obj.put("activateAt", activateAt.toString());
        return obj.toJSONString();
    }

    /**
     * Reads either the new envelope format ({@code {"jwk": ..., "activateAt": ...}}) or
     * the legacy bare-JWK format. Detection is by top-level keys: presence of {@code jwk}
     * means envelope, presence of {@code kty} means legacy. Missing activateAt — whether
     * because the file is legacy or because the envelope omits it — loads as
     * {@code Instant.EPOCH}, which the rest of the manager treats as "eligible to sign
     * right now."
     */
    private @NotNull ParsedKey parseKeyEnvelope(@NotNull final File file)
            throws IOException, ParseException {
        final var decrypted = encryption.decrypt(FileUtils.readFileToString(file, StandardCharsets.UTF_8));
        final Object parsed;
        try {
            parsed = new net.minidev.json.parser.JSONParser(
                    net.minidev.json.parser.JSONParser.MODE_PERMISSIVE).parse(decrypted);
        } catch (final net.minidev.json.parser.ParseException e) {
            throw new IOException("Key file " + file.getName() + " did not contain valid JSON", e);
        }
        if (!(parsed instanceof final net.minidev.json.JSONObject obj)) {
            throw new IOException("Key file " + file.getName() + " did not contain a JSON object");
        }
        final var inner = obj.get("jwk");
        if (inner != null) {
            // Envelope format.
            final var activateAtRaw = obj.get("activateAt");
            final var activateAt = activateAtRaw instanceof final String s
                    ? Instant.parse(s) : Instant.EPOCH;
            return new ParsedKey(JWK.parse(inner.toString()), activateAt);
        }
        if (obj.get("kty") != null) {
            // Legacy bare-JWK format.
            return new ParsedKey(JWK.parse(decrypted), Instant.EPOCH);
        }
        throw new IOException("Key file " + file.getName() + " is neither envelope nor legacy JWK shape");
    }

    private record ParsedKey(@NotNull JWK jwk, @NotNull Instant activateAt) {}

    private void saveKeyToFile(@NotNull final JWK key, @NotNull final String fileName,
                               @NotNull final Instant activateAt) throws IOException {
        final var target = new File(keyDirectory, fileName);
        final var temp = File.createTempFile("key-", ".tmp", keyDirectory);
        try {
            FileUtils.writeStringToFile(temp, encryption.encrypt(toEnvelopeJson(key, activateAt)),
                    StandardCharsets.UTF_8);
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
