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
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

// TODO: this class is doing too many things at once (key lifecycle state machine,
// JWK envelope serialisation + atomic disk I/O, signing, public-key rendering,
// rotation orchestration, the KeyMaterial record itself). The natural split is:
// (1) `KeyMaterial` extracted as a top-level record, (2) a `JwtKeyStorage` class
// owning all File / Encryption / envelope I/O, (3) this class focused on the
// lifecycle/signing/rotation contract. Deferred to a follow-up PR — the current
// scope is the warmup feature and reshaping the class would make that diff harder
// to review. Tracking: items 4 + 5 from the PR review on this branch.
public class JwtKeyManager {
    private static final Logger LOG = Logger.getLogger(JwtKeyManager.class.getName());

    private static final String[] KEY_FILE_NAMES = {
            "rsa-key.json", "ec-key.json", "rsa3072-key.json",
            "retired-rsa-key.json", "retired-ec-key.json", "retired-rsa3072-key.json",
            "pending-rsa-key.json", "pending-ec-key.json", "pending-rsa3072-key.json"
    };

    record KeyMaterial(
            @NotNull KeySlot rsa,
            @Nullable KeySlot retiredRsa,
            @Nullable KeySlot pendingRsa,
            @NotNull KeySlot ec,
            @Nullable KeySlot retiredEc,
            @Nullable KeySlot pendingEc,
            @NotNull KeySlot rsa3072,
            @Nullable KeySlot retiredRsa3072,
            @Nullable KeySlot pendingRsa3072
    ) {
        // Convenience accessors that unwrap the slot to the typed JWK. Provided
        // symmetrically for current, retired, and pending so callers never have to
        // mix `slot.jwk()` casts with `slotKey()` getters in the same expression.
        @NotNull RSAKey rsaKey() { return (RSAKey) rsa.jwk(); }
        @Nullable RSAKey retiredRsaKey() { return retiredRsa == null ? null : (RSAKey) retiredRsa.jwk(); }
        @Nullable RSAKey pendingRsaKey() { return pendingRsa == null ? null : (RSAKey) pendingRsa.jwk(); }
        @NotNull ECKey ecKey() { return (ECKey) ec.jwk(); }
        @Nullable ECKey retiredEcKey() { return retiredEc == null ? null : (ECKey) retiredEc.jwk(); }
        @Nullable ECKey pendingEcKey() { return pendingEc == null ? null : (ECKey) pendingEc.jwk(); }
        @NotNull RSAKey rsa3072Key() { return (RSAKey) rsa3072.jwk(); }
        @Nullable RSAKey retiredRsa3072Key() { return retiredRsa3072 == null ? null : (RSAKey) retiredRsa3072.jwk(); }
        @Nullable RSAKey pendingRsa3072Key() { return pendingRsa3072 == null ? null : (RSAKey) pendingRsa3072.jwk(); }

        boolean hasAnyPending() {
            return pendingRsa != null || pendingEc != null || pendingRsa3072 != null;
        }
    }

    private final File keyDirectory;
    private final Encryption encryption;
    private final Clock clock;
    private final OidcSettingsManager oidcSettingsManager;

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
        this(serverPaths, encryption, Clock.systemUTC());
    }

    /** Package-private — for tests that need a controllable clock. */
    JwtKeyManager(@NotNull final ServerPaths serverPaths,
                  @NotNull final Encryption encryption,
                  @NotNull final Clock clock) {
        this.encryption = encryption;
        this.clock = clock;
        this.keyDirectory = new File(serverPaths.getPluginDataDirectory(), "JwtBuildFeature");
        if (!this.keyDirectory.exists() && !this.keyDirectory.mkdirs())
            throw new RuntimeException("Failed to create key directory");
        this.oidcSettingsManager = new OidcSettingsManager(this.keyDirectory);
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

    /** Spring factory-method: returns the internal {@link OidcSettingsManager} for this key directory. */
    public OidcSettingsManager getOidcSettingsManager() {
        return oidcSettingsManager;
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
    /** Package-private — for tests only. */
    @Nullable KeySlot getRsaPendingSlot() { return requireReady().pendingRsa(); }
    /** Package-private — for tests only. */
    @Nullable KeySlot getEcPendingSlot() { return requireReady().pendingEc(); }
    /** Package-private — for tests only. */
    @Nullable KeySlot getRsa3072PendingSlot() { return requireReady().pendingRsa3072(); }

    /**
     * Returns the activateAt of any in-flight pending warmup, or {@code null} if no
     * warmup is in progress. All three algorithms share the same activateAt (they're
     * rotated together), so we just return the RSA one.
     */
    @Nullable
    public Instant getPendingActivateAt() {
        final var k = requireReady();
        return k.pendingRsa() == null ? null : k.pendingRsa().activateAt();
    }

    public boolean hasPending() {
        return requireReady().hasAnyPending();
    }

    public @NotNull List<JWK> getPublicKeys() {
        final var snapshot = requireReady();
        final List<JWK> result = new ArrayList<>();
        result.add(snapshot.rsaKey().toPublicJWK());
        if (snapshot.retiredRsaKey() != null) result.add(snapshot.retiredRsaKey().toPublicJWK());
        if (snapshot.pendingRsaKey() != null) result.add(snapshot.pendingRsaKey().toPublicJWK());
        result.add(snapshot.rsa3072Key().toPublicJWK());
        if (snapshot.retiredRsa3072Key() != null) result.add(snapshot.retiredRsa3072Key().toPublicJWK());
        if (snapshot.pendingRsa3072Key() != null) result.add(snapshot.pendingRsa3072Key().toPublicJWK());
        result.add(snapshot.ecKey().toPublicJWK());
        if (snapshot.retiredEcKey() != null) result.add(snapshot.retiredEcKey().toPublicJWK());
        if (snapshot.pendingEcKey() != null) result.add(snapshot.pendingEcKey().toPublicJWK());
        return Collections.unmodifiableList(result);
    }

    public synchronized void rotateKey()
            throws JOSEException, IOException, PendingRotationInProgressException {
        final var current = requireReady();
        if (current.hasAnyPending()) {
            // Why reject rather than replace: silently discarding the previous pending
            // key would let a misclicked "Rotate Now" or an overlapping cron tick wipe
            // out an in-flight warmup the admin chose deliberately. Surfacing the
            // collision as an exception lets the caller respond appropriately (controller
            // returns 409; scheduler logs and skips).
            final var firstPending = current.pendingRsa() != null ? current.pendingRsa()
                    : current.pendingEc() != null ? current.pendingEc()
                    : current.pendingRsa3072();
            throw new PendingRotationInProgressException(firstPending.activateAt());
        }

        final var settings = oidcSettingsManager.load();
        final var activateAt = clock.instant().plus(
                Duration.ofMinutes(settings.jwksCacheLifetimeMinutes()));

        // Generate all new keys before touching the filesystem so a key-generation
        // failure leaves the current keys intact.
        final var newRsa = generateFreshRsaKey();
        final var newRsa3072 = generateFreshRsa3072Key();
        final var newEc = generateFreshEcKey();

        // Write new keys to pending files then rename atomically so no reader ever sees
        // a partially-written key file, even if the JVM is killed mid-rotation.
        saveKeyToFile(newRsa, "pending-rsa-key.json", activateAt);
        saveKeyToFile(newRsa3072, "pending-rsa3072-key.json", activateAt);
        saveKeyToFile(newEc, "pending-ec-key.json", activateAt);

        keys.set(new KeyMaterial(
                current.rsa(),     current.retiredRsa(),     new KeySlot(newRsa, activateAt),
                current.ec(),      current.retiredEc(),      new KeySlot(newEc, activateAt),
                current.rsa3072(), current.retiredRsa3072(), new KeySlot(newRsa3072, activateAt)));
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
        promotePendingIfDue();

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

    /**
     * If any algorithm has a pending slot whose activateAt is at or before now, atomically
     * promote it: pending becomes current, current becomes retired, the previously-retired
     * key is dropped. All three algorithms promote together (they were rotated together;
     * they share a single activateAt).
     *
     * <p>Why lazy-on-sign and not a scheduled task: the only thing that depends on the
     * promotion having happened is sign() itself. JWKS render is correct either way — it
     * just emits all non-null publics, which is the same set before and after promotion
     * with the exception of the dropped previously-retired key (which is fine to drop
     * lazily because the warmup window has by definition elapsed). No timer means no
     * persistence-on-restart concerns and no HA timer-ownership problems.
     *
     * <p>Why compare-and-swap rather than a synchronized method: synchronized would
     * serialise every sign() — and most sign() calls do nothing here, since promotion
     * only happens once per warmup. The compare-and-swap on AtomicReference is the
     * cheapest concurrency primitive that gets us the invariant "the promotion
     * happens exactly once, regardless of how many nodes race."
     */
    private void promotePendingIfDue() {
        while (true) {
            final var k = keys.get();
            if (k == null || !k.hasAnyPending()) return;
            if (k.pendingRsa() == null || k.pendingEc() == null || k.pendingRsa3072() == null) {
                throw new IllegalStateException(
                        "JWT plugin: inconsistent KeyMaterial — pending slots are not all-or-none "
                        + "(rsa=" + (k.pendingRsa() != null) + ", ec=" + (k.pendingEc() != null)
                        + ", rsa3072=" + (k.pendingRsa3072() != null) + "). "
                        + "Rotation always writes all three together; this state should be unreachable.");
            }
            final var now = clock.instant();
            if (!k.pendingRsa().isActiveAt(now)) return;

            final var promoted = new KeyMaterial(
                    k.pendingRsa(),     new KeySlot(k.rsaKey(),     k.rsa().activateAt()),     null,
                    k.pendingEc(),      new KeySlot(k.ecKey(),      k.ec().activateAt()),      null,
                    k.pendingRsa3072(), new KeySlot(k.rsa3072Key(), k.rsa3072().activateAt()), null);

            if (keys.compareAndSet(k, promoted)) {
                promoteOnDisk(promoted);
                return;
            }
            // Lost the compare-and-swap race; loop and re-read.
        }
    }

    /**
     * Mirror of the in-memory promotion on disk: rewrite the current key files with the
     * pending content, rewrite the retired files with the previously-current content,
     * delete the pending files. The on-disk update happens after the in-memory
     * compare-and-swap has succeeded, so concurrent JWKS reads on the same node see
     * the promoted state regardless of where the disk write is in flight.
     *
     * <p>The compare-and-swap in promotePendingIfDue() guarantees exactly one caller
     * wins and calls this method per rotation cycle, so no additional synchronization
     * is needed here.
     *
     * <p>Crash recovery: if the JVM dies between the in-memory compare-and-swap and
     * the last delete,
     * the next loadKeys() will see overlapping pending+current+retired files. Since the
     * pending's activateAt is in the past (we just promoted), the startup-time
     * promotePendingIfDue() will idempotently complete what we couldn't.
     */
    private void promoteOnDisk(@NotNull final KeyMaterial promoted) {
        try {
            saveKeyToFile(promoted.rsaKey(),     "rsa-key.json",     promoted.rsa().activateAt());
            saveKeyToFile(promoted.rsa3072Key(), "rsa3072-key.json", promoted.rsa3072().activateAt());
            saveKeyToFile(promoted.ecKey(),      "ec-key.json",      promoted.ec().activateAt());

            if (promoted.retiredRsaKey() != null)
                saveKeyToFile(promoted.retiredRsaKey(), "retired-rsa-key.json", promoted.retiredRsa().activateAt());
            if (promoted.retiredRsa3072Key() != null)
                saveKeyToFile(promoted.retiredRsa3072Key(), "retired-rsa3072-key.json", promoted.retiredRsa3072().activateAt());
            if (promoted.retiredEcKey() != null)
                saveKeyToFile(promoted.retiredEcKey(), "retired-ec-key.json", promoted.retiredEc().activateAt());

            deleteIfExists("pending-rsa-key.json");
            deleteIfExists("pending-ec-key.json");
            deleteIfExists("pending-rsa3072-key.json");

            // Match the lock taken by refreshIfStale() so reads observe the post-write value.
            synchronized (this) {
                lastLoadedMaxMtime = maxKeyFileMtime();
            }
        } catch (final IOException e) {
            LOG.log(Level.SEVERE, "JWT plugin: in-memory key promotion succeeded but on-disk "
                    + "update failed; next startup will reconcile", e);
        }
    }

    private void deleteIfExists(final String fileName) {
        final var f = new File(keyDirectory, fileName);
        try {
            Files.deleteIfExists(f.toPath());
        } catch (final IOException e) {
            LOG.log(Level.WARNING, "JWT plugin: failed to delete " + f, e);
        }
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
        final var rsa            = loadOrGenerate("rsa-key.json",             RSAKey.class, JwtKeyManager::generateFreshRsaKey);
        final var retiredRsa     = loadIfExists  ("retired-rsa-key.json",     RSAKey.class);
        final var pendingRsa     = loadIfExists  ("pending-rsa-key.json",     RSAKey.class);
        final var ec             = loadOrGenerate("ec-key.json",              ECKey.class,  JwtKeyManager::generateFreshEcKey);
        final var retiredEc      = loadIfExists  ("retired-ec-key.json",      ECKey.class);
        final var pendingEc      = loadIfExists  ("pending-ec-key.json",      ECKey.class);
        final var rsa3072        = loadOrGenerate("rsa3072-key.json",         RSAKey.class, JwtKeyManager::generateFreshRsa3072Key);
        final var retiredRsa3072 = loadIfExists  ("retired-rsa3072-key.json", RSAKey.class);
        final var pendingRsa3072 = loadIfExists  ("pending-rsa3072-key.json", RSAKey.class);

        keys.set(new KeyMaterial(
                new KeySlot(rsa.jwk(), rsa.activateAt()),
                retiredRsa == null ? null : new KeySlot(retiredRsa.jwk(), retiredRsa.activateAt()),
                pendingRsa == null ? null : new KeySlot(pendingRsa.jwk(), pendingRsa.activateAt()),
                new KeySlot(ec.jwk(), ec.activateAt()),
                retiredEc == null ? null : new KeySlot(retiredEc.jwk(), retiredEc.activateAt()),
                pendingEc == null ? null : new KeySlot(pendingEc.jwk(), pendingEc.activateAt()),
                new KeySlot(rsa3072.jwk(), rsa3072.activateAt()),
                retiredRsa3072 == null ? null : new KeySlot(retiredRsa3072.jwk(), retiredRsa3072.activateAt()),
                pendingRsa3072 == null ? null : new KeySlot(pendingRsa3072.jwk(), pendingRsa3072.activateAt())));
        lastLoadedMaxMtime = maxKeyFileMtime();
        LOG.info("JWT plugin: JwtKeyManager initialized, keys loaded from " + keyDirectory);

        // If the server was down longer than the warmup, or a previous shutdown crashed
        // mid-activation, the pending's activateAt is already in the past. Run the same
        // promotion logic the sign() path uses so we recover before serving any traffic.
        promotePendingIfDue();
    }

    /** Generates a freshly-keyed JWK. Lambda-friendly because RSAKey/ECKey generators throw JOSEException. */
    @FunctionalInterface
    private interface FreshKeyGenerator { JWK generate() throws JOSEException; }

    /**
     * If {@code fileName} exists in the key directory, load and return it (asserting the
     * parsed JWK matches {@code expectedType}). Otherwise generate a fresh key with
     * {@code generator}, save it to disk with {@code activateAt = clock.instant()}, and
     * return the new key. Used during initial install of the plugin.
     */
    private ParsedKey loadOrGenerate(@NotNull final String fileName,
                                     @NotNull final Class<? extends JWK> expectedType,
                                     @NotNull final FreshKeyGenerator generator)
            throws IOException, ParseException, JOSEException {
        final var existing = loadIfExists(fileName, expectedType);
        if (existing != null) return existing;
        final var keyFile = new File(keyDirectory, fileName);
        LOG.info("JWT plugin: generating new key to " + keyFile);
        final var newKey = generator.generate();
        final var now = clock.instant();
        saveKeyToFile(newKey, fileName, now);
        return new ParsedKey(newKey, now);
    }

    /**
     * Returns the parsed key from {@code fileName} if the file exists, or {@code null}
     * otherwise. Asserts the parsed JWK matches {@code expectedType}; mismatch throws.
     * Used for retired and pending key files, which are optional.
     */
    @Nullable
    private ParsedKey loadIfExists(@NotNull final String fileName,
                                   @NotNull final Class<? extends JWK> expectedType)
            throws IOException, ParseException {
        final var f = new File(keyDirectory, fileName);
        if (!f.exists()) return null;
        LOG.info("JWT plugin: reading " + fileName + " from " + f);
        final var parsed = parseKeyEnvelope(f);
        if (!expectedType.isInstance(parsed.jwk())) {
            throw new IOException("Expected " + expectedType.getSimpleName() + " in " + fileName);
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
     * Reads the on-disk envelope format: {@code {"jwk": ..., "activateAt": ISO-8601}}.
     * A missing {@code activateAt} loads as {@code Instant.EPOCH}, which the rest of the
     * manager treats as "eligible to sign right now."
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
        if (inner == null) {
            throw new IOException("Key file " + file.getName() + " is missing the 'jwk' envelope field");
        }
        final var activateAtRaw = obj.get("activateAt");
        final var activateAt = activateAtRaw instanceof final String s
                ? Instant.parse(s) : Instant.EPOCH;
        return new ParsedKey(JWK.parse(inner.toString()), activateAt);
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
