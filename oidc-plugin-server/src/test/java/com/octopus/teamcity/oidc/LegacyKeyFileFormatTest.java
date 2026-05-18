package com.octopus.teamcity.oidc;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import jetbrains.buildServer.serverSide.ServerPaths;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;

import static com.octopus.teamcity.oidc.OidcSettings.DEFAULT_JWKS_CACHE_LIFETIME_MINUTES;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LegacyKeyFileFormatTest {

    @Mock private ServerPaths serverPaths;
    @TempDir private File tempDir;

    @BeforeEach
    void setUp() {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
    }

    @Test
    void readsLegacyBareJwkFileAsActivateAtEpoch() throws Exception {
        // Pre-upgrade format: the key file is a bare JWK JSON (no envelope wrapper).
        final var dir = new File(tempDir, "JwtBuildFeature");
        dir.mkdirs();
        final var rsa = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256)
                .keyIDFromThumbprint(true).generate();
        final var encryption = TestJwtKeyManagerFactory.testEncryption();
        FileUtils.writeStringToFile(new File(dir, "rsa-key.json"),
                encryption.encrypt(rsa.toString()), StandardCharsets.UTF_8);

        final var manager = TestJwtKeyManagerFactory.create(serverPaths);

        // Same key by kid (no regeneration), with activateAt = EPOCH (legacy).
        assertThat(manager.getRsaKey().getKeyID()).isEqualTo(rsa.getKeyID());
        assertThat(manager.getRsaKeySlot().activateAt()).isEqualTo(Instant.EPOCH);
    }

    @Test
    void writesAndReadsEnvelopeFormatRoundTrip() throws Exception {
        final var clock = new TestJwtKeyManagerFactory.MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        final var manager = TestJwtKeyManagerFactory.create(serverPaths, clock);
        final var firstKid = manager.getRsaKey().getKeyID();
        manager.rotateKey();
        // Advance past the warmup window so the next sign() promotes pending to current.
        // The pending activateAt (2026-01-01T00:10:00Z) is after EPOCH, so the reloaded
        // key's activateAt will satisfy isAfter(Instant.EPOCH).
        clock.advanceBy(Duration.ofMinutes(DEFAULT_JWKS_CACHE_LIFETIME_MINUTES + 1));
        manager.sign(new com.nimbusds.jwt.JWTClaimsSet.Builder().subject("x").build(), "RS256");
        final var rotatedKid = manager.getRsaKey().getKeyID();
        assertThat(rotatedKid).isNotEqualTo(firstKid);

        // Reload via a fresh manager. After Task 6 the on-disk format is envelope; the
        // rotated key's activateAt is recent (not EPOCH).
        final var reloaded = TestJwtKeyManagerFactory.create(serverPaths);
        assertThat(reloaded.getRsaKey().getKeyID()).isEqualTo(rotatedKid);
        assertThat(reloaded.getRsaKeySlot().activateAt()).isAfter(Instant.EPOCH);
    }
}
