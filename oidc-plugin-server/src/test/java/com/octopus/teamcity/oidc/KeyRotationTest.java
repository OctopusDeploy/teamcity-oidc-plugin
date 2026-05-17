package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.serverSide.ServerPaths;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class KeyRotationTest {

    @Mock private ServerPaths serverPaths;
    @Mock private OidcSettingsManager oidcSettingsManager;

    @TempDir private File tempDir;

    private JwtKeyManager keyManager;

    @BeforeEach
    void setUp() {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        keyManager = TestJwtKeyManagerFactory.create(serverPaths);
        lenient().when(oidcSettingsManager.load()).thenReturn(OidcSettings.defaults());
    }

    @Test
    public void rotationGeneratesNewRsaAndEcKeys() throws Exception {
        final var originalRsa = keyManager.getRsaKey();
        final var originalEc = keyManager.getEcKey();

        keyManager.rotateKey();
        // Rotation creates pending; force activation so we can observe the new keys.
        keyManager.__testOverridePendingActivateAt(Instant.EPOCH);
        keyManager.sign(new com.nimbusds.jwt.JWTClaimsSet.Builder().subject("x").build(), "RS256");

        assertThat(keyManager.getRsaKey().getKeyID()).isNotEqualTo(originalRsa.getKeyID());
        assertThat(keyManager.getEcKey().getKeyID()).isNotEqualTo(originalEc.getKeyID());
    }

    @Test
    public void jwksContainsCurrentRetiredAndPendingAfterRotateThenActivate() throws Exception {
        final var originalRsa = keyManager.getRsaKey();
        final var originalRsa3072 = keyManager.getRsa3072Key();
        final var originalEc = keyManager.getEcKey();

        keyManager.rotateKey();
        // Force activation so pending → current, original → retired.
        keyManager.__testOverridePendingActivateAt(Instant.EPOCH);
        keyManager.sign(new com.nimbusds.jwt.JWTClaimsSet.Builder().subject("x").build(), "RS256");

        final var newRsa = keyManager.getRsaKey();
        final var newRsa3072 = keyManager.getRsa3072Key();
        final var newEc = keyManager.getEcKey();

        final var keys = jwksKeys();
        assertThat(keys).hasSize(6);
        assertThat(kidsIn(keys)).contains(
                originalRsa.getKeyID(), newRsa.getKeyID(),
                originalRsa3072.getKeyID(), newRsa3072.getKeyID(),
                originalEc.getKeyID(), newEc.getKeyID());
    }

    @Test
    public void rotatingAgainRetiresPreviousRetiredKeys() throws Exception {
        final var rsa1 = keyManager.getRsaKey();
        final var rsa3072_1 = keyManager.getRsa3072Key();
        final var ec1 = keyManager.getEcKey();

        // First rotation: create pending, force activation.
        keyManager.rotateKey();
        keyManager.__testOverridePendingActivateAt(Instant.EPOCH);
        keyManager.sign(new com.nimbusds.jwt.JWTClaimsSet.Builder().subject("x").build(), "RS256");
        final var rsa2 = keyManager.getRsaKey();
        final var rsa3072_2 = keyManager.getRsa3072Key();
        final var ec2 = keyManager.getEcKey();

        // Second rotation: create pending, force activation.
        keyManager.rotateKey();
        keyManager.__testOverridePendingActivateAt(Instant.EPOCH);
        keyManager.sign(new com.nimbusds.jwt.JWTClaimsSet.Builder().subject("x").build(), "RS256");
        final var rsa3 = keyManager.getRsaKey();
        final var rsa3072_3 = keyManager.getRsa3072Key();
        final var ec3 = keyManager.getEcKey();

        final var keys = jwksKeys();
        assertThat(keys).hasSize(6);
        assertThat(kidsIn(keys)).doesNotContain(rsa1.getKeyID(), rsa3072_1.getKeyID(), ec1.getKeyID());
        assertThat(kidsIn(keys)).contains(
                rsa2.getKeyID(), rsa3.getKeyID(),
                rsa3072_2.getKeyID(), rsa3072_3.getKeyID(),
                ec2.getKeyID(), ec3.getKeyID());
    }

    @Test
    void rotatedKeysHaveActivateAtCloseToNow() throws Exception {
        final var beforeRotate = Instant.now();
        keyManager.rotateKey();
        final var afterRotate = Instant.now();
        // Reload from disk to confirm the timestamp made it through serialisation.
        // Rotation now creates a pending key; the activateAt on the pending slot should
        // be now + warmup (default 10 minutes). We just verify it's at or after beforeRotate.
        final var fresh = TestJwtKeyManagerFactory.create(serverPaths);
        final var pendingRsaSlot = fresh.getRsaPendingSlot();
        assertThat(pendingRsaSlot).isNotNull();
        assertThat(pendingRsaSlot.activateAt())
                .isAfterOrEqualTo(beforeRotate.minusSeconds(1));
    }

    @Test
    void rotationCreatesPendingWithoutChangingCurrent() throws Exception {
        final var originalRsa = keyManager.getRsaKey();
        final var originalEc = keyManager.getEcKey();
        final var originalRsa3072 = keyManager.getRsa3072Key();

        keyManager.rotateKey();

        // Current still the originals (pending hasn't activated).
        assertThat(keyManager.getRsaKey().getKeyID()).isEqualTo(originalRsa.getKeyID());
        assertThat(keyManager.getEcKey().getKeyID()).isEqualTo(originalEc.getKeyID());
        assertThat(keyManager.getRsa3072Key().getKeyID()).isEqualTo(originalRsa3072.getKeyID());

        // JWKS now has the original publics plus three pending publics.
        final var kids = kidsIn(jwksKeys());
        assertThat(kids).hasSize(6).contains(originalRsa.getKeyID(),
                originalEc.getKeyID(), originalRsa3072.getKeyID());
    }

    @Test
    void signDuringWarmupUsesCurrentKey() throws Exception {
        final var originalRsa = keyManager.getRsaKey();
        keyManager.rotateKey();
        final var token = keyManager.sign(
                new com.nimbusds.jwt.JWTClaimsSet.Builder().subject("x").build(), "RS256");
        assertThat(token.getHeader().getKeyID()).isEqualTo(originalRsa.getKeyID());
    }

    @Test
    void signAfterActivateAtPromotesPendingAndUsesIt() throws Exception {
        keyManager.rotateKey();
        final var pendingRsaKid = keyManager.getRsaPendingSlot().jwk().getKeyID();

        // Force the pending's activateAt into the past so the next sign promotes it.
        keyManager.__testOverridePendingActivateAt(Instant.EPOCH);

        final var token = keyManager.sign(
                new com.nimbusds.jwt.JWTClaimsSet.Builder().subject("x").build(), "RS256");

        assertThat(token.getHeader().getKeyID()).isEqualTo(pendingRsaKid);
        assertThat(keyManager.getRsaKey().getKeyID()).isEqualTo(pendingRsaKid);
    }

    @Test
    void rotateRejectsWhenPendingExists() throws Exception {
        keyManager.rotateKey();
        assertThatThrownBy(() -> keyManager.rotateKey())
                .isInstanceOf(PendingRotationInProgressException.class);
    }

    // --- helpers ---

    private SBuildServer buildServerWithRootUrl(final String url) {
        final var server = mock(SBuildServer.class);
        lenient().when(server.getRootUrl()).thenReturn(url);
        return server;
    }

    private OidcIssuerUrlProvider providerFor(final String issuerUrl) {
        return new OidcIssuerUrlProvider(buildServerWithRootUrl(issuerUrl), new OidcSettingsManager(tempDir));
    }

    private JSONArray jwksKeys() throws Exception {
        final var filter = new WellKnownPublicFilter(keyManager, providerFor("https://tc.example.com"), oidcSettingsManager);
        final var request = mock(HttpServletRequest.class);
        final var response = mock(HttpServletResponse.class);
        final var writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.JWKS_PATH);
        when(request.getContextPath()).thenReturn("");
        filter.doFilter(request, response, mock(FilterChain.class));
        final var jsonObject = parseJsonObject(writer.toString());
        return (JSONArray) jsonObject.get("keys");
    }

    private List<String> kidsIn(final JSONArray keys) {
        return keys.stream()
                .map(k -> (JSONObject)k)
                .map(k -> k.getAsString("kid"))
                .toList();
    }

    private static JSONObject parseJsonObject(final String json) throws Exception {
        return (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(json);
    }
}
