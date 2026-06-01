package com.octopus.teamcity.oidc.it;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.shaded.gson.JsonArray;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end integration tests: validates the plugin's OIDC endpoints over HTTP the same way a
 * cloud provider would. Containers, bring-up, and all server interaction come from
 * {@link SharedStack} / {@link TeamCityClient}; this class only sets the global root URL it needs
 * (its own mapped {@code http://localhost} URL, which its issuer assertions compare against).
 * <p>
 * Run with: mvn verify (from the project root, after mvn package).
 * Skipped by: mvn test (only failsafe/verify triggers these).
 */
public class JwtPluginIT {

    static String baseUrl;
    static TeamCityClient tc;
    static String superUserAuthHeader;

    @BeforeAll
    static void setup() throws Exception {
        SharedStack.ensureStarted();
        tc = SharedStack.teamCity();
        baseUrl = SharedStack.tcBaseUrl();
        superUserAuthHeader = tc.authHeader();

        dumpTcPluginLog();
        tc.setRootUrl(baseUrl);
    }

    private static void dumpTcPluginLog() throws Exception {
        final var result = SharedStack.teamcity().execInContainer(
                "sh", "-c",
                "grep -i 'jwt\\|oidc\\|error\\|exception\\|WellKnown\\|DelegatingFilter' " +
                "/opt/teamcity/logs/teamcity-server.log 2>/dev/null || echo '(no matching lines)'"
        );
        System.out.println("=== TC server log (jwt/oidc/error lines) ===");
        System.out.println(result.getStdout());
        if (!result.getStderr().isEmpty()) {
            System.out.println("STDERR: " + result.getStderr());
        }
        System.out.println("=== end TC server log ===");
    }

    // -------------------------------------------------------------------------
    // JWKS endpoint — /.well-known/jwks.json
    // -------------------------------------------------------------------------

    @Test
    void jwksEndpointIsPubliclyAccessibleWithoutAuthentication() throws Exception {
        /*
         * CRITICAL: cloud providers (GCP, AWS, Azure) fetch the JWKS without credentials.
         * If this test fails with 401 or a redirect, the plugin's JWKS endpoint is
         * auth-gated and OIDC federation will not work in production.
         *
         * Fix: configure TeamCity guest access for /.well-known/* paths, or implement
         * a RequestInterceptorAdapter that exempts these paths from auth.
         */
        final var response = tc.unauthenticatedGet("/.well-known/jwks.json");

        assertThat(response.statusCode())
                .as("JWKS endpoint must return 200 without authentication — " +
                    "cloud providers fetch it unauthenticated. " +
                    "Got %d. Body: %s", response.statusCode(), response.body())
                .isEqualTo(200);
    }

    @Test
    void jwksEndpointReturnsBothRsaAndEcPublicKeys() throws Exception {
        final var jwks = tc.fetchJwks();

        boolean hasRsa = false, hasEc = false;
        for (final var key : jwks.getKeys()) {
            if (key instanceof RSAKey) hasRsa = true;
            if (key instanceof ECKey) hasEc = true;
        }

        assertThat(hasRsa).as("JWKS must contain at least one RSA key (for RS256)").isTrue();
        assertThat(hasEc).as("JWKS must contain at least one EC key (for ES256)").isTrue();
    }

    @Test
    void jwksEndpointNeverExposesPrivateKeyMaterial() throws Exception {
        final var jwks = tc.fetchJwks();

        for (final var key : jwks.getKeys()) {
            assertThat(key.isPrivate())
                    .as("Key %s must not contain private key material", key.getKeyID())
                    .isFalse();
        }
    }

    @Test
    void jwksResponseHasCacheControlHeader() throws Exception {
        final var response = tc.unauthenticatedGet("/.well-known/jwks.json");

        assertThat(response.headers().firstValue("Cache-Control"))
                .isPresent()
                .hasValueSatisfying(v -> assertThat(v).contains("max-age=60"));
    }

    @Test
    void jwksKeyIdsAreThumbprints() throws Exception {
        final var jwks = tc.fetchJwks();

        for (final var key : jwks.getKeys()) {
            final var kid = key.getKeyID();
            final var expectedThumbprint = key.computeThumbprint().toString();
            assertThat(kid)
                    .as("kid for key %s should be its thumbprint", kid)
                    .isEqualTo(expectedThumbprint);
        }
    }

    // -------------------------------------------------------------------------
    // OIDC discovery endpoint — /.well-known/openid-configuration
    // -------------------------------------------------------------------------

    @Test
    void discoveryEndpointIsPubliclyAccessibleWithoutAuthentication() throws Exception {
        /*
         * CRITICAL: same requirement as the JWKS endpoint. Cloud providers fetch
         * the discovery document without credentials during OIDC provider setup.
         */
        final var response = tc.unauthenticatedGet("/.well-known/openid-configuration");

        assertThat(response.statusCode())
                .as("Discovery endpoint must return 200 without authentication. " +
                    "Got %d. Body: %s", response.statusCode(), response.body())
                .isEqualTo(200);
    }

    @Test
    void discoveryDocumentIssuerMatchesServerUrl() throws Exception {
        final var doc = fetchDiscoveryDocument();
        assertThat(doc.get("issuer").getAsString()).isEqualTo(baseUrl);
    }

    @Test
    void discoveryDocumentJwksUriPointsToWorkingJwksEndpoint() throws Exception {
        final var doc = fetchDiscoveryDocument();
        final var jwksUri = doc.get("jwks_uri").getAsString();

        // The URI advertised in the document must be publicly accessible and return a valid JWKS.
        // Fetch the literal advertised URI (an absolute URL) with a throwaway client.
        final var jwksResponse = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder().uri(URI.create(jwksUri)).GET().build(),
                HttpResponse.BodyHandlers.ofString()
        );
        assertThat(jwksResponse.statusCode())
                .as("jwks_uri must be publicly accessible — cloud providers fetch it unauthenticated. " +
                    "Got %d. Body: %s", jwksResponse.statusCode(), jwksResponse.body())
                .isEqualTo(200);

        JWKSet.parse(jwksResponse.body()); // throws ParseException if invalid
    }

    @Test
    void discoveryDocumentAdvertisesBothSigningAlgorithms() throws Exception {
        final var doc = fetchDiscoveryDocument();
        final var algs = toStringList(doc.get("id_token_signing_alg_values_supported").getAsJsonArray());

        assertThat(algs).contains("RS256", "ES256");
    }

    @Test
    void discoveryDocumentHasAllRequiredOidcFields() throws Exception {
        final var doc = fetchDiscoveryDocument();

        assertThat(doc.has("issuer")).as("issuer required").isTrue();
        assertThat(doc.has("jwks_uri")).as("jwks_uri required").isTrue();
        assertThat(doc.has("response_types_supported")).as("response_types_supported required").isTrue();
        assertThat(doc.has("subject_types_supported")).as("subject_types_supported required").isTrue();
        assertThat(doc.has("id_token_signing_alg_values_supported")).as("id_token_signing_alg_values_supported required").isTrue();
    }

    @Test
    void discoveryDocumentHasCacheControlHeader() throws Exception {
        final var response = tc.unauthenticatedGet("/.well-known/openid-configuration");

        assertThat(response.headers().firstValue("Cache-Control"))
                .isPresent()
                .hasValueSatisfying(v -> assertThat(v).contains("max-age=60"));
    }

    // -------------------------------------------------------------------------
    // Cross-endpoint: discovery document is consistent with JWKS
    // -------------------------------------------------------------------------

    @Test
    void discoveryDocumentJwksUriEndsWithJwksPath() throws Exception {
        final var doc = fetchDiscoveryDocument();
        final var jwksUri = doc.get("jwks_uri").getAsString();

        // Must end with the path the JWKS controller is registered on
        assertThat(jwksUri).endsWith("/.well-known/jwks.json");
    }

    @Test
    void discoveryIssuerHasNoTrailingSlash() throws Exception {
        // AWS and GCP compare the issuer claim character-for-character
        final var doc = fetchDiscoveryDocument();
        assertThat(doc.get("issuer").getAsString()).doesNotEndWith("/");
    }

    // -------------------------------------------------------------------------
    // Key rotation endpoint — /admin/jwtKeyRotate.html
    // -------------------------------------------------------------------------

    @Test
    void keyRotationEndpointRequiresPost() throws Exception {
        final var response = tc.authenticatedGet("/admin/jwtKeyRotate.html");
        // GET must be rejected
        assertThat(response.statusCode()).isEqualTo(405);
    }

    @Test
    void keyRotationEndpointRotatesKeysAndUpdatesJwks() throws Exception {
        // Capture current key IDs
        final var kidsBefore = tc.fetchJwks().getKeys().stream().map(JWK::getKeyID).toList();

        // Rotate
        final var rotateResponse = tc.adminFormPostRaw("/admin/jwtKeyRotate.html", "");
        assertThat(rotateResponse.statusCode()).isEqualTo(200);
        assertThat(rotateResponse.body()).contains("rotated");

        // New JWKS should have new keys; previously-active keys become retired (overlap window).
        // Previously-retired keys are evicted, so not all old kids will be present.
        final var kidsAfter = tc.fetchJwks().getKeys().stream().map(JWK::getKeyID).toList();

        // Some old keys must still be in JWKS (the ones that were active are now retired)
        final List<String> retained = new ArrayList<>(kidsAfter);
        retained.retainAll(kidsBefore);
        assertThat(retained)
                .as("Previously-active keys must remain in JWKS after rotation (overlap window for in-flight JWTs)")
                .isNotEmpty();

        // New keys must have been added
        final List<String> added = new ArrayList<>(kidsAfter);
        added.removeAll(kidsBefore);
        assertThat(added)
                .as("New active keys must be added by rotation")
                .isNotEmpty();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /** Fetches a public path without authentication, asserting a 200, and returns the body. */
    private String publicGet(final String path) throws Exception {
        final var response = tc.unauthenticatedGet(path);
        assertThat(response.statusCode())
                .as("GET %s returned unexpected status", path)
                .isEqualTo(200);
        return response.body();
    }

    private JsonObject fetchDiscoveryDocument() throws Exception {
        final var body = publicGet("/.well-known/openid-configuration");
        return JsonParser.parseString(body).getAsJsonObject();
    }

    private List<String> toStringList(final JsonArray array) {
        final List<String> result = new ArrayList<>();
        array.forEach(e -> result.add(e.getAsString()));
        return result;
    }
}
