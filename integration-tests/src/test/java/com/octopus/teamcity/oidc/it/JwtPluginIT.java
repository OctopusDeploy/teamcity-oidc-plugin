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
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end integration tests: validates the plugin's OIDC endpoints over HTTP the same way a
 * cloud provider would. Containers and the one-time bring-up live in {@link SharedStack}; this
 * class only sets the global server root URL it needs (its own mapped {@code http://localhost}
 * URL, which its issuer assertions compare against) before running.
 * <p>
 * Run with: mvn verify (from the project root, after mvn package).
 * Skipped by: mvn test (only failsafe/verify triggers these).
 */
public class JwtPluginIT {

    static String baseUrl;
    static TeamCityClient tc;
    static String superUserAuthHeader;

    /** Stateless client for the raw read-only GET helpers below. */
    static HttpClient http;

    @BeforeAll
    static void setup() throws Exception {
        SharedStack.ensureStarted();
        tc = SharedStack.teamCity();
        baseUrl = SharedStack.tcBaseUrl();
        superUserAuthHeader = tc.authHeader();
        http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(10))
                .build();

        dumpTcPluginLog();
        configureServerRootUrl();
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
        final var response = unauthenticatedGet("/.well-known/jwks.json");

        assertThat(response.statusCode())
                .as("JWKS endpoint must return 200 without authentication — " +
                    "cloud providers fetch it unauthenticated. " +
                    "Got %d. Body: %s", response.statusCode(), response.body())
                .isEqualTo(200);
    }

    @Test
    void jwksEndpointReturnsBothRsaAndEcPublicKeys() throws Exception {
        final var body = publicGet("/.well-known/jwks.json");
        final var jwks = JWKSet.parse(body);

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
        final var body = publicGet("/.well-known/jwks.json");
        final var jwks = JWKSet.parse(body);

        for (final var key : jwks.getKeys()) {
            assertThat(key.isPrivate())
                    .as("Key %s must not contain private key material", key.getKeyID())
                    .isFalse();
        }
    }

    @Test
    void jwksResponseHasCacheControlHeader() throws Exception {
        final var response = publicGetWithHeaders("/.well-known/jwks.json");

        assertThat(response.headers().firstValue("Cache-Control"))
                .isPresent()
                .hasValueSatisfying(v -> assertThat(v).contains("max-age=60"));
    }

    @Test
    void jwksKeyIdsAreThumbprints() throws Exception {
        final var body = publicGet("/.well-known/jwks.json");
        final var jwks = JWKSet.parse(body);

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
        final var response = unauthenticatedGet("/.well-known/openid-configuration");

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

        // The URI in the document must be publicly accessible and return a valid JWKS
        final var jwksResponse = http.send(
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
        final var response = publicGetWithHeaders("/.well-known/openid-configuration");

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
        final var response = authenticatedGet("/admin/jwtKeyRotate.html", superUserAuthHeader);
        // GET must be rejected
        assertThat(response.statusCode()).isEqualTo(405);
    }

    @Test
    void keyRotationEndpointRotatesKeysAndUpdatesJwks() throws Exception {
        // Capture current key IDs
        final var jwksBefore = publicGet("/.well-known/jwks.json");
        final var setsBefore = JWKSet.parse(jwksBefore);
        final var kidsBefore = setsBefore.getKeys().stream().map(JWK::getKeyID).toList();

        // Rotate
        final var rotateResponse = tc.adminFormPostRaw("/admin/jwtKeyRotate.html", "");
        assertThat(rotateResponse.statusCode()).isEqualTo(200);
        assertThat(rotateResponse.body()).contains("rotated");

        // New JWKS should have new keys; previously-active keys become retired (overlap window).
        // Previously-retired keys are evicted, so not all old kids will be present.
        final var jwksAfter = publicGet("/.well-known/jwks.json");
        final var setsAfter = JWKSet.parse(jwksAfter);
        final var kidsAfter = setsAfter.getKeys().stream().map(JWK::getKeyID).toList();

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

    private HttpResponse<String> unauthenticatedGet(final String path) throws Exception {
        final var builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .GET();
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** GETs via /httpAuth/ so TeamCity processes Basic auth credentials. */
    private HttpResponse<String> authenticatedGet(final String path, final String authHeader) throws Exception {
        final var builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + httpAuthPath(path)))
                .GET();
        builder.header("Authorization", authHeader);
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** Prefixes the path with /httpAuth/ so TeamCity processes Basic auth credentials. */
    private static String httpAuthPath(final String path) {
        return "/httpAuth" + path;
    }

    /** Fetches a public path without authentication or /httpAuth/ prefix. */
    private String publicGet(final String path) throws Exception {
        final var response = unauthenticatedGet(path);
        assertThat(response.statusCode())
                .as("GET %s returned unexpected status", path)
                .isEqualTo(200);
        return response.body();
    }

    /** Fetches a public path without auth, returning the full response for header inspection. */
    private HttpResponse<String> publicGetWithHeaders(final String path) throws Exception {
        return unauthenticatedGet(path);
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

    /**
     * Updates TC's "Server URL" (root URL) to {@code baseUrl} via the admin settings form, then
     * waits for the change to propagate. TC defaults to {@code http://localhost:8111} (its internal
     * port); cloud providers and OIDC verifiers need the externally-accessible URL so the issuer in
     * the discovery document and JWT tokens is reachable. The propagation wait matters on the shared
     * server: another IT class may have set a different root URL, and the discovery issuer is read
     * live from {@code getRootUrl()}.
     */
    private static void configureServerRootUrl() throws Exception {
        final var encoded = URI.create(baseUrl).toASCIIString().replace(":", "%3A").replace("/", "%2F");
        // serverConfigGeneral.html is TC's built-in settings form — it returns HTML, not JSON, so
        // use the raw POST (adminFormPost would try to parse the body as JSON).
        final var resp = tc.adminFormPostRaw("/admin/serverConfigGeneral.html", "rootUrl=" + encoded + "&submitSettings=store");
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            throw new IllegalStateException("TC root URL POST returned " + resp.statusCode() + ": " + resp.body());
        }

        final var deadline = System.currentTimeMillis() + Duration.ofMinutes(1).toMillis();
        while (System.currentTimeMillis() < deadline) {
            final var webUrl = (String) Json.parse(tc.get("/httpAuth/app/rest/server")).get("webUrl");
            if (baseUrl.equals(webUrl)) return;
            TimeUnit.SECONDS.sleep(2);
        }
        throw new IllegalStateException("TC root URL did not update to " + baseUrl + " within 1 minute");
    }
}
