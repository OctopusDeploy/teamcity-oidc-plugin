package com.octopus.teamcity.oidc.it;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.shaded.gson.JsonArray;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * End-to-end integration tests: starts a real TeamCity server with the plugin installed,
 * then validates the OIDC endpoints over HTTP the same way a cloud provider would.
 *
 * Run with: mvn verify (from the project root, after mvn package)
 * Skipped by: mvn test  (only failsafe/verify triggers these)
 *
 * TeamCity startup takes 60–120 seconds; the container is shared across all tests in this class.
 */
@Testcontainers
public class JwtPluginIT {

    private static final int TC_PORT = 8111;
    private static final String TC_IMAGE = "jetbrains/teamcity-server:2025.11";

    /** Path produced by the build module's maven-assembly-plugin. */
    private static final Path PLUGIN_ZIP = Path.of(
            System.getProperty("project.basedir", "."),
            "../target/teamcity-oidc-plugin.zip"
    ).normalize();

    @Container
    static final GenericContainer<?> teamcity = new GenericContainer<>(TC_IMAGE)
            .withExposedPorts(TC_PORT)
            /*
             * Disables the interactive "first start" confirmation screen added in TC 2023.11.
             * Without this flag TC blocks at 503 indefinitely waiting for an admin to visit
             * the web UI and confirm the data directory path.
             */
            .withEnv("TEAMCITY_SERVER_OPTS", "-Dteamcity.startup.maintenance=false")
            .withCopyFileToContainer(
                    MountableFile.forHostPath(PLUGIN_ZIP),
                    "/data/teamcity_server/datadir/plugins/teamcity-oidc-plugin.zip"
            )
            /*
             * Wait until TC's maintenance servlet is up (GET /mnt/ returns 200).
             * This is the earliest point at which we can accept the license agreement.
             * TC remains at 503 on the root until the agreement is accepted and plugins load.
             */
            .waitingFor(
                    Wait.forHttp("/mnt/")
                            .forStatusCode(200)
                            .withStartupTimeout(Duration.ofMinutes(5))
            );

    static String baseUrl;
    static HttpClient http;

    /** Basic-auth header for the TeamCity super user (empty username, token as password). */
    static String superUserAuthHeader;

    @BeforeAll
    static void setup() throws Exception {
        baseUrl = "http://localhost:" + teamcity.getMappedPort(TC_PORT);
        http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER) // surface redirects explicitly
                .connectTimeout(Duration.ofSeconds(10))
                .build();

        acceptLicenseAgreementIfRequired();
        waitForTcReady();

        String token = extractSuperUserTokenWithRetry();
        String encoded = Base64.getEncoder().encodeToString((":" + token).getBytes());
        superUserAuthHeader = "Basic " + encoded;

        configureServerRootUrl();
    }

    /**
     * TC 2025.11 requires accepting the license agreement before it will serve any requests.
     *
     * <p>The maintenance servlet ({@code /mnt/}) becomes available shortly after Tomcat starts,
     * but TC doesn't reach the license-agreement stage until a few seconds later. Sending the
     * acceptance too early races with TC's startup and the acceptance is lost. We wait until
     * TC logs the license stage before posting.</p>
     *
     * <p>Uses curl inside the container to avoid Java HttpClient cookie-handling quirks.</p>
     */
    private static void acceptLicenseAgreementIfRequired() throws Exception {
        // Wait until TC has logged the license-agreement stage, which means it is
        // now blocked and ready to process the acceptance.
        long deadline = System.currentTimeMillis() + Duration.ofMinutes(2).toMillis();
        while (System.currentTimeMillis() < deadline) {
            var result = teamcity.execInContainer(
                    "grep", "-q", "Review and accept TeamCity license agreement",
                    "/opt/teamcity/logs/teamcity-server.log"
            );
            if (result.getExitCode() == 0) break;
            TimeUnit.SECONDS.sleep(3);
        }

        // Accept the license via curl inside the container using the internal port.
        teamcity.execInContainer(
                "sh", "-c",
                "curl -sc /tmp/tc-cookies.txt http://localhost:8111/mnt/ > /dev/null && " +
                "curl -sb /tmp/tc-cookies.txt -X POST " +
                "http://localhost:8111/mnt/do/acceptLicenseAgreement"
        );
    }

    /**
     * Wait until TC transitions from 503 (loading / awaiting license) to 401 (ready).
     */
    private static void waitForTcReady() throws Exception {
        long deadline = System.currentTimeMillis() + Duration.ofMinutes(5).toMillis();
        while (System.currentTimeMillis() < deadline) {
            HttpResponse<String> r = http.send(
                    HttpRequest.newBuilder().uri(URI.create(baseUrl + "/")).GET().build(),
                    HttpResponse.BodyHandlers.ofString()
            );
            if (r.statusCode() == 401 || r.statusCode() == 200) {
                return;
            }
            TimeUnit.SECONDS.sleep(3);
        }
        throw new IllegalStateException("TeamCity did not become ready within 3 minutes");
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
        HttpResponse<String> response = get("/.well-known/jwks.json", null);

        assertThat(response.statusCode())
                .as("JWKS endpoint must return 200 without authentication — " +
                    "cloud providers fetch it unauthenticated. " +
                    "Got %d. Body: %s", response.statusCode(), response.body())
                .isEqualTo(200);
    }

    @Test
    void jwksEndpointReturnsBothRsaAndEcPublicKeys() throws Exception {
        String body = authenticatedGet("/.well-known/jwks.json");
        JWKSet jwks = JWKSet.parse(body);

        boolean hasRsa = false, hasEc = false;
        for (JWK key : jwks.getKeys()) {
            if (key instanceof RSAKey) hasRsa = true;
            if (key instanceof ECKey) hasEc = true;
        }

        assertThat(hasRsa).as("JWKS must contain at least one RSA key (for RS256)").isTrue();
        assertThat(hasEc).as("JWKS must contain at least one EC key (for ES256)").isTrue();
    }

    @Test
    void jwksEndpointNeverExposesPrivateKeyMaterial() throws Exception {
        String body = authenticatedGet("/.well-known/jwks.json");
        JWKSet jwks = JWKSet.parse(body);

        for (JWK key : jwks.getKeys()) {
            assertThat(key.isPrivate())
                    .as("Key %s must not contain private key material", key.getKeyID())
                    .isFalse();
        }
    }

    @Test
    void jwksResponseHasCacheControlHeader() throws Exception {
        HttpResponse<String> response = authenticatedGetWithHeaders("/.well-known/jwks.json");

        assertThat(response.headers().firstValue("Cache-Control"))
                .isPresent()
                .hasValueSatisfying(v -> assertThat(v).contains("max-age=300"));
    }

    @Test
    void jwksKeyIdsAreThumbprints() throws Exception {
        String body = authenticatedGet("/.well-known/jwks.json");
        JWKSet jwks = JWKSet.parse(body);

        for (JWK key : jwks.getKeys()) {
            String kid = key.getKeyID();
            String expectedThumbprint = key.computeThumbprint().toString();
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
        HttpResponse<String> response = get("/.well-known/openid-configuration", null);

        assertThat(response.statusCode())
                .as("Discovery endpoint must return 200 without authentication. " +
                    "Got %d. Body: %s", response.statusCode(), response.body())
                .isEqualTo(200);
    }

    @Test
    void discoveryDocumentIssuerMatchesServerUrl() throws Exception {
        JsonObject doc = fetchDiscoveryDocument();
        assertThat(doc.get("issuer").getAsString()).isEqualTo(baseUrl);
    }

    @Test
    void discoveryDocumentJwksUriPointsToWorkingJwksEndpoint() throws Exception {
        JsonObject doc = fetchDiscoveryDocument();
        String jwksUri = doc.get("jwks_uri").getAsString();

        // The URI in the document should resolve to a valid JWKS
        HttpResponse<String> jwksResponse = http.send(
                HttpRequest.newBuilder().uri(URI.create(jwksUri)).GET().build(),
                HttpResponse.BodyHandlers.ofString()
        );
        // Accept 200 (public) or 401 (auth required — also a bug, but separate from this test)
        assertThat(jwksResponse.statusCode())
                .as("jwks_uri must resolve to an endpoint that exists")
                .isIn(200, 401);

        // If accessible, it must parse as a valid JWKSet
        if (jwksResponse.statusCode() == 200) {
            JWKSet.parse(jwksResponse.body()); // throws ParseException if invalid
        }
    }

    @Test
    void discoveryDocumentAdvertisesBothSigningAlgorithms() throws Exception {
        JsonObject doc = fetchDiscoveryDocument();
        List<String> algs = toStringList(doc.get("id_token_signing_alg_values_supported").getAsJsonArray());

        assertThat(algs).contains("RS256", "ES256");
    }

    @Test
    void discoveryDocumentHasAllRequiredOidcFields() throws Exception {
        JsonObject doc = fetchDiscoveryDocument();

        assertThat(doc.has("issuer")).as("issuer required").isTrue();
        assertThat(doc.has("jwks_uri")).as("jwks_uri required").isTrue();
        assertThat(doc.has("response_types_supported")).as("response_types_supported required").isTrue();
        assertThat(doc.has("subject_types_supported")).as("subject_types_supported required").isTrue();
        assertThat(doc.has("id_token_signing_alg_values_supported")).as("id_token_signing_alg_values_supported required").isTrue();
    }

    @Test
    void discoveryDocumentHasCacheControlHeader() throws Exception {
        HttpResponse<String> response = authenticatedGetWithHeaders("/.well-known/openid-configuration");

        assertThat(response.headers().firstValue("Cache-Control"))
                .isPresent()
                .hasValueSatisfying(v -> assertThat(v).contains("max-age=300"));
    }

    // -------------------------------------------------------------------------
    // Cross-endpoint: discovery document is consistent with JWKS
    // -------------------------------------------------------------------------

    @Test
    void discoveryDocumentJwksUriEndsWithJwksPath() throws Exception {
        JsonObject doc = fetchDiscoveryDocument();
        String jwksUri = doc.get("jwks_uri").getAsString();

        // Must end with the path the JWKS controller is registered on
        assertThat(jwksUri).endsWith("/.well-known/jwks.json");
    }

    @Test
    void discoveryIssuerHasNoTrailingSlash() throws Exception {
        // AWS and GCP compare the issuer claim character-for-character
        JsonObject doc = fetchDiscoveryDocument();
        assertThat(doc.get("issuer").getAsString()).doesNotEndWith("/");
    }

    // -------------------------------------------------------------------------
    // Key rotation endpoint — /admin/jwtKeyRotate.html
    // -------------------------------------------------------------------------

    @Test
    void keyRotationEndpointRequiresPost() throws Exception {
        HttpResponse<String> response = get("/admin/jwtKeyRotate.html", superUserAuthHeader);
        // GET must be rejected
        assertThat(response.statusCode()).isEqualTo(405);
    }

    @Test
    void keyRotationEndpointRotatesKeysAndUpdatesJwks() throws Exception {
        // Capture current key IDs
        String jwksBefore = authenticatedGet("/.well-known/jwks.json");
        JWKSet setsBefore = JWKSet.parse(jwksBefore);
        List<String> kidsBefore = setsBefore.getKeys().stream().map(JWK::getKeyID).toList();

        // Rotate
        HttpResponse<String> rotateResponse = post("/admin/jwtKeyRotate.html", superUserAuthHeader);
        assertThat(rotateResponse.statusCode()).isEqualTo(200);
        assertThat(rotateResponse.body()).contains("rotated");

        // New JWKS should have new keys AND the old ones (rotation overlap window)
        String jwksAfter = authenticatedGet("/.well-known/jwks.json");
        JWKSet setsAfter = JWKSet.parse(jwksAfter);
        List<String> kidsAfter = setsAfter.getKeys().stream().map(JWK::getKeyID).toList();

        assertThat(kidsAfter).containsAll(kidsBefore); // old keys still present
        assertThat(kidsAfter.size()).isGreaterThan(kidsBefore.size()); // new keys added
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private HttpResponse<String> get(String path, String authHeader) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .GET();
        if (authHeader != null) {
            builder.header("Authorization", authHeader);
        }
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private String authenticatedGet(String path) throws Exception {
        HttpResponse<String> response = get(httpAuthPath(path), superUserAuthHeader);
        assertThat(response.statusCode())
                .as("Authenticated GET %s returned unexpected status", path)
                .isEqualTo(200);
        return response.body();
    }

    private HttpResponse<String> authenticatedGetWithHeaders(String path) throws Exception {
        return get(httpAuthPath(path), superUserAuthHeader);
    }

    private HttpResponse<String> post(String path, String authHeader) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + httpAuthPath(path)))
                .POST(HttpRequest.BodyPublishers.noBody());
        if (authHeader != null) {
            builder.header("Authorization", authHeader);
        }
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** Prefixes the path with /httpAuth/ so TeamCity processes Basic auth credentials. */
    private static String httpAuthPath(String path) {
        return "/httpAuth" + path;
    }

    private JsonObject fetchDiscoveryDocument() throws Exception {
        String body = authenticatedGet("/.well-known/openid-configuration");
        return JsonParser.parseString(body).getAsJsonObject();
    }

    private List<String> toStringList(JsonArray array) {
        List<String> result = new ArrayList<>();
        array.forEach(e -> result.add(e.getAsString()));
        return result;
    }

    /**
     * Updates TC's "Server URL" (root URL) to {@code baseUrl} via the admin settings form.
     * TC defaults to {@code http://localhost:8111} (its internal port); cloud providers and
     * OIDC verifiers need the externally-accessible URL so that the issuer in the discovery
     * document and JWT tokens is reachable.
     */
    private static void configureServerRootUrl() throws Exception {
        // Fetch the CSRF token from the global settings page.
        HttpResponse<String> page = http.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/httpAuth/admin/admin.html?item=serverConfigGeneral"))
                        .header("Authorization", superUserAuthHeader)
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString()
        );
        Matcher csrfMatcher = Pattern.compile("tc-csrf-token\" content=\"([^\"]+)\"").matcher(page.body());
        if (!csrfMatcher.find()) {
            throw new IllegalStateException("Could not find CSRF token on global settings page");
        }
        String csrf = csrfMatcher.group(1);

        // POST the new root URL.
        String form = "rootUrl=" + URI.create(baseUrl).toASCIIString().replace(":", "%3A").replace("/", "%2F")
                      + "&submitSettings=store&tc-csrf-token=" + csrf;
        http.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/httpAuth/admin/serverConfigGeneral.html"))
                        .header("Authorization", superUserAuthHeader)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(form))
                        .build(),
                HttpResponse.BodyHandlers.ofString()
        );
    }

    /**
     * TC writes the super user token to teamcity-server.log after plugins are fully loaded.
     * Retry for up to 60 seconds in case TC just finished accepting the license agreement
     * and hasn't written the token yet.
     */
    private static String extractSuperUserTokenWithRetry() throws Exception {
        long deadline = System.currentTimeMillis() + Duration.ofSeconds(60).toMillis();
        String lastError = "";
        while (System.currentTimeMillis() < deadline) {
            var result = teamcity.execInContainer(
                    "grep", "-o", "Super user authentication token: [0-9]*",
                    "/opt/teamcity/logs/teamcity-server.log"
            );
            String output = result.getStdout().trim();
            Matcher matcher = Pattern.compile("Super user authentication token: (\\d+)").matcher(output);
            if (matcher.find()) {
                return matcher.group(1);
            }
            lastError = "grep output: '" + output + "', stderr: '" + result.getStderr() + "'";
            TimeUnit.SECONDS.sleep(5);
        }
        throw new IllegalStateException(
                "TeamCity super user token not found in server log after 60s. " + lastError);
    }
}
