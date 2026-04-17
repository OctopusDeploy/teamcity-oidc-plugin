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
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import java.net.CookieManager;
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
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end integration tests: starts a real TeamCity server with the plugin installed,
 * then validates the OIDC endpoints over HTTP the same way a cloud provider would.
 * Run with: mvn verify (from the project root, after mvn package)
 * Skipped by: mvn test  (only failsafe/verify triggers these)
 * TeamCity startup takes 60–120 seconds; the container is shared across all tests in this class.
 */
@Testcontainers
public class JwtPluginIT {

    private static final int TC_PORT = 8111;
    private static final String TC_IMAGE = "jetbrains/teamcity-server:2025.11";

    private static final Duration TC_READY_TIMEOUT = Duration.ofMinutes(5);
    private static final Duration LICENSE_ACCEPTANCE_TIMEOUT = Duration.ofMinutes(2);

    /** Path produced by the build module's maven-assembly-plugin. */
    private static final Path PLUGIN_ZIP = requirePluginZip();

    private static Path requirePluginZip() {
        final var targetDir = Path.of(
                System.getProperty("project.basedir", "."),
                "../target/"
        ).normalize();
        try (var stream = java.nio.file.Files.list(targetDir)) {
            return stream
                    .filter(p -> p.getFileName().toString().matches("Octopus\\.TeamCity\\.OIDC\\..*\\.zip"))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException(
                            "Plugin zip not found in: " + targetDir.toAbsolutePath() +
                            "\nRun 'mvn package -DskipTests' from the project root first."));
        } catch (java.io.IOException e) {
            throw new IllegalStateException("Could not list target directory: " + targetDir.toAbsolutePath(), e);
        }
    }

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
                    "/data/teamcity_server/datadir/plugins/" + PLUGIN_ZIP.getFileName()
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

    /** Basic-auth header for the TeamCity superuser (empty username, token as password). */
    static String superUserAuthHeader;

    /** TC CSRF token, fetched once during setup and reused for all POST requests. */
    static String csrfToken;

    @BeforeAll
    static void setup() throws Exception {
        baseUrl = "http://" + teamcity.getHost() + ":" + teamcity.getMappedPort(TC_PORT);
        http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER) // surface redirects explicitly
                .connectTimeout(Duration.ofSeconds(10))
                .cookieHandler(new CookieManager()) // maintain session cookies so CSRF tokens stay valid
                .build();

        acceptLicenseAgreementIfRequired();
        waitForTcReady();
        dumpTcPluginLog();

        final var token = extractSuperUserTokenWithRetry();
        final var encoded = Base64.getEncoder().encodeToString((":" + token).getBytes());
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
        final var deadline = System.currentTimeMillis() + LICENSE_ACCEPTANCE_TIMEOUT.toMillis();
        while (System.currentTimeMillis() < deadline) {
            final var result = teamcity.execInContainer(
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
        final var deadline = System.currentTimeMillis() + TC_READY_TIMEOUT.toMillis();
        while (System.currentTimeMillis() < deadline) {
            final var r = http.send(
                    HttpRequest.newBuilder().uri(URI.create(baseUrl + "/")).GET().build(),
                    HttpResponse.BodyHandlers.ofString()
            );
            if (r.statusCode() == 401 || r.statusCode() == 200) {
                return;
            }
            TimeUnit.SECONDS.sleep(3);
        }
        throw new IllegalStateException("TeamCity did not become ready within " + TC_READY_TIMEOUT.toMinutes() + " minutes");
    }

    private static void dumpTcPluginLog() throws Exception {
        final var result = teamcity.execInContainer(
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
        final var rotateResponse = post("/admin/jwtKeyRotate.html", superUserAuthHeader);
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

    private HttpResponse<String> post(final String path, final String authHeader) throws Exception {
        final var body = csrfToken != null ? "tc-csrf-token=" + csrfToken : "";
        final var builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + httpAuthPath(path)))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body));
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
     * Updates TC's "Server URL" (root URL) to {@code baseUrl} via the admin settings form.
     * TC defaults to {@code http://localhost:8111} (its internal port); cloud providers and
     * OIDC verifiers need the externally-accessible URL so that the issuer in the discovery
     * document and JWT tokens is reachable.
     */
    private static void configureServerRootUrl() throws Exception {
        // Fetch the CSRF token from the global settings page.
        final var page = http.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/httpAuth/admin/admin.html?item=serverConfigGeneral"))
                        .header("Authorization", superUserAuthHeader)
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString()
        );
        final var csrfMatcher = Pattern.compile("tc-csrf-token\" content=\"([^\"]+)\"").matcher(page.body());
        if (!csrfMatcher.find()) {
            throw new IllegalStateException("Could not find CSRF token on global settings page");
        }
        final var csrf = csrfMatcher.group(1);
        csrfToken = csrf;

        // POST the new root URL.
        final var form = "rootUrl=" + URI.create(baseUrl).toASCIIString().replace(":", "%3A").replace("/", "%2F")
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
     * TC writes the superuser token to teamcity-server.log after plugins are fully loaded.
     * Retry for up to 60 seconds in case TC just finished accepting the license agreement
     * and hasn't written the token yet.
     */
    private static String extractSuperUserTokenWithRetry() throws Exception {
        final var deadline = System.currentTimeMillis() + Duration.ofSeconds(60).toMillis();
        var lastError = "";
        while (System.currentTimeMillis() < deadline) {
            final var result = teamcity.execInContainer(
                    "grep", "-o", "Super user authentication token: [0-9]*",
                    "/opt/teamcity/logs/teamcity-server.log"
            );
            final var output = result.getStdout().trim();
            final var matcher = Pattern.compile("Super user authentication token: (\\d+)").matcher(output);
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
