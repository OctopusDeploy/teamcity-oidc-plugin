package com.octopus.teamcity.oidc.it;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
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
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end integration test for key-rotation warmup behaviour.
 * <p>
 * Exercises the full pending-key lifecycle against a live TeamCity server:
 * <ol>
 *   <li>Set {@code jwksCacheLifetimeMinutes=1} so the warmup window is ~60 s.</li>
 *   <li>Capture the current signing kid from the public JWKS endpoint.</li>
 *   <li>Trigger rotation — assert JWKS immediately contains the pending public keys.</li>
 *   <li>Assert signing during warmup still uses the old (current) kid.</li>
 *   <li>Assert a second rotation during warmup is rejected with HTTP 409.</li>
 *   <li>Wait out the 1-minute warmup window.</li>
 *   <li>Trigger sign() (via the test-connection endpoint) to force lazy promotion.</li>
 *   <li>Assert the JWKS first key is now the formerly-pending kid.</li>
 *   <li>Assert a subsequent rotation succeeds (no longer blocked).</li>
 * </ol>
 * <p>
 * Notes on HTTPS and issuer URL:
 * {@code JwtTestController.stepJwt()} requires the issuer URL to use HTTPS. This test
 * sets the {@code overrideIssuerUrl} to a synthetic {@code https://} address before
 * calling the test-connection endpoint. The reachability check in
 * {@code OidcSettingsController} will warn but still persist the value, which is
 * sufficient for our purposes (we only need {@code sign()} to run, not the JWT to be
 * exchangeable with a real IdP).
 * <p>
 * Run with: {@code mvn verify -pl integration-tests -Dit.test=KeyRotationWarmupIT}
 * (point {@code JAVA_HOME} at a JDK 21 install first).
 * Build the plugin zip first: {@code mvn package -DskipTests}
 */
@Testcontainers
@Timeout(value = 7, unit = TimeUnit.MINUTES)
public class KeyRotationWarmupIT {

    private static final int TC_PORT = 8111;
    private static final String TC_IMAGE = "jetbrains/teamcity-server:2025.11";

    /**
     * Fake HTTPS issuer URL used to satisfy {@code JwtTestController}'s issuer-URL HTTPS check.
     * TC doesn't actually serve HTTPS here — we only need {@code sign()} to run to drive the
     * lazy-promotion path. The reachability check in OidcSettingsController will warn but
     * still save the value.
     */
    private static final String FAKE_HTTPS_ISSUER = "https://teamcity-local-it";

    private static final String PROJECT_ID = "WarmupTest";
    private static final String BUILD_TYPE_ID = "WarmupTest_Build";

    private static final Duration TC_READY_TIMEOUT = Duration.ofMinutes(5);
    private static final Duration LICENSE_ACCEPTANCE_TIMEOUT = Duration.ofMinutes(2);

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
        } catch (final java.io.IOException e) {
            throw new IllegalStateException("Could not list target directory: " + targetDir.toAbsolutePath(), e);
        }
    }

    @Container
    static final GenericContainer<?> teamcity = new GenericContainer<>(TC_IMAGE)
            .withExposedPorts(TC_PORT)
            .withEnv("TEAMCITY_SERVER_OPTS", "-Dteamcity.startup.maintenance=false")
            .withCopyFileToContainer(
                    MountableFile.forHostPath(PLUGIN_ZIP),
                    "/data/teamcity_server/datadir/plugins/" + PLUGIN_ZIP.getFileName()
            )
            .waitingFor(
                    Wait.forHttp("/mnt/")
                            .forStatusCode(200)
                            .withStartupTimeout(Duration.ofMinutes(5))
            );

    static String baseUrl;
    /**
     * Cookie-aware client — TC session cookies are required for CSRF-protected POST endpoints
     * (jwtKeyRotate.html, jwtOidcSettings.html, jwtTest.html).
     */
    static HttpClient http;
    /**
     * Stateless client for the TC REST API. Must NOT share the CookieManager from {@link #http}:
     * once a session cookie is established, TC treats REST API requests as cookie-authenticated
     * and enforces CSRF on them too. Using a separate client without a CookieManager avoids
     * this; Basic auth alone is sufficient for the REST API.
     */
    static HttpClient httpRest;
    static String superUserAuthHeader;
    /** CSRF token obtained once from the admin settings page and reused for all POSTs. */
    static String csrfToken;

    @BeforeAll
    static void setup() throws Exception {
        baseUrl = "http://" + teamcity.getHost() + ":" + teamcity.getMappedPort(TC_PORT);
        // CookieManager is essential: TC's admin endpoints (jwtKeyRotate.html,
        // jwtOidcSettings.html, jwtTest.html) check the CSRF token stored in the session
        // cookie alongside the tc-csrf-token form parameter.
        http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(10))
                .cookieHandler(new CookieManager())
                .build();
        // Stateless REST client — no CookieManager so TC doesn't enforce CSRF on REST calls.
        httpRest = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(10))
                .build();

        acceptLicenseAgreementIfRequired();
        waitForTcReady();

        final var token = extractSuperUserTokenWithRetry();
        superUserAuthHeader = "Basic " + Base64.getEncoder().encodeToString((":" + token).getBytes());

        fetchCsrfToken();
        createProjectAndBuildType();
    }

    // -------------------------------------------------------------------------
    // The test
    // -------------------------------------------------------------------------

    @Test
    void warmupDelaysNewKeyTakingOverSigning() throws Exception {
        // Step 1: set jwksCacheLifetimeMinutes=1 (1-minute warmup instead of the
        // 10-minute default) so the test can complete in ~75 s.
        postAdminForm("/admin/jwtOidcSettings.html", "jwksCacheLifetimeMinutes=1");

        // Step 2: set a fake HTTPS issuer URL override so JwtTestController.stepJwt()
        // passes its HTTPS scheme check when we call it later to trigger sign().
        // The save happens even when the reachability check warns (URL not reachable).
        postAdminForm("/admin/jwtOidcSettings.html",
                "overrideIssuerUrl=" + encode(FAKE_HTTPS_ISSUER));

        // Step 3: capture the current signing kid from the JWKS.
        // Before the first rotation there are exactly 3 keys (RSA-2048, RSA-3072, EC).
        // getPublicKeys() always puts the RSA-2048 current key first.
        final var jwksBefore = fetchJwks();
        final var currentRsaKid = rsaKidAt(jwksBefore, 0);
        assertThat(jwksBefore.getKeys()).as("JWKS before rotation").hasSize(3);

        // Step 4: trigger rotation.
        final var rotateBody = postAdminForm("/admin/jwtKeyRotate.html", "");
        assertThat(rotateBody.get("status")).as("rotation status").isEqualTo("rotated");
        assertThat(rotateBody).as("rotation response must contain activeAt").containsKey("activeAt");
        final var activeAt = Instant.parse((String) rotateBody.get("activeAt"));
        assertThat(activeAt)
                .as("activeAt must be in the future (warmup window not yet elapsed)")
                .isAfter(Instant.now());

        // Step 5: JWKS now contains current + pending publics — 6 keys total.
        // getPublicKeys() order (no retired on a fresh instance):
        //   [0] current RSA-2048  [1] pending RSA-2048
        //   [2] current RSA-3072  [3] pending RSA-3072
        //   [4] current EC        [5] pending EC
        final var jwksDuringWarmup = fetchJwks();
        assertThat(jwksDuringWarmup.getKeys())
                .as("JWKS during warmup must contain both current and pending keys")
                .hasSize(6);
        final var pendingRsaKid = rsaKidAt(jwksDuringWarmup, 1);
        assertThat(pendingRsaKid)
                .as("pending kid must differ from current kid")
                .isNotEqualTo(currentRsaKid);
        // Confirm the current kid is still at position 0 (signing has not yet promoted pending).
        assertThat(rsaKidAt(jwksDuringWarmup, 0))
                .as("current kid must still be at JWKS[0] during warmup")
                .isEqualTo(currentRsaKid);

        // Step 6: signing during warmup still uses currentRsaKid. We drive sign() via the
        // test-connection endpoint: POST step=jwt issues a JWT (which calls keyManager.sign()).
        // The JWT is stored server-side; the response confirms it was issued successfully.
        final var jwtDuringWarmup = postStepJwt();
        assertThat(jwtDuringWarmup.get("ok")).as("step=jwt during warmup").isEqualTo(true);

        // The JWKS first key must still be currentRsaKid — promotion has not happened
        // because the warmup window has not elapsed.
        assertThat(rsaKidAt(fetchJwks(), 0))
                .as("JWKS[0] must still be currentRsaKid during warmup")
                .isEqualTo(currentRsaKid);

        // Step 7: a second rotation during warmup must be rejected with 409.
        final var duringWarmupRotate = postAdminFormRaw("/admin/jwtKeyRotate.html", "");
        assertThat(duringWarmupRotate.statusCode())
                .as("rotation during warmup must return HTTP 409")
                .isEqualTo(409);
        final var warmupBody = parseJson(duringWarmupRotate.body());
        assertThat(warmupBody.get("status"))
                .as("409 body must report warmupInProgress")
                .isEqualTo("warmupInProgress");

        // Step 8: wait out the warmup window (activeAt + 5 s safety buffer).
        final var waitMs = Duration.between(Instant.now(), activeAt).toMillis() + 5_000L;
        if (waitMs > 0) {
            log("Waiting " + waitMs + " ms for warmup to elapse...");
            Thread.sleep(waitMs);
        }
        log("Warmup elapsed — triggering promotion via sign().");

        // Re-fetch the CSRF token after the 65-second sleep. TC may rotate the session
        // CSRF value between requests if the session is idle for an extended period.
        fetchCsrfToken();

        // Step 9: call step=jwt again to trigger sign() → promotePendingIfDue().
        // Now that activeAt is in the past, the pending key will be promoted to current.
        final var jwtAfterWarmup = postStepJwt();
        assertThat(jwtAfterWarmup.get("ok")).as("step=jwt after warmup").isEqualTo(true);

        // Step 10: the formerly-pending kid is now current — JWKS[0] must equal pendingRsaKid.
        // After promotion the layout is (retired is present now):
        //   [0] promoted RSA-2048 (formerly pending)  [1] retired RSA-2048 (formerly current)
        //   [2] promoted RSA-3072                      [3] retired RSA-3072
        //   [4] promoted EC                            [5] retired EC
        assertThat(rsaKidAt(fetchJwks(), 0))
                .as("After warmup, JWKS[0] must be the formerly-pending kid (promotion complete)")
                .isEqualTo(pendingRsaKid);

        // Step 11: a subsequent rotation must now succeed (pending was promoted; no warmup in
        // progress any more).
        final var afterPromotionRotate = postAdminFormRaw("/admin/jwtKeyRotate.html", "");
        assertThat(afterPromotionRotate.statusCode())
                .as("rotation after promotion must return HTTP 200")
                .isEqualTo(200);
        final var afterBody = parseJson(afterPromotionRotate.body());
        assertThat(afterBody.get("status"))
                .as("post-promotion rotation status must be rotated")
                .isEqualTo("rotated");
    }

    // -------------------------------------------------------------------------
    // Setup helpers
    // -------------------------------------------------------------------------

    private static void acceptLicenseAgreementIfRequired() throws Exception {
        final var deadline = System.currentTimeMillis() + LICENSE_ACCEPTANCE_TIMEOUT.toMillis();
        while (System.currentTimeMillis() < deadline) {
            final var result = teamcity.execInContainer(
                    "grep", "-q", "Review and accept TeamCity license agreement",
                    "/opt/teamcity/logs/teamcity-server.log"
            );
            if (result.getExitCode() == 0) break;
            TimeUnit.SECONDS.sleep(3);
        }
        teamcity.execInContainer(
                "sh", "-c",
                "curl -sc /tmp/tc-cookies.txt http://localhost:8111/mnt/ > /dev/null && " +
                "curl -sb /tmp/tc-cookies.txt -X POST " +
                "http://localhost:8111/mnt/do/acceptLicenseAgreement"
        );
    }

    private static void waitForTcReady() throws Exception {
        final var deadline = System.currentTimeMillis() + TC_READY_TIMEOUT.toMillis();
        while (System.currentTimeMillis() < deadline) {
            // Use httpRest (no CookieManager) — we don't want a session cookie from the root
            // redirect, which would later cause the REST API to enforce CSRF.
            final var r = httpRest.send(
                    HttpRequest.newBuilder().uri(URI.create(baseUrl + "/")).GET().build(),
                    HttpResponse.BodyHandlers.ofString()
            );
            if (r.statusCode() == 401 || r.statusCode() == 200) return;
            TimeUnit.SECONDS.sleep(3);
        }
        throw new IllegalStateException("TeamCity did not become ready within " + TC_READY_TIMEOUT.toMinutes() + " minutes");
    }

    private static String extractSuperUserTokenWithRetry() throws Exception {
        final var deadline = System.currentTimeMillis() + Duration.ofSeconds(60).toMillis();
        while (System.currentTimeMillis() < deadline) {
            final var result = teamcity.execInContainer(
                    "grep", "-o", "Super user authentication token: [0-9]*",
                    "/opt/teamcity/logs/teamcity-server.log"
            );
            final var matcher = Pattern.compile("Super user authentication token: (\\d+)")
                    .matcher(result.getStdout().trim());
            if (matcher.find()) return matcher.group(1);
            TimeUnit.SECONDS.sleep(5);
        }
        throw new IllegalStateException("TC super user token not found in server log after 60s");
    }

    /**
     * Fetches the CSRF token from the admin settings page and stores it in {@link #csrfToken}.
     * The token is bound to the HTTP session maintained by the {@link CookieManager}; it must
     * be resent in every CSRF-protected POST as the {@code tc-csrf-token} form parameter.
     */
    private static void fetchCsrfToken() throws Exception {
        final var page = http.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/httpAuth/admin/admin.html?item=serverConfigGeneral"))
                        .header("Authorization", superUserAuthHeader)
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString()
        );
        final var matcher = Pattern.compile("tc-csrf-token\" content=\"([^\"]+)\"").matcher(page.body());
        if (!matcher.find()) throw new IllegalStateException("CSRF token not found on admin page");
        csrfToken = matcher.group(1);
    }

    /**
     * Creates the project and build type used as the signing context for {@code step=jwt}.
     * JwtTestController requires a valid build type for which the calling user has
     * EDIT_PROJECT permission; the super-user satisfies this for any build type.
     */
    private static void createProjectAndBuildType() throws Exception {
        tcRestPost("/httpAuth/app/rest/projects",
                "{\"id\":\"" + PROJECT_ID + "\",\"name\":\"WarmupTest\",\"parentProject\":{\"id\":\"_Root\"}}");
        tcRestPost("/httpAuth/app/rest/buildTypes",
                "{\"id\":\"" + BUILD_TYPE_ID + "\",\"name\":\"WarmupTest Build\","
                + "\"project\":{\"id\":\"" + PROJECT_ID + "\"}}");
    }

    // -------------------------------------------------------------------------
    // Request helpers
    // -------------------------------------------------------------------------

    /**
     * POSTs a form body to a CSRF-protected admin endpoint and returns the parsed JSON response.
     * Passes the super-user auth header and the CSRF token automatically.
     */
    private static JSONObject postAdminForm(final String path, final String extraParams) throws Exception {
        final var response = postAdminFormRaw(path, extraParams);
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException(
                    "POST " + path + " returned " + response.statusCode() + ": " + response.body());
        }
        return parseJson(response.body());
    }

    private static HttpResponse<String> postAdminFormRaw(final String path,
                                                          final String extraParams) throws Exception {
        final var csrf = "tc-csrf-token=" + csrfToken;
        final var body = extraParams.isEmpty() ? csrf : extraParams + "&" + csrf;
        return http.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/httpAuth" + path))
                        .header("Authorization", superUserAuthHeader)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build(),
                HttpResponse.BodyHandlers.ofString()
        );
    }

    /**
     * Calls the test-connection endpoint with {@code step=jwt} to issue a signed JWT.
     * The JWT is stored in the server-side HTTP session; the response contains only an
     * {@code ok} flag and a {@code tokenRef}. The important side-effect is that
     * {@code JwtKeyManager.sign()} is called, which triggers {@code promotePendingIfDue()}
     * — the mechanism the warmup lifecycle relies on.
     */
    private static JSONObject postStepJwt() throws Exception {
        final var body = "step=jwt&algorithm=RS256"
                + "&buildTypeId=" + BUILD_TYPE_ID
                + "&tc-csrf-token=" + csrfToken;
        final var response = http.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/httpAuth/admin/jwtTest.html"))
                        .header("Authorization", superUserAuthHeader)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build(),
                HttpResponse.BodyHandlers.ofString()
        );
        if (response.statusCode() != 200) {
            throw new IllegalStateException(
                    "step=jwt returned " + response.statusCode() + ": " + response.body());
        }
        return parseJson(response.body());
    }

    private static void tcRestPost(final String path, final String json) throws Exception {
        // Use the stateless REST client — no session cookie, so TC doesn't require CSRF.
        final var response = httpRest.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + path))
                        .header("Authorization", superUserAuthHeader)
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(json))
                        .build(),
                HttpResponse.BodyHandlers.ofString()
        );
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException(
                    "TC REST POST " + path + " returned " + response.statusCode() + ": " + response.body());
        }
    }

    private static JWKSet fetchJwks() throws Exception {
        // Use httpRest (no CookieManager) — the JWKS endpoint is public and needs no session.
        final var response = httpRest.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/.well-known/jwks.json"))
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString()
        );
        if (response.statusCode() != 200) {
            throw new IllegalStateException("JWKS endpoint returned " + response.statusCode());
        }
        return JWKSet.parse(response.body());
    }

    /**
     * Returns the key-ID of the RSA-2048 key at the given position in the JWKS key list.
     * {@code getPublicKeys()} always places RSA keys (2048 and 3072) before EC keys, and
     * the RSA-2048 current key before the RSA-2048 pending key (when present). RSA-3072
     * keys are distinguishable by their larger modulus, but for this test we only need to
     * track RSA-2048 kids: position 0 is always current RSA-2048, position 1 (when present)
     * is always pending RSA-2048.
     */
    private static String rsaKidAt(final JWKSet jwks, final int positionAmongRsa2048Keys) {
        final var rsa2048Keys = jwks.getKeys().stream()
                .filter(k -> k instanceof RSAKey rsa && rsa.size() == 2048)
                .map(JWK::getKeyID)
                .toList();
        assertThat(rsa2048Keys)
                .as("JWKS must contain at least " + (positionAmongRsa2048Keys + 1) + " RSA-2048 key(s)")
                .hasSizeGreaterThan(positionAmongRsa2048Keys);
        return rsa2048Keys.get(positionAmongRsa2048Keys);
    }

    private static JSONObject parseJson(final String body) {
        try {
            return (JSONObject) new JSONParser(JSONParser.DEFAULT_PERMISSIVE_MODE).parse(body);
        } catch (final net.minidev.json.parser.ParseException e) {
            throw new IllegalStateException("Failed to parse JSON: " + body, e);
        }
    }

    private static String encode(final String value) {
        return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
    }

    private static void log(final String msg) {
        System.out.println("[KeyRotationWarmupIT] " + java.time.LocalTime.now() + " " + msg);
    }
}
