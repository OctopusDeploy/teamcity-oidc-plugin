package com.octopus.teamcity.oidc.it;

import net.minidev.json.JSONObject;
import org.testcontainers.containers.GenericContainer;

import java.net.CookieManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Talks to a single running TeamCity server: REST API calls, public (unauthenticated) endpoint
 * GETs, and CSRF-protected admin form POSTs. Also owns the one-time bring-up sequence
 * (accept license -> wait ready -> extract super-user token -> fetch CSRF token) that every
 * integration test needs before it can drive the server.
 * <p>
 * Two HTTP clients are kept deliberately separate:
 * <ul>
 *   <li>{@link #rest} — no {@link CookieManager}. Used for the REST API. Once TC sees a session
 *       cookie it starts enforcing CSRF on REST calls too, so this client must stay stateless;
 *       Basic auth alone is sufficient for the REST API.</li>
 *   <li>{@link #form} — cookie-aware. TC's admin endpoints (jwtKeyRotate.html, jwtOidcSettings.html,
 *       jwtTest.html, serverConfigGeneral.html) validate the CSRF token stored in the session
 *       cookie alongside the {@code tc-csrf-token} form parameter.</li>
 * </ul>
 */
final class TeamCityClient {

    private static final Duration READY_TIMEOUT = Duration.ofMinutes(5);
    private static final Duration LICENSE_TIMEOUT = Duration.ofMinutes(2);
    private static final Duration TOKEN_TIMEOUT = Duration.ofSeconds(60);

    private final HttpClient rest;
    private final HttpClient form;
    private final String baseUrl;
    private final String authHeader;
    private final String superUserToken;
    private String csrfToken;

    private TeamCityClient(final HttpClient rest, final HttpClient form, final String baseUrl,
                           final String authHeader, final String superUserToken) {
        this.rest = rest;
        this.form = form;
        this.baseUrl = baseUrl;
        this.authHeader = authHeader;
        this.superUserToken = superUserToken;
    }

    /**
     * Brings a freshly-started TeamCity container to a ready, authenticated state and returns a
     * client wired to it. {@code baseUrl} is the host-reachable {@code http://host:port} for the
     * container's mapped TC port.
     */
    static TeamCityClient bringUp(final GenericContainer<?> teamcity, final String baseUrl) throws Exception {
        final var rest = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        final var form = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(10))
                .cookieHandler(new CookieManager())
                .build();

        acceptLicenseAgreementIfRequired(teamcity);
        waitForTcReady(rest, baseUrl);
        final var token = extractSuperUserTokenWithRetry(teamcity);
        final var authHeader = "Basic " + Base64.getEncoder().encodeToString((":" + token).getBytes());

        final var client = new TeamCityClient(rest, form, baseUrl, authHeader, token);
        client.refreshCsrf();
        return client;
    }

    String baseUrl() {
        return baseUrl;
    }

    String authHeader() {
        return authHeader;
    }

    String superUserToken() {
        return superUserToken;
    }

    String csrfToken() {
        return csrfToken;
    }

    // -------------------------------------------------------------------------
    // REST API (stateless client, Basic auth)
    // -------------------------------------------------------------------------

    /** GETs a REST path (caller includes the {@code /httpAuth} prefix). Returns the body. */
    String get(final String path) throws Exception {
        final var response = rest.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + path))
                        .header("Authorization", authHeader)
                        .header("Accept", "application/json")
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());
        requireSuccess("GET", path, response);
        return response.body();
    }

    /** POSTs JSON to a REST path (caller includes the {@code /httpAuth} prefix). Returns the body. */
    String post(final String path, final String json) throws Exception {
        final var response = rest.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + path))
                        .header("Authorization", authHeader)
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(json))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        requireSuccess("POST", path, response);
        return response.body();
    }

    /** PUTs a plain-text body to a REST path (caller includes the {@code /httpAuth} prefix). */
    void put(final String path, final String textBody) throws Exception {
        final var response = rest.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + path))
                        .header("Authorization", authHeader)
                        .header("Content-Type", "text/plain")
                        .PUT(HttpRequest.BodyPublishers.ofString(textBody))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        requireSuccess("PUT", path, response);
    }

    /** DELETEs a REST path (caller includes the {@code /httpAuth} prefix). */
    void delete(final String path) throws Exception {
        final var response = rest.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + path))
                        .header("Authorization", authHeader)
                        .DELETE().build(),
                HttpResponse.BodyHandlers.ofString());
        requireSuccess("DELETE", path, response);
    }

    // -------------------------------------------------------------------------
    // Public endpoints (no auth, no /httpAuth prefix)
    // -------------------------------------------------------------------------

    /** GETs a public path with no authentication, returning the full response. */
    HttpResponse<String> unauthenticatedGet(final String path) throws Exception {
        return rest.send(
                HttpRequest.newBuilder().uri(URI.create(baseUrl + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    // -------------------------------------------------------------------------
    // CSRF-protected admin form POSTs (cookie-aware client)
    // -------------------------------------------------------------------------

    /** Re-reads the CSRF token from the admin settings page. TC may rotate it during idle windows. */
    void refreshCsrf() throws Exception {
        final var page = form.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/httpAuth/admin/admin.html?item=serverConfigGeneral"))
                        .header("Authorization", authHeader)
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());
        final var matcher = Pattern.compile("tc-csrf-token\" content=\"([^\"]+)\"").matcher(page.body());
        if (!matcher.find()) {
            throw new IllegalStateException("CSRF token not found on admin settings page");
        }
        csrfToken = matcher.group(1);
    }

    /**
     * POSTs a form body to a CSRF-protected admin endpoint (caller passes the path without the
     * {@code /httpAuth} prefix, e.g. {@code /admin/jwtKeyRotate.html}). The CSRF token is appended
     * automatically. Returns the raw response so callers can assert on non-2xx status codes.
     */
    HttpResponse<String> adminFormPostRaw(final String path, final String extraParams) throws Exception {
        var response = sendAdminForm(path, extraParams);
        // The session CSRF token rotates during idle periods, and the shared server is long-lived
        // (one class's bring-up token is stale by the time a later class POSTs). A 403 here means
        // the cached token no longer matches the session — re-scrape it and retry once.
        if (response.statusCode() == 403 && response.body().contains("CSRF")) {
            refreshCsrf();
            response = sendAdminForm(path, extraParams);
        }
        return response;
    }

    private HttpResponse<String> sendAdminForm(final String path, final String extraParams) throws Exception {
        final var csrf = "tc-csrf-token=" + csrfToken;
        final var body = extraParams.isEmpty() ? csrf : extraParams + "&" + csrf;
        return form.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/httpAuth" + path))
                        .header("Authorization", authHeader)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    /** As {@link #adminFormPostRaw} but throws on non-2xx and parses the JSON response. */
    JSONObject adminFormPost(final String path, final String extraParams) throws Exception {
        final var response = adminFormPostRaw(path, extraParams);
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException(
                    "POST " + path + " returned " + response.statusCode() + ": " + response.body());
        }
        return Json.parse(response.body());
    }

    // -------------------------------------------------------------------------
    // Provisioning helpers
    // -------------------------------------------------------------------------

    /** Creates a TC project whose name equals its id, under the given parent project. */
    void createProject(final String projectId, final String parentId) throws Exception {
        createProject(projectId, projectId, parentId);
    }

    /** Creates a TC project under the given parent project. */
    void createProject(final String projectId, final String name, final String parentId) throws Exception {
        post("/httpAuth/app/rest/projects", """
                {"id":"%s","name":"%s","parentProject":{"id":"%s"}}
                """.formatted(projectId, name, parentId));
    }

    /** Creates a build type in the given project. */
    void createBuildType(final String buildTypeId, final String name, final String projectId) throws Exception {
        post("/httpAuth/app/rest/buildTypes", """
                {"id":"%s","name":"%s","project":{"id":"%s"}}
                """.formatted(buildTypeId, name, projectId));
    }

    /**
     * Creates an OIDC Identity Token connection as a projectFeature on the given parent project.
     *
     * @return the generated connection id (PROJECT_EXT_* form) from the TC response
     */
    String createOidcConnection(final String parentProjectId, final String displayName, final String audience,
                                final int ttlMinutes, final String algorithm,
                                final String subjectDimensions) throws Exception {
        final var json = """
                {
                     "type": "OAuthProvider",
                     "properties":
                     {
                       "property": [
                         {"name":"providerType","value":"oidc-identity-token"},
                         {"name":"displayName","value":"%s"},
                         {"name":"audience","value":"%s"},
                         {"name":"ttl_minutes","value":"%d"},
                         {"name":"algorithm","value":"%s"},
                         {"name":"subject_dimensions","value":"%s"}
                       ]
                     }
                   }
                """.formatted(displayName, audience, ttlMinutes, algorithm, subjectDimensions);
        final var responseBody = post(
                "/httpAuth/app/rest/projects/" + parentProjectId + "/projectFeatures", json);
        final var id = (String) Json.parse(responseBody).get("id");
        if (id == null) {
            throw new IllegalStateException("Could not extract connection id from TC response: " + responseBody);
        }
        return id;
    }

    // -------------------------------------------------------------------------
    // Bring-up sequence
    // -------------------------------------------------------------------------

    /**
     * TC 2025.11 requires accepting the license agreement before it serves any requests. The
     * maintenance servlet ({@code /mnt/}) comes up shortly after Tomcat, but TC doesn't reach the
     * license stage until a few seconds later; posting too early races startup and the acceptance
     * is lost. We wait until TC logs the license stage, then POST acceptance via curl inside the
     * container (avoids Java HttpClient cookie-handling quirks).
     */
    private static void acceptLicenseAgreementIfRequired(final GenericContainer<?> teamcity) throws Exception {
        final var deadline = System.currentTimeMillis() + LICENSE_TIMEOUT.toMillis();
        while (System.currentTimeMillis() < deadline) {
            final var result = teamcity.execInContainer(
                    "grep", "-q", "Review and accept TeamCity license agreement",
                    "/opt/teamcity/logs/teamcity-server.log");
            if (result.getExitCode() == 0) break;
            TimeUnit.SECONDS.sleep(3);
        }
        teamcity.execInContainer(
                "sh", "-c",
                "curl -sc /tmp/tc-cookies.txt http://localhost:8111/mnt/ > /dev/null && " +
                "curl -sb /tmp/tc-cookies.txt -X POST " +
                "http://localhost:8111/mnt/do/acceptLicenseAgreement");
    }

    /** Waits until TC transitions from 503 (loading / awaiting license) to 401/200 (ready). */
    private static void waitForTcReady(final HttpClient rest, final String baseUrl) throws Exception {
        final var deadline = System.currentTimeMillis() + READY_TIMEOUT.toMillis();
        while (System.currentTimeMillis() < deadline) {
            final var r = rest.send(
                    HttpRequest.newBuilder().uri(URI.create(baseUrl + "/")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() == 401 || r.statusCode() == 200) return;
            TimeUnit.SECONDS.sleep(3);
        }
        throw new IllegalStateException("TeamCity did not become ready within " + READY_TIMEOUT.toMinutes() + " minutes");
    }

    /**
     * TC writes the super-user token to teamcity-server.log after plugins are fully loaded.
     * Retries for up to 60s in case TC just finished accepting the license and hasn't written
     * the token yet.
     */
    private static String extractSuperUserTokenWithRetry(final GenericContainer<?> teamcity) throws Exception {
        final var deadline = System.currentTimeMillis() + TOKEN_TIMEOUT.toMillis();
        var lastError = "";
        while (System.currentTimeMillis() < deadline) {
            final var result = teamcity.execInContainer(
                    "grep", "-o", "Super user authentication token: [0-9]*",
                    "/opt/teamcity/logs/teamcity-server.log");
            final var output = result.getStdout().trim();
            final var matcher = Pattern.compile("Super user authentication token: (\\d+)").matcher(output);
            if (matcher.find()) return matcher.group(1);
            lastError = "grep output: '" + output + "', stderr: '" + result.getStderr() + "'";
            TimeUnit.SECONDS.sleep(5);
        }
        throw new IllegalStateException(
                "TeamCity super user token not found in server log after 60s. " + lastError);
    }

    private static void requireSuccess(final String method, final String path,
                                       final HttpResponse<String> response) {
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException(
                    "TC " + method + " " + path + " returned " + response.statusCode() + ": " + response.body());
        }
    }
}
