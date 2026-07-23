package com.octopus.teamcity.oidc.it;

import com.nimbusds.jose.jwk.JWKSet;
import net.minidev.json.JSONArray;
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
        // The session CSRF token can go stale on the long-lived shared session; refresh and retry once on a 403.
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

    /** Creates a build configuration template in the given project. */
    void createBuildTypeTemplate(final String templateId, final String name, final String projectId) throws Exception {
        post("/httpAuth/app/rest/projects/" + projectId + "/templates", """
                {"id":"%s","name":"%s","project":{"id":"%s"}}
                """.formatted(templateId, name, projectId));
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
    // Higher-level operations
    // -------------------------------------------------------------------------

    /** GETs an authenticated path (Basic auth, {@code /httpAuth} prefix), returning the raw response. */
    HttpResponse<String> authenticatedGet(final String path) throws Exception {
        return rest.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/httpAuth" + path))
                        .header("Authorization", authHeader)
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Sets the global server root URL via the admin settings form, then polls until the change has
     * propagated (the REST {@code /server} {@code webUrl} reflects it). The wait matters on the
     * shared server, where another class may have set a different root URL.
     */
    void setRootUrl(final String rootUrl) throws Exception {
        final var encoded = rootUrl.replace(":", "%3A").replace("/", "%2F");
        final var resp = adminFormPostRaw("/admin/serverConfigGeneral.html",
                "rootUrl=" + encoded + "&submitSettings=store");
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            throw new IllegalStateException("TC root URL POST returned " + resp.statusCode() + ": " + resp.body());
        }
        final var deadline = System.currentTimeMillis() + Duration.ofMinutes(1).toMillis();
        while (System.currentTimeMillis() < deadline) {
            final var webUrl = (String) Json.parse(get("/httpAuth/app/rest/server")).get("webUrl");
            if (rootUrl.equals(webUrl)) return;
            TimeUnit.SECONDS.sleep(2);
        }
        throw new IllegalStateException("TC root URL did not update to " + rootUrl + " within 1 minute");
    }

    /** Creates a system-administrator user (e.g. to satisfy TC's first-run wizard gate). */
    void createAdminUser(final String username, final String password) throws Exception {
        post("/httpAuth/app/rest/users",
                "{\"username\":\"%s\",\"password\":\"%s\",\"roles\":{\"role\":[{\"roleId\":\"SYSTEM_ADMIN\",\"scope\":\"g\"}]}}"
                        .formatted(username, password));
    }

    /** Fetches and parses the public JWKS document. */
    JWKSet fetchJwks() throws Exception {
        final var response = unauthenticatedGet("/.well-known/jwks.json");
        if (response.statusCode() != 200) {
            throw new IllegalStateException("JWKS endpoint returned " + response.statusCode());
        }
        return JWKSet.parse(response.body());
    }

    /** Queues a build for the given build type and returns the queued build's id. */
    String triggerBuild(final String buildTypeId) throws Exception {
        final var body = post("/httpAuth/app/rest/buildQueue",
                "{\"buildType\":{\"id\":\"%s\"}}".formatted(buildTypeId));
        return String.valueOf(Json.parse(body).get("id"));
    }

    /** Polls until the build finishes; throws if it did not finish SUCCESS within 3 minutes. */
    void waitForBuildSuccess(final String buildId) throws Exception {
        final var deadline = System.currentTimeMillis() + Duration.ofMinutes(3).toMillis();
        while (System.currentTimeMillis() < deadline) {
            final var body = get("/httpAuth/app/rest/builds/id:" + buildId);
            final var build = Json.parse(body);
            if ("finished".equals(String.valueOf(build.get("state")))) {
                final var status = String.valueOf(build.get("status"));
                if (!"SUCCESS".equals(status)) {
                    throw new IllegalStateException(
                            "Build " + buildId + " finished with non-SUCCESS status: " + body);
                }
                return;
            }
            TimeUnit.SECONDS.sleep(5);
        }
        throw new IllegalStateException("Build " + buildId + " did not finish within 3 minutes");
    }

    /** Waits for an unauthorized agent to appear and authorizes it. */
    void authorizeAgent() throws Exception {
        final var deadline = System.currentTimeMillis() + Duration.ofMinutes(3).toMillis();
        while (System.currentTimeMillis() < deadline) {
            final var body = get("/httpAuth/app/rest/agents?locator=authorized:false");
            final var agents = (JSONArray) Json.parse(body).get("agent");
            if (agents != null && !agents.isEmpty()) {
                final var agentId = String.valueOf(((JSONObject) agents.getFirst()).get("id"));
                put("/httpAuth/app/rest/agents/id:" + agentId + "/authorized", "true");
                return;
            }
            TimeUnit.SECONDS.sleep(5);
        }
        throw new IllegalStateException("No unauthorized TC agent appeared within 3 minutes");
    }

    /** Waits until an authorized, connected, enabled agent is idle (running no build). */
    void waitForAgentIdle() throws Exception {
        final var deadline = System.currentTimeMillis() + Duration.ofMinutes(5).toMillis();
        while (System.currentTimeMillis() < deadline) {
            final var body = get("/httpAuth/app/rest/agents"
                    + "?locator=authorized:true,connected:true,enabled:true&fields=agent(id,build)");
            final var agents = (JSONArray) Json.parse(body).get("agent");
            if (agents != null) {
                for (final var item : agents) {
                    if (((JSONObject) item).get("build") == null) return;
                }
            }
            TimeUnit.SECONDS.sleep(5);
        }
        throw new IllegalStateException("No idle TC agent within 5 minutes");
    }

    /** Reads a build feature's properties as a name→value map. */
    JSONObject featureProperties(final String buildTypeId, final String featureId) throws Exception {
        final var body = get("/httpAuth/app/rest/buildTypes/" + buildTypeId
                + "/features/" + featureId + "?fields=properties(property)");
        final var propsContainer = (JSONObject) Json.parse(body).get("properties");
        final var propArray = (JSONArray) propsContainer.get("property");
        final var result = new JSONObject();
        for (final var item : propArray) {
            final var prop = (JSONObject) item;
            result.put((String) prop.get("name"), prop.get("value"));
        }
        return result;
    }

    /** Sets a single build-feature property via REST PUT. TC uses {@code /parameters/} in the URL. */
    void setFeatureProperty(final String buildTypeId, final String featureId,
                            final String name, final String value) throws Exception {
        put("/httpAuth/app/rest/buildTypes/" + buildTypeId + "/features/" + featureId
                + "/parameters/" + name, value);
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

    /** Waits until TC returns 401/200 (i.e. it's up and serving). */
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
