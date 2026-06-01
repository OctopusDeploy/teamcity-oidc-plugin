package com.octopus.teamcity.oidc.it;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;

import net.minidev.json.JSONArray;

import java.net.http.HttpClient;
import java.nio.file.Files;
import java.time.Duration;
import java.util.Base64;

/**
 * End-to-end OIDC flow against the shared stack: triggers a real build, reads the issued JWT back
 * from an artifact, and exchanges it with Octopus. The containers and one-time bring-up live in
 * {@link SharedStack}; this class owns the OIDC-flow-specific server configuration (root URL,
 * Octopus service account + identity, agent authorization, project/build creation).
 */
public class OidcFlowIT {

    // Aliases to the shared stack so the test bodies below read unchanged.
    private static final int TC_PORT = SharedStack.TC_PORT;
    private static final String TC_HTTPS_BASE = SharedStack.TC_HTTPS_BASE;
    private static final String OCTOPUS_ADMIN_API_KEY = SharedStack.octopusApiKey();
    private static final String CONTAINER_PREFIX = SharedStack.CONTAINER_PREFIX;

    private static final String BUILD_CONFIG_EXTERNAL_ID = "OidcTest_Build";
    private static final String PROJECT_EXTERNAL_ID = "OidcTest";
    static String octopusExternalId; // fetched after service account creation, used as JWT audience
    static String octopusServiceAccountId; // fetched after service account creation
    static String projectInternalId; // fetched after project creation, used in Octopus OIDC subject
    static String buildTypeInternalId; // fetched after build type creation, used in Octopus OIDC subject

    // Shared-stack handles, wired in setup().
    private static TeamCityClient tc;
    private static GenericContainer<?> teamcity;
    private static GenericContainer<?> octopus;
    private static GenericContainer<?> caddy;
    private static GenericContainer<?> agent;
    static String tcBaseUrl;       // http://localhost:<mapped TC port> — for test→TC calls
    static String octopusBaseUrl;  // http://localhost:<mapped Octopus port> — for test→Octopus calls
    static String superUserAuthHeader;
    static HttpClient tcHttp;      // TLS-trusting client (trusts the test CA); also fine for plain HTTP
    static HttpClient octopusHttp; // talks to Octopus (plain HTTP from test host)

    static void log(final String msg) {
        System.out.println("[OidcFlowIT] " + java.time.LocalTime.now() + " " + msg);
    }

    @BeforeAll
    static void setup() throws Exception {
        SharedStack.ensureStarted();
        tc = SharedStack.teamCity();
        teamcity = SharedStack.teamcity();
        octopus = SharedStack.octopus();
        caddy = SharedStack.caddy();
        agent = SharedStack.agent();
        tcBaseUrl = SharedStack.tcBaseUrl();
        octopusBaseUrl = SharedStack.octopusBaseUrl();
        tcHttp = SharedStack.caddyTlsHttp();
        octopusHttp = SharedStack.octopusHttp();
        superUserAuthHeader = tc.authHeader();

        log("Stack up. TC=" + tcBaseUrl + " Octopus=" + octopusBaseUrl);
        log("TC super user token: " + tc.superUserToken() + "  (login at " + tcBaseUrl + " with empty username)");

        log("Configuring TC root URL to " + TC_HTTPS_BASE + "...");
        tc.setRootUrl(TC_HTTPS_BASE);

        log("Creating Octopus service account...");
        octopusExternalId = createOctopusServiceAccount();
        log("Octopus ExternalId=" + octopusExternalId + " userId=" + octopusServiceAccountId);

        log("Creating TC project and build config (audience=" + octopusExternalId + ")...");
        createTcProjectAndBuildConfig(octopusExternalId);

        log("Waiting for TC agent to register...");
        tc.authorizeAgent();

        log("Attaching Octopus OIDC identity...");
        attachOctopusOidcIdentity();

        log("Updating CA certificates in Octopus container...");
        octopus.execInContainer("update-ca-certificates");

        log("Waiting for JWT plugin to be ready (JWKS endpoint)...");
        waitForPluginReady();
        log("Setup complete.");
    }

    @AfterAll
    static void dumpContainerLogs() {
        final var logDir = java.nio.file.Path.of(System.getProperty("java.io.tmpdir"), "tc-it-logs", CONTAINER_PREFIX);
        try {
            Files.createDirectories(logDir);
        } catch (final Exception e) {
            log("Could not create log dir: " + e.getMessage());
            return;
        }

        // TC server log — full file for thorough post-mortem
        try {
            final var result = teamcity.execInContainer(
                    "cat", "/opt/teamcity/logs/teamcity-server.log");
            Files.writeString(logDir.resolve("teamcity-server.log"),
                    result.getStdout() + result.getStderr());
        } catch (final Exception e) {
            log("Could not read TC server log: " + e.getMessage());
        }

        // Container stdout/stderr
        for (final var entry : java.util.Map.of(
                "teamcity", teamcity,
                "agent", agent,
                "caddy", caddy,
                "octopus", octopus
        ).entrySet()) {
            try {
                Files.writeString(logDir.resolve(entry.getKey() + ".log"),
                        entry.getValue().getLogs());
            } catch (final Exception e) {
                log("Could not write logs for " + entry.getKey() + ": " + e.getMessage());
            }
        }
        log("Container logs written to " + logDir);
    }

    private static void createTcProjectAndBuildConfig(final String audience) throws Exception {
        // Create project
        final var projectJson = """
                {"id":"OidcTest","name":"OidcTest","parentProject":{"id":"_Root"}}
                """;
        tc.post("/httpAuth/app/rest/projects", projectJson);

        // Create build config
        final var buildConfigJson = """
                {"id":"OidcTest_Build","name":"OidcTest Build","project":{"id":"OidcTest"}}
                """;
        tc.post("/httpAuth/app/rest/buildTypes", buildConfigJson);

        // Fetch the internal IDs that TC auto-assigns. The Octopus OIDC identity subject
        // is built from these (project:<id>:build_type:<id>) so they need to match the
        // composite `sub` claim the plugin emits at build time. Using internal IDs instead
        // of the external IDs makes the trust binding rename-stable.
        //
        // TC's REST API omits `internalId` from the default response — it must be requested
        // explicitly via `?fields=internalId`.
        projectInternalId = (String) Json.parse(tc.get("/httpAuth/app/rest/projects/" + PROJECT_EXTERNAL_ID + "?fields=internalId"))
                .get("internalId");
        buildTypeInternalId = (String) Json.parse(tc.get("/httpAuth/app/rest/buildTypes/" + BUILD_CONFIG_EXTERNAL_ID + "?fields=internalId"))
                .get("internalId");

        // Add JWT build feature — audience is the Octopus ExternalId GUID.
        // Subject scoping is left at the default (no optional dimensions), so `sub` is the
        // minimal `project:<id>:build_type:<id>` form that matches Octopus's literal-subject
        // federated credential.
        final var featureJson = """
                {"type":"oidc-plugin","properties":{"property":[
                  {"name":"audience","value":"%s"},
                  {"name":"ttl_minutes","value":"10"}
                ]}}
                """.formatted(audience);
        tc.post("/httpAuth/app/rest/buildTypes/OidcTest_Build/features", featureJson);

        // Write jwt.token to a file artifact so we can retrieve it via the artifacts API.
        // jwt.token is masked in the resulting-properties API and in the build log; artifact
        // file content is not, so an artifact is the only way to read the value back.
        final var stepJson = """
                {"type":"simpleRunner","name":"capture-jwt","properties":{"property":[
                  {"name":"script.content","value":"JWT=%jwt.token%\\nprintf 'JWT (first 50): %.50s\\\\n' \\"$JWT\\"\\nprintf '%s' \\"$JWT\\" > jwt.txt"},
                  {"name":"use.custom.script","value":"true"}
                ]}}
                """;
        tc.post("/httpAuth/app/rest/buildTypes/OidcTest_Build/steps", stepJson);

        // Publish jwt.txt as an artifact so the test can download it via the artifacts API
        tc.put("/httpAuth/app/rest/buildTypes/OidcTest_Build/settings/artifactRules", "jwt.txt");

        // Map jwt.token onto an env var, mirroring the real-world usage pattern
        // (env.ARM_OIDC_TOKEN=%jwt.token%) that exposed the masking bug.
        final var envVarParamJson = """
                {"name":"env.ARM_OIDC_TOKEN","value":"%jwt.token%"}
                """;
        tc.post("/httpAuth/app/rest/buildTypes/OidcTest_Build/parameters", envVarParamJson);
    }

    /**
     * Attaches a small public Git repo as a VCS root so the build has branch info
     * (used by the build feature edit UI's sample-claims display). The build type
     * is configured with manual checkout so the agent doesn't fetch the repo.
     */
    private static void attachSampleVcsRoot() throws Exception {
        // Disable automatic checkout so the build doesn't depend on outbound Git access
        tc.put("/httpAuth/app/rest/buildTypes/OidcTest_Build/settings/checkoutMode", "MANUAL");

        // teamcity:branchSpec must be set for builds to carry branch information;
        // without it, SBuild.getBranch() returns null and the JWT branch claim is blank.
        final var vcsRootJson = """
                {"id":"OidcTest_VcsRoot","name":"OidcTest VCS",
                 "vcsName":"jetbrains.git",
                 "project":{"id":"OidcTest"},
                 "properties":{"property":[
                     {"name":"url","value":"https://github.com/octocat/Hello-World.git"},
                     {"name":"branch","value":"refs/heads/master"},
                     {"name":"teamcity:branchSpec","value":"+:refs/heads/*"},
                     {"name":"authMethod","value":"ANONYMOUS"}
                 ]}}
                """;
        tc.post("/httpAuth/app/rest/vcs-roots", vcsRootJson);

        final var vcsEntryJson = """
                {"id":"OidcTest_VcsRoot","vcs-root":{"id":"OidcTest_VcsRoot"},"checkout-rules":""}
                """;
        tc.post("/httpAuth/app/rest/buildTypes/OidcTest_Build/vcs-root-entries", vcsEntryJson);
    }

    /**
     * Polls until both conditions are true:
     *   1. JWKS contains at least one key — the plugin has generated key material.
     *   2. The OIDC discovery issuer equals TC_HTTPS_BASE — this calls buildServer.getRootUrl()
     *      directly through the plugin's own code path, which is the same call made at build time
     *      in JwtBuildStartContext.updateParameters(). Waiting here ensures the root URL change
     *      has fully propagated through TC's internals, not just been committed to the REST API.
     */
    private static void waitForPluginReady() throws Exception {
        final var deadline = System.currentTimeMillis() + Duration.ofMinutes(5).toMillis();
        final var httpsBase = "https://" + caddy.getHost() + ":" + caddy.getMappedPort(443);
        while (System.currentTimeMillis() < deadline) {
            try {
                final var jwksResponse = tcHttp.send(
                        java.net.http.HttpRequest.newBuilder()
                                .uri(java.net.URI.create(httpsBase + "/.well-known/jwks.json"))
                                .GET().build(),
                        java.net.http.HttpResponse.BodyHandlers.ofString()
                );
                if (jwksResponse.statusCode() != 200) {
                    log("JWKS returned " + jwksResponse.statusCode() + ", retrying...");
                    java.util.concurrent.TimeUnit.SECONDS.sleep(5);
                    continue;
                }
                final var jwks = Json.parse(jwksResponse.body());
                final var keys = (JSONArray) jwks.get("keys");
                if (keys == null || keys.isEmpty()) {
                    log("JWKS returned 200 but no keys yet (TC built-in?), retrying...");
                    java.util.concurrent.TimeUnit.SECONDS.sleep(5);
                    continue;
                }

                // Also verify the issuer — exercises buildServer.getRootUrl() through the
                // plugin's own code path (WellKnownPublicFilter), same as updateParameters()
                final var discoveryResponse = tcHttp.send(
                        java.net.http.HttpRequest.newBuilder()
                                .uri(java.net.URI.create(httpsBase + "/.well-known/openid-configuration"))
                                .GET().build(),
                        java.net.http.HttpResponse.BodyHandlers.ofString()
                );
                if (discoveryResponse.statusCode() == 200) {
                    final var issuer = (String) Json.parse(discoveryResponse.body()).get("issuer");
                    if (TC_HTTPS_BASE.equals(issuer)) {
                        log("JWT plugin ready (JWKS has " + keys.size() + " key(s), issuer=" + issuer + ").");
                        return;
                    }
                    log("JWKS ready but issuer not yet updated (got: " + issuer + "), retrying...");
                } else {
                    log("Discovery returned " + discoveryResponse.statusCode() + ", retrying...");
                }
            } catch (final Exception e) {
                log("waitForPluginReady poll failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
            java.util.concurrent.TimeUnit.SECONDS.sleep(5);
        }
        throw new IllegalStateException("JWT plugin did not become ready with correct issuer within 5 minutes");
    }

    private static String octopusGet(final String path) throws Exception {
        final var response = octopusHttp.send(
                java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create(octopusBaseUrl + path))
                        .header("X-Octopus-ApiKey", OCTOPUS_ADMIN_API_KEY)
                        .header("Accept", "application/json")
                        .GET().build(),
                java.net.http.HttpResponse.BodyHandlers.ofString()
        );
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException(
                    "Octopus GET " + path + " returned " + response.statusCode() + ": " + response.body());
        }
        return response.body();
    }

    private static String octopusPost(final String path, final String json) throws Exception {
        final var response = octopusHttp.send(
                java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create(octopusBaseUrl + path))
                        .header("X-Octopus-ApiKey", OCTOPUS_ADMIN_API_KEY)
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .POST(java.net.http.HttpRequest.BodyPublishers.ofString(json))
                        .build(),
                java.net.http.HttpResponse.BodyHandlers.ofString()
        );
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException(
                    "Octopus POST " + path + " returned " + response.statusCode() + ": " + response.body());
        }
        return response.body();
    }

    /**
     * Creates an Octopus service account and returns its ExternalId GUID.
     * The ExternalId is used as the JWT audience — it must be set on the TC build
     * feature before triggering a build, and passed as "audience" in the token exchange.
     */
    private static String createOctopusServiceAccount() throws Exception {
        // Create the service account
        final var userResponse = octopusPost("/api/users", """
                {"Username":"teamcity-ci","DisplayName":"TeamCity CI",
                 "IsActive":true,"IsService":true,"Identities":[]}
                """);
        final var userId = (String) Json.parse(userResponse).get("Id");
        if (userId == null) throw new IllegalStateException(
                "Could not extract user Id from Octopus response: " + userResponse);

        // Fetch ExternalId — the GUID Octopus expects in the JWT aud claim
        final var identitiesResponse = octopusGet(
                "/api/serviceaccounts/" + userId + "/oidcidentities/v1?skip=0&take=1");
        final var externalId = (String) Json.parse(identitiesResponse).get("ExternalId");
        if (externalId == null) throw new IllegalStateException(
                "Could not extract ExternalId from Octopus response: " + identitiesResponse);

        // Store userId for use in attachOctopusOidcIdentity
        octopusServiceAccountId = userId;
        return externalId;
    }

    private static void attachOctopusOidcIdentity() throws Exception {
        // Subject must match the composite `sub` claim the plugin emits. With
        // subject_dimensions=none on the build feature, the plugin emits
        // `project:<project_internal_id>:build_type:<build_type_internal_id>`.
        final var subject = "project:" + projectInternalId + ":build_type:" + buildTypeInternalId;
        octopusPost("/api/serviceaccounts/" + octopusServiceAccountId + "/oidcidentities/create/v1", """
                {"ServiceAccountId":"%s","Name":"TeamCity Build",
                 "Issuer":"%s","Subject":"%s"}
                """.formatted(octopusServiceAccountId, TC_HTTPS_BASE, subject));
    }

    @Test
    void teamCityJwtIsAcceptedByOctopus() throws Exception {
        // 1. Wait for agent idle, then trigger build
        tc.waitForAgentIdle();
        log("Triggering build...");
        final var buildId = tc.triggerBuild(BUILD_CONFIG_EXTERNAL_ID);
        if (buildId.equals("null")) throw new IllegalStateException(
                "Could not parse build id for " + BUILD_CONFIG_EXTERNAL_ID);
        log("Build queued, id=" + buildId);

        // 2. Wait for build to finish
        log("Waiting for build to finish...");
        tc.waitForBuildSuccess(buildId);
        log("Build finished successfully.");

        // 3. Extract jwt.token from artifact
        log("Extracting JWT from build artifact...");
        final var jwt = extractJwtFromBuild(buildId);
        org.assertj.core.api.Assertions.assertThat(jwt)
                .as("jwt.token must be present in build artifact")
                .isNotBlank();
        log("JWT extracted (length=" + jwt.length() + ")");

        // 4. Sanity-check the JWT
        log("Verifying JWT claims and signature...");
        verifyJwtClaims(jwt);
        log("JWT verified.");

        // 5. Exchange with Octopus
        log("Exchanging JWT with Octopus...");
        final var accessToken = exchangeJwtWithOctopus(jwt);
        org.assertj.core.api.Assertions.assertThat(accessToken)
                .as("Octopus must return a non-blank access_token")
                .isNotBlank();
        log("Octopus accepted the JWT and returned an access token.");

        // 6. Verify the access token works — call /api/users/me with it
        log("Verifying access token against /api/users/me...");
        final var meResponse = octopusHttp.send(
                java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create(octopusBaseUrl + "/api/users/me"))
                        .header("Authorization", "Bearer " + accessToken)
                        .header("Accept", "application/json")
                        .GET().build(),
                java.net.http.HttpResponse.BodyHandlers.ofString()
        );
        log("/api/users/me status=" + meResponse.statusCode() + " body=" + meResponse.body());
        org.assertj.core.api.Assertions.assertThat(meResponse.statusCode())
                .as("/api/users/me must return 200 with the service account identity")
                .isEqualTo(200);
    }

    @Test
    void jwtTokenIsMaskedInBuildLogAndResultingProperties() throws Exception {
        tc.waitForAgentIdle();
        log("Triggering build for masking assertions...");
        final var buildId = tc.triggerBuild(BUILD_CONFIG_EXTERNAL_ID);
        log("Build queued, id=" + buildId);
        tc.waitForBuildSuccess(buildId);

        // Artifact contents are exempt from masking, so this gives us the literal JWT
        // value that should be replaced with ******* everywhere it appears.
        final var jwt = extractJwtFromBuild(buildId);
        org.assertj.core.api.Assertions.assertThat(jwt)
                .as("Sanity: jwt.txt artifact must contain a JWT")
                .startsWith("eyJ");

        final var resultingProperties = fetchResultingProperties(buildId);
        org.assertj.core.api.Assertions.assertThat(resultingProperties)
                .as("jwt.token must be masked in resulting-properties")
                .contains("name=\"jwt.token\" value=\"*******\"");
        org.assertj.core.api.Assertions.assertThat(resultingProperties)
                .as("env.ARM_OIDC_TOKEN (which resolves to %jwt.token%) must be masked in resulting-properties")
                .contains("name=\"env.ARM_OIDC_TOKEN\" value=\"*******\"");
        org.assertj.core.api.Assertions.assertThat(resultingProperties)
                .as("Raw JWT must not appear anywhere in resulting-properties")
                .doesNotContain(jwt);

        final var buildLog = fetchBuildLog(buildId);
        org.assertj.core.api.Assertions.assertThat(buildLog)
                .as("Raw JWT must not appear in the build log")
                .doesNotContain(jwt);
    }

    private static String fetchResultingProperties(final String buildId) throws Exception {
        final var response = tcHttp.send(
                java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create(
                                tcBaseUrl + "/httpAuth/app/rest/builds/id:" + buildId + "/resulting-properties"))
                        .header("Authorization", superUserAuthHeader)
                        .GET().build(),
                java.net.http.HttpResponse.BodyHandlers.ofString()
        );
        if (response.statusCode() != 200) {
            throw new IllegalStateException(
                    "Failed to fetch resulting-properties: " + response.statusCode() + " " + response.body());
        }
        return response.body();
    }

    private static String fetchBuildLog(final String buildId) throws Exception {
        final var response = tcHttp.send(
                java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create(
                                tcBaseUrl + "/httpAuth/downloadBuildLog.html?buildId=" + buildId))
                        .header("Authorization", superUserAuthHeader)
                        .GET().build(),
                java.net.http.HttpResponse.BodyHandlers.ofString()
        );
        if (response.statusCode() != 200) {
            throw new IllegalStateException(
                    "Failed to fetch build log: " + response.statusCode() + " " + response.body());
        }
        return response.body();
    }

    private static String extractJwtFromBuild(final String buildId) throws Exception {
        // jwt.token is masked in resulting-properties via JwtPasswordsProvider.
        // The build step writes it to jwt.txt; we download that artifact instead.
        final var response = tcHttp.send(
                java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create(
                                tcBaseUrl + "/httpAuth/app/rest/builds/id:" + buildId
                                        + "/artifacts/content/jwt.txt"))
                        .header("Authorization", superUserAuthHeader)
                        .GET().build(),
                java.net.http.HttpResponse.BodyHandlers.ofString()
        );
        if (response.statusCode() != 200) {
            throw new IllegalStateException(
                    "Failed to download jwt.txt artifact: " + response.statusCode()
                            + " " + response.body());
        }
        return response.body().trim();
    }

    private static void verifyJwtClaims(final String jwt) throws Exception {
        final var parsed = com.nimbusds.jwt.SignedJWT.parse(jwt);
        final var claims = parsed.getJWTClaimsSet();

        org.assertj.core.api.Assertions.assertThat(claims.getIssuer())
                .as("iss must equal TC_HTTPS_BASE").isEqualTo(TC_HTTPS_BASE);
        org.assertj.core.api.Assertions.assertThat(claims.getAudience())
                .as("aud must contain octopusExternalId").contains(octopusExternalId);
        org.assertj.core.api.Assertions.assertThat(claims.getExpirationTime())
                .as("JWT must not be expired").isAfter(new java.util.Date());

        // Verify signature against the JWKS served by TC (via Caddy TLS)
        // tcHttp trusts the self-signed cert via TlsTrustManager
        final var jwksResponse = tcHttp.send(
                java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create(
                                "https://" + caddy.getHost() + ":" + caddy.getMappedPort(443) + "/.well-known/jwks.json"))
                        .GET().build(),
                java.net.http.HttpResponse.BodyHandlers.ofString()
        );
        final var jwks = com.nimbusds.jose.jwk.JWKSet.parse(jwksResponse.body());
        final var keySource =
                new com.nimbusds.jose.jwk.source.ImmutableJWKSet<>(jwks);
        final var keySelector =
                new com.nimbusds.jose.proc.JWSVerificationKeySelector<>(
                        parsed.getHeader().getAlgorithm(), keySource);
        final var processor =
                new com.nimbusds.jwt.proc.DefaultJWTProcessor<>();
        processor.setJWSKeySelector(keySelector);
        processor.process(parsed, null); // throws if signature invalid
    }

    private static String exchangeJwtWithOctopus(final String jwt) throws Exception {
        // Discover token endpoint from Octopus's own OIDC discovery doc
        final var discoveryResponse = octopusHttp.send(
                java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create(octopusBaseUrl + "/.well-known/openid-configuration"))
                        .GET().build(),
                java.net.http.HttpResponse.BodyHandlers.ofString()
        );
        final var tokenEndpointStr = (String) Json.parse(discoveryResponse.body()).get("token_endpoint");
        if (tokenEndpointStr == null) throw new IllegalStateException(
                "token_endpoint not found in Octopus discovery doc: " + discoveryResponse.body());

        // Rewrite the token endpoint to use the mapped localhost URL
        final var rawEndpoint = java.net.URI.create(tokenEndpointStr);
        final var tokenEndpoint = java.net.URI.create(
                octopusBaseUrl + rawEndpoint.getRawPath()
                + (rawEndpoint.getRawQuery() != null ? "?" + rawEndpoint.getRawQuery() : ""));

        // Exchange the JWT — anonymous (no API key)
        final var exchangeBody = """
                {"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange",
                 "audience":"%s",
                 "subject_token":"%s",
                 "subject_token_type":"urn:ietf:params:oauth:token-type:jwt"}
                """.formatted(octopusExternalId, jwt);

        final var exchangeResponse = octopusHttp.send(
                java.net.http.HttpRequest.newBuilder()
                        .uri(tokenEndpoint)
                        .header("Content-Type", "application/json")
                        .POST(java.net.http.HttpRequest.BodyPublishers.ofString(exchangeBody))
                        .build(),
                java.net.http.HttpResponse.BodyHandlers.ofString()
        );
        org.assertj.core.api.Assertions.assertThat(exchangeResponse.statusCode())
                .as("Octopus OIDC token exchange must return 200. Body: " + exchangeResponse.body())
                .isEqualTo(200);

        final var accessToken = (String) Json.parse(exchangeResponse.body()).get("access_token");
        if (accessToken == null) throw new IllegalStateException(
                "access_token not found in Octopus response: " + exchangeResponse.body());
        return accessToken;
    }

    // -------------------------------------------------------------------------
    // Helpers for the connection-inheritance integration test
    // -------------------------------------------------------------------------

    /**
     * Creates a build configuration that references an OIDC connection by id (no inline
     * audience/ttl/algorithm — those are resolved from the connection at build time).
     * Adds the same capture-jwt step and artifact rule used by the existing OidcTest_Build
     * so we can read the JWT back via the artifacts API.
     */
    private static void createBuildTypeReferencingConnection(
            final String projectId,
            final String buildTypeId,
            final String connectionId) throws Exception {
        // Build config
        final var buildConfigJson = """
                {"id":"%s","name":"%s","project":{"id":"%s"}}
                """.formatted(buildTypeId, buildTypeId, projectId);
        tc.post("/httpAuth/app/rest/buildTypes", buildConfigJson);

        // Build feature — only connection_id; all other issuance settings come from the connection
        final var featureJson = """
                {"type":"oidc-plugin","properties":{"property":[
                  {"name":"connection_id","value":"%s"}
                ]}}
                """.formatted(connectionId);
        tc.post("/httpAuth/app/rest/buildTypes/" + buildTypeId + "/features", featureJson);

        // Capture-jwt step — writes jwt.token to jwt.txt for artifact retrieval
        final var stepJson = """
                {
                    "type": "simpleRunner",
                    "name": "capture-jwt",
                    "properties":{
                        "property":[
                            {"name": "script.content","value": "JWT=%jwt.token%\\nprintf 'JWT (first 50): %.50s\\\\n' \\"$JWT\\"\\nprintf '%s' \\"$JWT\\" > jwt.txt"},
                            {"name": "use.custom.script","value": "true"}
                        ]
                    }
                }
                """;
        tc.post("/httpAuth/app/rest/buildTypes/" + buildTypeId + "/steps", stepJson);

        // Publish jwt.txt as an artifact
        tc.put("/httpAuth/app/rest/buildTypes/" + buildTypeId + "/settings/artifactRules", "jwt.txt");

        // VCS root with branch tracking so the build has branch info and the JWT carries
        // a :branch: segment (required by the subject_dimensions=branch connection setting).
        // Manual checkout avoids any outbound Git dependency.
        tc.put("/httpAuth/app/rest/buildTypes/" + buildTypeId + "/settings/checkoutMode", "MANUAL");
        final var vcsRootId = projectId + "_VcsRoot";
        final var vcsRootJson = """
                {
                      "id": "%s",
                      "name": "%s VCS",
                      "vcsName": "jetbrains.git",
                      "project": {"id": "%s"},
                      "properties": {
                        "property":[
                          {"name":"url","value":"https://github.com/octocat/Hello-World.git"},
                          {"name":"branch","value":"refs/heads/master"},
                          {"name":"teamcity:branchSpec","value":"+:refs/heads/*"},
                          {"name":"authMethod","value":"ANONYMOUS"}
                        ]
                      }
                    }
                """.formatted(vcsRootId, projectId, projectId);
        tc.post("/httpAuth/app/rest/vcs-roots", vcsRootJson);
        final var vcsEntryJson = """
                {"id":"%s","vcs-root":{"id":"%s"},"checkout-rules":""}
                """.formatted(vcsRootId, vcsRootId);
        tc.post("/httpAuth/app/rest/buildTypes/" + buildTypeId + "/vcs-root-entries", vcsEntryJson);
    }

    @Test
    void connectionInheritedFromParentProjectIsUsed() throws Exception {
        // Create an OIDC connection at _Root so it is accessible to all sub-projects
        final var connectionId = tc.createOidcConnection(
                "_Root", "IT Connection", "api://it-connection-audience", 30, "ES256", "branch");
        log("Created OIDC connection: " + connectionId);

        tc.createProject("OidcConnIT", "_Root");
        createBuildTypeReferencingConnection("OidcConnIT", "OidcConnIT_Build", connectionId);
        log("Created project OidcConnIT and build type OidcConnIT_Build referencing connection " + connectionId);

        tc.waitForAgentIdle();
        log("Triggering connection-inheritance build...");
        final var buildId = tc.triggerBuild("OidcConnIT_Build");
        log("Build queued, id=" + buildId);

        tc.waitForBuildSuccess(buildId);
        log("Build finished successfully.");

        final var jwt = extractJwtFromBuild(buildId);
        org.assertj.core.api.Assertions.assertThat(jwt)
                .as("jwt.token must be present in build artifact")
                .isNotBlank();
        log("JWT extracted (length=" + jwt.length() + ")");

        final var claims = com.nimbusds.jwt.SignedJWT.parse(jwt).getJWTClaimsSet();

        org.assertj.core.api.Assertions.assertThat(claims.getAudience())
                .as("aud must match the connection's audience")
                .containsExactly("api://it-connection-audience");

        final var ttlSeconds =
                (claims.getExpirationTime().getTime() - claims.getIssueTime().getTime()) / 1000;
        org.assertj.core.api.Assertions.assertThat(ttlSeconds)
                .as("TTL must be within the 30-minute window set on the connection")
                .isBetween(29L * 60, 30L * 60);

        org.assertj.core.api.Assertions.assertThat(claims.getSubject())
                .as("sub must be project:<id>:build_type:<id>:branch:<branch> with every segment "
                        + "populated (subject_dimensions=branch on the connection requires a non-empty branch)")
                .matches("project:[^:]+:build_type:[^:]+:branch:.+");

        log("JWT claims verified: aud=" + claims.getAudience()
                + " ttl=" + ttlSeconds + "s sub=" + claims.getSubject());
    }

    /**
     * Blocks until Enter is pressed, keeping all containers alive for manual UI testing.
     * Run with:
     *   TESTCONTAINERS_RYUK_DISABLED=true \
     *   JAVA_HOME=$(jenv prefix 21) \
     *   mvn verify -pl integration-tests -Dit.test=OidcFlowIT#manualTestingPause -Dmanual
     * Add to /etc/hosts (once):
     *   127.0.0.1  teamcity-tls  teamcity-public-tls  octopus-tls
     * Then browse to https://teamcity-tls:<port> printed below.
     * Accept the cert warning (self-signed CA), log in with empty username + the token below.
     */
    @Test
    void manualTestingPause() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(
                System.getProperty("manual") != null,
                "Skipped — pass -Dmanual to activate manual testing pause"
        );

        // Attach a VCS root and run a sample build so the build feature edit UI
        // has real branch / trigger_type sample values to display.
        log("Attaching VCS root for manual stack...");
        attachSampleVcsRoot();
        log("Triggering sample build for manual stack...");
        tc.waitForAgentIdle();
        final var buildId = tc.triggerBuild(BUILD_CONFIG_EXTERNAL_ID);
        log("Sample build queued, id=" + buildId + " — waiting for it to finish...");
        tc.waitForBuildSuccess(buildId);
        log("Sample build finished.");

        final int caddyPort = caddy.getMappedPort(443);
        final var httpsUrl = "https://teamcity-tls:" + caddyPort;
        final var altHttpsUrl = "https://teamcity-public-tls:" + caddyPort;
        // TC runs inside Docker — use the internal Caddy port (8443), not the host-mapped port.
        final var octopusTlsUrl = "https://octopus-tls:8443";
        // superUserAuthHeader is "Basic <base64(:token)>" — decode and split on ":" to get the token
        final var superUserToken = superUserAuthHeader.replace("Basic ", "");
        final var decodedToken = new String(Base64.getDecoder().decode(superUserToken)).split(":", 2)[1];

        // Direct HTTP URL — port is fixed at MANUAL_TC_HOST_PORT in manual mode so the URL
        // is stable across container restarts. Use this URL with Chrome MCP to skip the
        // Caddy self-signed cert warning.
        final var directHttpUrl = "http://localhost:" + teamcity.getMappedPort(TC_PORT);
        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════════╗");
        System.out.println("║  Stack is ready for manual testing                               ║");
        System.out.println("║                                                                  ║");
        System.out.printf( "║  TeamCity:    %-51s║%n", httpsUrl);
        System.out.printf( "║  Alt URL:     %-51s║%n", altHttpsUrl);
        System.out.printf( "║  Direct HTTP: %-51s║%n", directHttpUrl);
        System.out.printf( "║  Login:       %-51s║%n", "(empty username)");
        System.out.printf( "║  Password:    %-51s║%n", decodedToken);
        System.out.println("║                                                                  ║");
        System.out.printf( "║  Octopus (browser): %-47s║%n", octopusBaseUrl);
        System.out.printf( "║  Octopus (Try Exchange URL): %-38s║%n", octopusTlsUrl);
        System.out.printf( "║  API key:     %-51s║%n", OCTOPUS_ADMIN_API_KEY);
        System.out.printf( "║  Octopus ExternalId (JWT aud): %-35s║%n", octopusExternalId);
        System.out.println("║                                                                  ║");
        System.out.println("║  /etc/hosts:  127.0.0.1  teamcity-tls  teamcity-public-tls       ║");
        System.out.println("║               127.0.0.1  octopus-tls                             ║");
        System.out.println("║  Cert warning: accept in browser (self-signed CA)                ║");
        System.out.println("║                                                                  ║");
        System.out.println("║  Press Ctrl+C to stop all containers                             ║");
        System.out.println("╚══════════════════════════════════════════════════════════════════╝");
        System.out.println();

        Thread.sleep(Long.MAX_VALUE);
    }
}
