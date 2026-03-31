package de.ndr.teamcity.it;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MSSQLServerContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import javax.net.ssl.SSLContext;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Duration;

import static org.assertj.core.api.Assertions.fail;

@Testcontainers
public class OidcFlowIT {

    private static final int TC_PORT = 8111;
    private static final String TC_IMAGE = "jetbrains/teamcity-server:2025.11";
    private static final String AGENT_IMAGE = "jetbrains/teamcity-agent:2025.11";
    private static final String OCTOPUS_IMAGE = "octopusdeploy/octopusdeploy:latest";
    private static final String CADDY_IMAGE = "caddy:latest";
    private static final String MSSQL_IMAGE = "mcr.microsoft.com/mssql/server:2022-latest";

    private static final String OCTOPUS_ADMIN_API_KEY = "API-INTEGRATION-TEST-0000000000001";
    private static final String OCTOPUS_ADMIN_PASSWORD = "P@ssw0rd123!";
    private static final String MSSQL_PASSWORD = "P@ssw0rd123!";

    private static final String TC_INTERNAL_ALIAS = "teamcity";
    private static final String CADDY_ALIAS = "teamcity-tls";
    private static final String TC_HTTPS_BASE = "https://teamcity-tls";

    private static final String BUILD_CONFIG_EXTERNAL_ID = "OidcTest_Build";
    static String octopusExternalId; // fetched after service account creation, used as JWT audience
    static String octopusServiceAccountId; // fetched after service account creation

    private static final Path PLUGIN_ZIP = Path.of(
            System.getProperty("project.basedir", "."),
            "../target/jwt-plugin.zip"
    ).normalize();

    static final Network network = Network.newNetwork();

    @Container
    static final MSSQLServerContainer<?> mssql = new MSSQLServerContainer<>(MSSQL_IMAGE)
            .withNetwork(network)
            .withNetworkAliases("mssql")
            .withPassword(MSSQL_PASSWORD)
            .acceptLicense();

    // ADO.NET connection string using the Docker network alias for MSSQL
    private static final String OCTOPUS_DB_CONNECTION_STRING =
            "Server=mssql,1433;Database=Octopus;User Id=sa;Password=" + MSSQL_PASSWORD + ";TrustServerCertificate=true";

    @Container
    static final GenericContainer<?> octopus = new GenericContainer<>(OCTOPUS_IMAGE)
            .withNetwork(network)
            .withExposedPorts(8080)
            .withEnv("ACCEPT_EULA", "Y")
            .withEnv("DB_CONNECTION_STRING", OCTOPUS_DB_CONNECTION_STRING)
            .withEnv("ADMIN_USERNAME", "admin")
            .withEnv("ADMIN_PASSWORD", OCTOPUS_ADMIN_PASSWORD)
            .withEnv("ADMIN_API_KEY", OCTOPUS_ADMIN_API_KEY)
            .withEnv("DISABLE_DIND", "Y")
            .dependsOn(mssql)
            .waitingFor(Wait.forHttp("/api").forStatusCode(200).withStartupTimeout(Duration.ofMinutes(5)));

    @Container
    static final GenericContainer<?> teamcity = new GenericContainer<>(TC_IMAGE)
            .withNetwork(network)
            .withNetworkAliases(TC_INTERNAL_ALIAS)
            .withExposedPorts(TC_PORT)
            .withEnv("TEAMCITY_SERVER_OPTS", "-Dteamcity.startup.maintenance=false")
            .withCopyFileToContainer(
                    MountableFile.forHostPath(PLUGIN_ZIP),
                    "/data/teamcity_server/datadir/plugins/jwt-plugin.zip"
            )
            .waitingFor(
                    Wait.forHttp("/mnt/").forStatusCode(200).withStartupTimeout(Duration.ofMinutes(5))
            );

    @Container
    static final GenericContainer<?> caddy = new GenericContainer<>(CADDY_IMAGE)
            .withNetwork(network)
            .withNetworkAliases(CADDY_ALIAS)
            .withExposedPorts(443)
            .withCopyFileToContainer(
                    MountableFile.forClasspathResource("Caddyfile"),
                    "/etc/caddy/Caddyfile"
            )
            .withCopyFileToContainer(
                    MountableFile.forClasspathResource("tls/server.crt"),
                    "/etc/caddy/tls/server.crt"
            )
            .withCopyFileToContainer(
                    MountableFile.forClasspathResource("tls/server.key"),
                    "/etc/caddy/tls/server.key"
            )
            .waitingFor(Wait.forListeningPort().withStartupTimeout(Duration.ofMinutes(1)));

    @Container
    static final GenericContainer<?> agent = new GenericContainer<>(AGENT_IMAGE)
            .withNetwork(network)
            .withEnv("SERVER_URL", TC_HTTPS_BASE)
            .dependsOn(teamcity, caddy);

    static String tcBaseUrl;       // http://localhost:<mapped TC port> — for test→TC calls
    static String octopusBaseUrl;  // http://localhost:<mapped Octopus port> — for test→Octopus calls
    static String superUserAuthHeader;
    static HttpClient tcHttp;      // talks to TC (plain HTTP from test host)
    static HttpClient octopusHttp; // talks to Octopus (plain HTTP from test host)

    @BeforeAll
    static void setup() throws Exception {
        tcBaseUrl = "http://localhost:" + teamcity.getMappedPort(TC_PORT);
        octopusBaseUrl = "http://localhost:" + octopus.getMappedPort(8080);

        SSLContext ssl = TlsTrustManager.buildSslContext();
        tcHttp = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(10))
                .sslContext(ssl)
                .build();
        octopusHttp = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(10))
                .build();

        acceptTcLicenseAgreementIfRequired();
        waitForTcReady();

        String token = extractTcSuperUserTokenWithRetry();
        String encoded = java.util.Base64.getEncoder().encodeToString((":" + token).getBytes());
        superUserAuthHeader = "Basic " + encoded;

        configureTcServerRootUrl();

        // Create Octopus service account first to get the ExternalId GUID,
        // which is used as the JWT audience in the TC build config.
        octopusExternalId = createOctopusServiceAccount();
        createTcProjectAndBuildConfig(octopusExternalId);
        authorizeAgent();
        attachOctopusOidcIdentity(octopusExternalId);
    }

    private static void acceptTcLicenseAgreementIfRequired() throws Exception {
        long deadline = System.currentTimeMillis() + Duration.ofMinutes(2).toMillis();
        while (System.currentTimeMillis() < deadline) {
            var result = teamcity.execInContainer(
                    "grep", "-q", "Review and accept TeamCity license agreement",
                    "/opt/teamcity/logs/teamcity-server.log"
            );
            if (result.getExitCode() == 0) break;
            java.util.concurrent.TimeUnit.SECONDS.sleep(3);
        }
        teamcity.execInContainer(
                "sh", "-c",
                "curl -sc /tmp/tc-cookies.txt http://localhost:8111/mnt/ > /dev/null && " +
                "curl -sb /tmp/tc-cookies.txt -X POST " +
                "http://localhost:8111/mnt/do/acceptLicenseAgreement"
        );
    }

    private static void waitForTcReady() throws Exception {
        long deadline = System.currentTimeMillis() + Duration.ofMinutes(5).toMillis();
        while (System.currentTimeMillis() < deadline) {
            var r = tcHttp.send(
                    java.net.http.HttpRequest.newBuilder()
                            .uri(java.net.URI.create(tcBaseUrl + "/"))
                            .GET().build(),
                    java.net.http.HttpResponse.BodyHandlers.ofString()
            );
            if (r.statusCode() == 401 || r.statusCode() == 200) return;
            java.util.concurrent.TimeUnit.SECONDS.sleep(3);
        }
        throw new IllegalStateException("TeamCity did not become ready");
    }

    private static String extractTcSuperUserTokenWithRetry() throws Exception {
        long deadline = System.currentTimeMillis() + Duration.ofSeconds(60).toMillis();
        while (System.currentTimeMillis() < deadline) {
            var result = teamcity.execInContainer(
                    "grep", "-o", "Super user authentication token: [0-9]*",
                    "/opt/teamcity/logs/teamcity-server.log"
            );
            var matcher = java.util.regex.Pattern.compile(
                    "Super user authentication token: (\\d+)"
            ).matcher(result.getStdout().trim());
            if (matcher.find()) return matcher.group(1);
            java.util.concurrent.TimeUnit.SECONDS.sleep(5);
        }
        throw new IllegalStateException("TC super user token not found in log after 60s");
    }

    private static void configureTcServerRootUrl() throws Exception {
        var page = tcHttp.send(
                java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create(tcBaseUrl + "/httpAuth/admin/admin.html?item=serverConfigGeneral"))
                        .header("Authorization", superUserAuthHeader)
                        .GET().build(),
                java.net.http.HttpResponse.BodyHandlers.ofString()
        );
        var csrfMatcher = java.util.regex.Pattern.compile(
                "tc-csrf-token\" content=\"([^\"]+)\""
        ).matcher(page.body());
        if (!csrfMatcher.find()) throw new IllegalStateException("CSRF token not found");
        String csrf = csrfMatcher.group(1);

        // TC_HTTPS_BASE = "https://teamcity-tls" — the Docker-internal Caddy URL
        String encodedUrl = TC_HTTPS_BASE.replace(":", "%3A").replace("/", "%2F");
        String form = "rootUrl=" + encodedUrl + "&submitSettings=store&tc-csrf-token=" + csrf;
        tcHttp.send(
                java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create(tcBaseUrl + "/httpAuth/admin/serverConfigGeneral.html"))
                        .header("Authorization", superUserAuthHeader)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(java.net.http.HttpRequest.BodyPublishers.ofString(form))
                        .build(),
                java.net.http.HttpResponse.BodyHandlers.ofString()
        );
    }

    private static String createTcProjectAndBuildConfig(String audience) throws Exception {
        // Create project
        String projectJson = """
                {"id":"OidcTest","name":"OidcTest","parentProject":{"id":"_Root"}}
                """;
        tcPost("/httpAuth/app/rest/projects", projectJson);

        // Create build config
        String buildConfigJson = """
                {"id":"OidcTest_Build","name":"OidcTest Build","project":{"id":"OidcTest"}}
                """;
        tcPost("/httpAuth/app/rest/buildTypes", buildConfigJson);

        // Add JWT build feature — audience is the Octopus ExternalId GUID
        String featureJson = """
                {"type":"teamcity-jwt","properties":{"property":[
                  {"name":"audience","value":"%s"},
                  {"name":"ttl_minutes","value":"10"},
                  {"name":"enabled_claims","value":"sub,iss,aud"}
                ]}}
                """.formatted(audience);
        tcPost("/httpAuth/app/rest/buildTypes/OidcTest_Build/features", featureJson);

        // Add echo build step
        String stepJson = """
                {"type":"simpleRunner","name":"echo","properties":{"property":[
                  {"name":"script.content","value":"echo running"},
                  {"name":"use.custom.script","value":"true"}
                ]}}
                """;
        tcPost("/httpAuth/app/rest/buildTypes/OidcTest_Build/steps", stepJson);

        return "OidcTest_Build";
    }

    private static void tcPost(String path, String json) throws Exception {
        var response = tcHttp.send(
                java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create(tcBaseUrl + path))
                        .header("Authorization", superUserAuthHeader)
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .POST(java.net.http.HttpRequest.BodyPublishers.ofString(json))
                        .build(),
                java.net.http.HttpResponse.BodyHandlers.ofString()
        );
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException("TC POST " + path + " returned " + response.statusCode() + ": " + response.body());
        }
    }

    private static void authorizeAgent() throws Exception {
        long deadline = System.currentTimeMillis() + Duration.ofMinutes(3).toMillis();
        while (System.currentTimeMillis() < deadline) {
            var response = tcHttp.send(
                    java.net.http.HttpRequest.newBuilder()
                            .uri(java.net.URI.create(
                                    tcBaseUrl + "/httpAuth/app/rest/agents?locator=authorized:false"))
                            .header("Authorization", superUserAuthHeader)
                            .header("Accept", "application/json")
                            .GET().build(),
                    java.net.http.HttpResponse.BodyHandlers.ofString()
            );
            // Parse the first agent id from the JSON
            var matcher = java.util.regex.Pattern.compile("\"id\":(\\d+)")
                    .matcher(response.body());
            if (matcher.find()) {
                String agentId = matcher.group(1);
                tcHttp.send(
                        java.net.http.HttpRequest.newBuilder()
                                .uri(java.net.URI.create(
                                        tcBaseUrl + "/httpAuth/app/rest/agents/id:" + agentId + "/authorized"))
                                .header("Authorization", superUserAuthHeader)
                                .header("Content-Type", "text/plain")
                                .PUT(java.net.http.HttpRequest.BodyPublishers.ofString("true"))
                                .build(),
                        java.net.http.HttpResponse.BodyHandlers.ofString()
                );
                return;
            }
            java.util.concurrent.TimeUnit.SECONDS.sleep(5);
        }
        throw new IllegalStateException("No unauthorized TC agent appeared within 3 minutes");
    }

    private static String octopusGet(String path) throws Exception {
        var response = octopusHttp.send(
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

    private static String octopusPost(String path, String json) throws Exception {
        var response = octopusHttp.send(
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
        String userResponse = octopusPost("/api/users", """
                {"Username":"teamcity-ci","DisplayName":"TeamCity CI",
                 "IsActive":true,"IsService":true,"Identities":[]}
                """);
        var idMatcher = java.util.regex.Pattern.compile("\"Id\":\"(Users-\\d+)\"")
                .matcher(userResponse);
        if (!idMatcher.find()) throw new IllegalStateException(
                "Could not extract user Id from Octopus response: " + userResponse);
        String userId = idMatcher.group(1);

        // Fetch ExternalId — the GUID Octopus expects in the JWT aud claim
        String identitiesResponse = octopusGet(
                "/api/serviceaccounts/" + userId + "/oidcidentities/v1?skip=0&take=1");
        var externalIdMatcher = java.util.regex.Pattern.compile("\"ExternalId\":\"([^\"]+)\"")
                .matcher(identitiesResponse);
        if (!externalIdMatcher.find()) throw new IllegalStateException(
                "Could not extract ExternalId from Octopus response: " + identitiesResponse);

        // Store userId for use in attachOctopusOidcIdentity
        octopusServiceAccountId = userId;
        return externalIdMatcher.group(1);
    }

    private static void attachOctopusOidcIdentity(String externalId) throws Exception {
        octopusPost("/api/serviceaccounts/" + octopusServiceAccountId + "/oidcidentities/create/v1", """
                {"ServiceAccountId":"%s","Name":"TeamCity Build",
                 "Issuer":"%s","Subject":"%s"}
                """.formatted(octopusServiceAccountId, TC_HTTPS_BASE, BUILD_CONFIG_EXTERNAL_ID));
    }

    @Test
    void teamCityJwtIsAcceptedByOctopus() throws Exception {
        fail("not implemented yet");
    }
}
