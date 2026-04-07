package com.octopus.teamcity.oidc.it;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;

import javax.net.ssl.SSLContext;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.Base64;


@Testcontainers
public class OidcFlowIT {

    private static final int TC_PORT = 8111;
    private static final String TC_IMAGE = "jetbrains/teamcity-server:2025.11";
    private static final String AGENT_IMAGE = "jetbrains/teamcity-agent:2025.11";
    private static final String OCTOPUS_IMAGE = "octopusdeploy/octopusdeploy:2024.3";
    private static final String CADDY_IMAGE = "caddy:latest";
    private static final String MSSQL_IMAGE = "mcr.microsoft.com/mssql/server:2022-latest";

    private static final String OCTOPUS_ADMIN_API_KEY = "API-" + "TESTKEY000000000000000000001";
    private static final String OCTOPUS_ADMIN_PASSWORD = "P@ssw0rd123!";
    private static final String MSSQL_PASSWORD = "P@ssw0rd123!";

    private static final String TC_INTERNAL_ALIAS = "teamcity";
    private static final String CADDY_ALIAS = "teamcity-tls";
    private static final String TC_HTTPS_BASE = "https://teamcity-tls";

    private static final String BUILD_CONFIG_EXTERNAL_ID = "OidcTest_Build";
    static String octopusExternalId; // fetched after service account creation, used as JWT audience
    static String octopusServiceAccountId; // fetched after service account creation

    private static final String CONTAINER_PREFIX = "jwt-it-"
            + java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));

    private static final Path PLUGIN_ZIP = requirePluginZip();

    private static Path requirePluginZip() {
        Path zip = Path.of(
                System.getProperty("project.basedir", "."),
                "../target/" + System.getProperty("plugin.zip.name", "Octopus.TeamCity.OIDC.1.0-SNAPSHOT") + ".zip"
        ).normalize();
        if (!zip.toFile().exists()) {
            throw new IllegalStateException(
                    "Plugin zip not found: " + zip.toAbsolutePath() +
                    "\nRun 'mvn package -DskipTests' from the project root first.");
        }
        return zip;
    }

    /**
     * Temp directory bind-mounted as TC's plugins dir.
     * Using a bind mount (not withCopyFileToContainer) so TC can create subdirectories
     * like .bundledTools — docker cp sets root ownership on the parent dir, which
     * prevents the tcuser process from writing into it.
     */
    private static final Path TC_PLUGINS_DIR;
    /**
     * The TC container's JVM cacerts with the test CA cert added, so that
     * JwtTestController's HttpClient can reach Caddy over HTTPS without
     * an SSLHandshakeException. Built on the host (where we have write access)
     * and bind-mounted read-only into the container at startup.
     */
    private static final Path TC_CACERTS_WITH_TEST_CA;
    static {
        try {
            TC_PLUGINS_DIR = Files.createTempDirectory("tc-plugins-");
            Files.copy(PLUGIN_ZIP, TC_PLUGINS_DIR.resolve(System.getProperty("plugin.zip.name", "Octopus.TeamCity.OIDC.1.0-SNAPSHOT") + ".zip"),
                    StandardCopyOption.REPLACE_EXISTING);
            TC_PLUGINS_DIR.toFile().setWritable(true, false);

            TC_CACERTS_WITH_TEST_CA = buildCacertsWithTestCa();
        } catch (Exception e) {
            throw new RuntimeException("Failed to prepare TC runtime files", e);
        }
    }

    /** Copies the host JVM's cacerts and adds the test CA so TC can talk to Caddy. */
    private static Path buildCacertsWithTestCa() throws Exception {
        String javaHome = System.getProperty("java.home");
        Path hostCacerts = Path.of(javaHome, "lib", "security", "cacerts");

        KeyStore ks = KeyStore.getInstance("JKS");
        char[] pass = "changeit".toCharArray();
        if (Files.exists(hostCacerts)) {
            try (InputStream in = Files.newInputStream(hostCacerts)) {
                ks.load(in, pass);
            }
        } else {
            ks.load(null, pass);
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (InputStream in = OidcFlowIT.class.getResourceAsStream("/tls/ca.crt")) {
            ks.setCertificateEntry("test-ca", cf.generateCertificate(in));
        }

        Path tmp = Files.createTempFile("tc-cacerts-", ".jks");
        try (OutputStream out = Files.newOutputStream(tmp)) {
            ks.store(out, pass);
        }
        return tmp;
    }

    static final Network network = Network.newNetwork();

    @Container
    static final GenericContainer<?> mssql = new GenericContainer<>(MSSQL_IMAGE)
            .withNetwork(network)
            .withNetworkAliases("mssql")
            .withExposedPorts(1433)
            .withEnv("ACCEPT_EULA", "Y")
            .withEnv("MSSQL_SA_PASSWORD", MSSQL_PASSWORD)
            .withCreateContainerCmdModifier(cmd -> cmd.withName(CONTAINER_PREFIX + "-mssql"))
            // Wait for SQL Server to be fully initialised and accepting connections,
            // not just the TCP port being open — Octopus will crash if it connects too early
            .waitingFor(Wait.forLogMessage(".*SQL Server is now ready for client connections.*\\n", 1)
                    .withStartupTimeout(Duration.ofMinutes(3)));

    // ADO.NET connection string using the Docker network alias for MSSQL
    private static final String OCTOPUS_DB_CONNECTION_STRING =
            "Server=mssql,1433;Database=Octopus;User Id=sa;Password=" + MSSQL_PASSWORD + ";TrustServerCertificate=true";

    @Container
    static final GenericContainer<?> octopus = new GenericContainer<>(OCTOPUS_IMAGE)
            .withNetwork(network)
            .withNetworkAliases("octopus")
            .withExposedPorts(8080)
            .withEnv("ACCEPT_EULA", "Y")
            .withEnv("DB_CONNECTION_STRING", OCTOPUS_DB_CONNECTION_STRING)
            .withEnv("ADMIN_USERNAME", "admin")
            .withEnv("ADMIN_PASSWORD", OCTOPUS_ADMIN_PASSWORD)
            .withEnv("ADMIN_API_KEY", OCTOPUS_ADMIN_API_KEY)
            .withEnv("DISABLE_DIND", "Y")
            .withCopyFileToContainer(
                    MountableFile.forClasspathResource("tls/ca.crt"),
                    "/usr/local/share/ca-certificates/test-ca.crt"
            )
            .withCreateContainerCmdModifier(cmd -> cmd.withName(CONTAINER_PREFIX + "-octopus"))
            .dependsOn(mssql)
            .waitingFor(Wait.forHttp("/api").forStatusCode(200).withStartupTimeout(Duration.ofMinutes(10)));

    @Container
    static final GenericContainer<?> teamcity = new GenericContainer<>(TC_IMAGE)
            .withNetwork(network)
            .withNetworkAliases(TC_INTERNAL_ALIAS)
            .withExposedPorts(TC_PORT)
            .withEnv("TEAMCITY_SERVER_OPTS", "-Dteamcity.startup.maintenance=false")
            .withFileSystemBind(TC_PLUGINS_DIR.toString(),
                    "/data/teamcity_server/datadir/plugins", BindMode.READ_WRITE)
            // Replace the JVM truststore with one that includes our test CA, so that
            // JwtTestController's HttpClient can reach Caddy over HTTPS.
            .withFileSystemBind(TC_CACERTS_WITH_TEST_CA.toString(),
                    "/opt/java/openjdk/lib/security/cacerts", BindMode.READ_ONLY)
            .withCreateContainerCmdModifier(cmd -> cmd.withName(CONTAINER_PREFIX + "-teamcity"))
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
            .withCreateContainerCmdModifier(cmd -> cmd.withName(CONTAINER_PREFIX + "-caddy"))
            .waitingFor(Wait.forListeningPort().withStartupTimeout(Duration.ofMinutes(1)));

    @Container
    static final GenericContainer<?> agent = new GenericContainer<>(AGENT_IMAGE)
            .withNetwork(network)
            // Connect directly to TC over plain HTTP — the agent doesn't need to go through
            // Caddy and would fail TLS verification anyway (self-signed cert, no custom truststore).
            // The JWT iss claim comes from TC's configured root URL (https://teamcity-tls), not
            // from how the agent connects.
            .withEnv("SERVER_URL", "http://" + TC_INTERNAL_ALIAS + ":" + TC_PORT)
            .withCreateContainerCmdModifier(cmd -> cmd.withName(CONTAINER_PREFIX + "-agent"))
            .dependsOn(teamcity);

    static String tcBaseUrl;       // http://localhost:<mapped TC port> — for test→TC calls
    static String octopusBaseUrl;  // http://localhost:<mapped Octopus port> — for test→Octopus calls
    static String superUserAuthHeader;
    static HttpClient tcHttp;      // talks to TC (plain HTTP from test host)
    static HttpClient octopusHttp; // talks to Octopus (plain HTTP from test host)

    static void log(String msg) {
        System.out.println("[OidcFlowIT] " + java.time.LocalTime.now() + " " + msg);
    }

    @BeforeAll
    static void setup() throws Exception {
        tcBaseUrl = "http://localhost:" + teamcity.getMappedPort(TC_PORT);
        octopusBaseUrl = "http://localhost:" + octopus.getMappedPort(8080);
        log("Containers up. TC=" + tcBaseUrl + " Octopus=" + octopusBaseUrl);

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

        log("Accepting TC license agreement...");
        acceptTcLicenseAgreementIfRequired();
        log("Waiting for TC to be ready...");
        waitForTcReady();

        log("Extracting TC super user token...");
        String token = extractTcSuperUserTokenWithRetry();
        String encoded = java.util.Base64.getEncoder().encodeToString((":" + token).getBytes());
        superUserAuthHeader = "Basic " + encoded;

        log("TC super user token: " + token + "  (login at " + tcBaseUrl + " with empty username)");
        log("Configuring TC root URL to " + TC_HTTPS_BASE + "...");
        configureTcServerRootUrl();
        verifyTcRootUrl();

        log("Creating Octopus service account...");
        octopusExternalId = createOctopusServiceAccount();
        log("Octopus ExternalId=" + octopusExternalId + " userId=" + octopusServiceAccountId);

        log("Creating TC project and build config (audience=" + octopusExternalId + ")...");
        createTcProjectAndBuildConfig(octopusExternalId);

        log("Waiting for TC agent to register...");
        authorizeAgent();

        log("Attaching Octopus OIDC identity...");
        attachOctopusOidcIdentity(octopusExternalId);

        log("Updating CA certificates in Octopus container...");
        octopus.execInContainer("update-ca-certificates");

        log("Waiting for JWT plugin to be ready (JWKS endpoint)...");
        waitForPluginReady();
        log("Setup complete.");
    }

    @AfterAll
    static void dumpContainerLogs() {
        java.nio.file.Path logDir = java.nio.file.Path.of(System.getProperty("java.io.tmpdir"), "tc-it-logs", CONTAINER_PREFIX);
        try {
            Files.createDirectories(logDir);
        } catch (Exception e) {
            log("Could not create log dir: " + e.getMessage());
            return;
        }

        // TC server log — full file for thorough post-mortem
        try {
            var result = teamcity.execInContainer(
                    "cat", "/opt/teamcity/logs/teamcity-server.log");
            Files.writeString(logDir.resolve("teamcity-server.log"),
                    result.getStdout() + result.getStderr());
        } catch (Exception e) {
            log("Could not read TC server log: " + e.getMessage());
        }

        // Container stdout/stderr
        for (var entry : java.util.Map.of(
                "teamcity", teamcity,
                "agent", agent,
                "caddy", caddy,
                "octopus", octopus
        ).entrySet()) {
            try {
                Files.writeString(logDir.resolve(entry.getKey() + ".log"),
                        entry.getValue().getLogs());
            } catch (Exception e) {
                log("Could not write logs for " + entry.getKey() + ": " + e.getMessage());
            }
        }
        log("Container logs written to " + logDir);
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

        String encodedUrl = TC_HTTPS_BASE.replace(":", "%3A").replace("/", "%2F");
        String form = "rootUrl=" + encodedUrl + "&submitSettings=store&tc-csrf-token=" + csrf;
        var postResponse = tcHttp.send(
                java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create(tcBaseUrl + "/httpAuth/admin/serverConfigGeneral.html"))
                        .header("Authorization", superUserAuthHeader)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(java.net.http.HttpRequest.BodyPublishers.ofString(form))
                        .build(),
                java.net.http.HttpResponse.BodyHandlers.ofString()
        );
        if (postResponse.statusCode() < 200 || postResponse.statusCode() >= 300) {
            throw new IllegalStateException("TC root URL POST returned " + postResponse.statusCode());
        }
    }

    private static void verifyTcRootUrl() throws Exception {
        long deadline = System.currentTimeMillis() + Duration.ofMinutes(1).toMillis();
        while (System.currentTimeMillis() < deadline) {
            var response = tcHttp.send(
                    java.net.http.HttpRequest.newBuilder()
                            .uri(java.net.URI.create(tcBaseUrl + "/httpAuth/app/rest/server"))
                            .header("Authorization", superUserAuthHeader)
                            .header("Accept", "application/json")
                            .GET().build(),
                    java.net.http.HttpResponse.BodyHandlers.ofString()
            );
            String rootUrl = (String) parseJson(response.body()).get("webUrl");
            if (TC_HTTPS_BASE.equals(rootUrl)) {
                log("TC root URL confirmed: " + rootUrl);
                return;
            }
            log("TC root URL not yet updated (got: " + rootUrl + "), retrying...");
            java.util.concurrent.TimeUnit.SECONDS.sleep(3);
        }
        throw new IllegalStateException("TC root URL did not update to " + TC_HTTPS_BASE + " within 1 minute");
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
                {"type":"oidc-plugin","properties":{"property":[
                  {"name":"audience","value":"%s"},
                  {"name":"ttl_minutes","value":"10"},
                  {"name":"enabled_claims","value":"sub,iss,aud"}
                ]}}
                """.formatted(audience);
        tcPost("/httpAuth/app/rest/buildTypes/OidcTest_Build/features", featureJson);

        // Write jwt.token to a file artifact so we can retrieve it via the artifacts API.
        // The resulting-properties API masks password parameters; artifact file content is not masked.
        String stepJson = """
                {"type":"simpleRunner","name":"capture-jwt","properties":{"property":[
                  {"name":"script.content","value":"JWT=%jwt.token%\\nprintf 'JWT (first 50): %.50s\\\\n' \\"$JWT\\"\\nprintf '%s' \\"$JWT\\" > jwt.txt"},
                  {"name":"use.custom.script","value":"true"}
                ]}}
                """;
        tcPost("/httpAuth/app/rest/buildTypes/OidcTest_Build/steps", stepJson);

        // Publish jwt.txt as an artifact so the test can download it via the artifacts API
        tcPut("/httpAuth/app/rest/buildTypes/OidcTest_Build/settings/artifactRules", "jwt.txt");

        return "OidcTest_Build";
    }

    @SuppressWarnings("unchecked")
    private static JSONObject parseJson(String body) {
        try {
            return (JSONObject) new JSONParser(JSONParser.DEFAULT_PERMISSIVE_MODE).parse(body);
        } catch (net.minidev.json.parser.ParseException e) {
            throw new IllegalStateException("Failed to parse JSON: " + body, e);
        }
    }

    private static void tcPut(String path, String textBody) throws Exception {
        var response = tcHttp.send(
                java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create(tcBaseUrl + path))
                        .header("Authorization", superUserAuthHeader)
                        .header("Content-Type", "text/plain")
                        .PUT(java.net.http.HttpRequest.BodyPublishers.ofString(textBody))
                        .build(),
                java.net.http.HttpResponse.BodyHandlers.ofString()
        );
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException("TC PUT " + path + " returned " + response.statusCode() + ": " + response.body());
        }
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
            JSONArray agentList = (JSONArray) parseJson(response.body()).get("agent");
            if (agentList != null && !agentList.isEmpty()) {
                String agentId = String.valueOf(((JSONObject) agentList.get(0)).get("id"));
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

    /**
     * Waits until at least one agent is connected, authorized, enabled and has no active build.
     * After authorization the agent must download plugins from TC before it can run builds;
     * triggering a build before the agent is idle leaves it stuck in the queue.
     */
    /**
     * Polls the JWKS endpoint until the JWT plugin has generated its own key material.
     *
     * TC 2025.11 has built-in OIDC support that serves /.well-known/jwks.json and
     * /.well-known/openid-configuration immediately (returning 200 with the correct issuer
     * as soon as the root URL is configured). We must not stop at that — we need to wait
     * until our plugin's own JWKS keys appear in the response.
     *
     * Our plugin generates one RSA key (RS256) and one EC key (ES256).  TC's built-in OIDC
     * does not generate RSA/EC key pairs on first startup (or returns an empty JWKS).
     * We treat ≥1 key in the JWKS as the signal that our plugin has finished initialising.
     */
    /**
     * Polls until both conditions are true:
     *   1. JWKS contains at least one key (our plugin has generated key material — TC's built-in
     *      OIDC may respond with an empty JWKS before our plugin loads).
     *   2. The OIDC discovery issuer equals TC_HTTPS_BASE — this calls buildServer.getRootUrl()
     *      directly through the plugin's own code path, which is the same call made at build time
     *      in JwtBuildStartContext.updateParameters(). Waiting here ensures the root URL change
     *      has fully propagated through TC's internals, not just been committed to the REST API.
     */
    private static void waitForPluginReady() throws Exception {
        long deadline = System.currentTimeMillis() + Duration.ofMinutes(5).toMillis();
        String httpsBase = "https://localhost:" + caddy.getMappedPort(443);
        while (System.currentTimeMillis() < deadline) {
            try {
                var jwksResponse = tcHttp.send(
                        java.net.http.HttpRequest.newBuilder()
                                .uri(java.net.URI.create(httpsBase + "/.well-known/jwks.json"))
                                .GET().build(),
                        java.net.http.HttpResponse.BodyHandlers.ofString()
                );
                if (jwksResponse.statusCode() != 200) {
                    java.util.concurrent.TimeUnit.SECONDS.sleep(5);
                    continue;
                }
                JSONObject jwks = parseJson(jwksResponse.body());
                JSONArray keys = (JSONArray) jwks.get("keys");
                if (keys == null || keys.isEmpty()) {
                    log("JWKS returned 200 but no keys yet (TC built-in?), retrying...");
                    java.util.concurrent.TimeUnit.SECONDS.sleep(5);
                    continue;
                }

                // Also verify the issuer — exercises buildServer.getRootUrl() through the
                // plugin's own code path (WellKnownPublicFilter), same as updateParameters()
                var discoveryResponse = tcHttp.send(
                        java.net.http.HttpRequest.newBuilder()
                                .uri(java.net.URI.create(httpsBase + "/.well-known/openid-configuration"))
                                .GET().build(),
                        java.net.http.HttpResponse.BodyHandlers.ofString()
                );
                if (discoveryResponse.statusCode() == 200) {
                    String issuer = (String) parseJson(discoveryResponse.body()).get("issuer");
                    if (TC_HTTPS_BASE.equals(issuer)) {
                        log("JWT plugin ready (JWKS has " + keys.size() + " key(s), issuer=" + issuer + ").");
                        return;
                    }
                    log("JWKS ready but issuer not yet updated (got: " + issuer + "), retrying...");
                }
            } catch (Exception ignored) {
                // Caddy or TC not ready yet — keep polling
            }
            java.util.concurrent.TimeUnit.SECONDS.sleep(5);
        }
        throw new IllegalStateException("JWT plugin did not become ready with correct issuer within 5 minutes");
    }

    private static void waitForAgentIdle() throws Exception {
        log("Waiting for agent to become idle...");
        long deadline = System.currentTimeMillis() + Duration.ofMinutes(5).toMillis();
        while (System.currentTimeMillis() < deadline) {
            var response = tcHttp.send(
                    java.net.http.HttpRequest.newBuilder()
                            .uri(java.net.URI.create(
                                    tcBaseUrl + "/httpAuth/app/rest/agents"
                                            + "?locator=authorized:true,connected:true,enabled:true"
                                            + "&fields=agent(id,build)"))
                            .header("Authorization", superUserAuthHeader)
                            .header("Accept", "application/json")
                            .GET().build(),
                    java.net.http.HttpResponse.BodyHandlers.ofString()
            );
            JSONArray agentList = (JSONArray) parseJson(response.body()).get("agent");
            if (agentList != null) {
                for (Object item : agentList) {
                    JSONObject agentObj = (JSONObject) item;
                    if (agentObj.get("build") == null) {
                        log("Agent is idle.");
                        return;
                    }
                }
            }
            java.util.concurrent.TimeUnit.SECONDS.sleep(5);
        }
        throw new IllegalStateException("No idle TC agent within 5 minutes");
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
        String userId = (String) parseJson(userResponse).get("Id");
        if (userId == null) throw new IllegalStateException(
                "Could not extract user Id from Octopus response: " + userResponse);

        // Fetch ExternalId — the GUID Octopus expects in the JWT aud claim
        String identitiesResponse = octopusGet(
                "/api/serviceaccounts/" + userId + "/oidcidentities/v1?skip=0&take=1");
        String externalId = (String) parseJson(identitiesResponse).get("ExternalId");
        if (externalId == null) throw new IllegalStateException(
                "Could not extract ExternalId from Octopus response: " + identitiesResponse);

        // Store userId for use in attachOctopusOidcIdentity
        octopusServiceAccountId = userId;
        return externalId;
    }

    private static void attachOctopusOidcIdentity(String externalId) throws Exception {
        octopusPost("/api/serviceaccounts/" + octopusServiceAccountId + "/oidcidentities/create/v1", """
                {"ServiceAccountId":"%s","Name":"TeamCity Build",
                 "Issuer":"%s","Subject":"%s"}
                """.formatted(octopusServiceAccountId, TC_HTTPS_BASE, BUILD_CONFIG_EXTERNAL_ID));
    }

    @Test
    void teamCityJwtIsAcceptedByOctopus() throws Exception {
        // 1. Wait for agent idle, then trigger build
        waitForAgentIdle();
        log("Triggering build...");
        String queueResponse = triggerBuild();
        String buildId = String.valueOf(parseJson(queueResponse).get("id"));
        if (buildId == null || buildId.equals("null")) throw new IllegalStateException(
                "Could not parse build id from: " + queueResponse);
        log("Build queued, id=" + buildId);

        // 2. Wait for build to finish
        log("Waiting for build to finish...");
        waitForBuildSuccess(buildId);
        log("Build finished successfully.");

        // 3. Extract jwt.token from artifact
        log("Extracting JWT from build artifact...");
        String jwt = extractJwtFromBuild(buildId);
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
        String accessToken = exchangeJwtWithOctopus(jwt);
        org.assertj.core.api.Assertions.assertThat(accessToken)
                .as("Octopus must return a non-blank access_token")
                .isNotBlank();
        log("Octopus accepted the JWT and returned an access token.");

        // 6. Verify the access token works — call /api/users/me with it
        log("Verifying access token against /api/users/me...");
        var meResponse = octopusHttp.send(
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

    private static String triggerBuild() throws Exception {
        String body = """
                {"buildType":{"id":"OidcTest_Build"}}
                """;
        var response = tcHttp.send(
                java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create(tcBaseUrl + "/httpAuth/app/rest/buildQueue"))
                        .header("Authorization", superUserAuthHeader)
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body))
                        .build(),
                java.net.http.HttpResponse.BodyHandlers.ofString()
        );
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException("Failed to queue build: " + response.statusCode() + " " + response.body());
        }
        return response.body();
    }

    private static void waitForBuildSuccess(String buildId) throws Exception {
        long deadline = System.currentTimeMillis() + Duration.ofMinutes(3).toMillis();
        String lastState = null;
        while (System.currentTimeMillis() < deadline) {
            var response = tcHttp.send(
                    java.net.http.HttpRequest.newBuilder()
                            .uri(java.net.URI.create(
                                    tcBaseUrl + "/httpAuth/app/rest/builds/id:" + buildId))
                            .header("Authorization", superUserAuthHeader)
                            .header("Accept", "application/json")
                            .GET().build(),
                    java.net.http.HttpResponse.BodyHandlers.ofString()
            );
            JSONObject build = parseJson(response.body());
            String state = String.valueOf(build.get("state"));
            String status = String.valueOf(build.get("status"));
            if (!state.equals(lastState)) {
                log("Build " + buildId + " state=" + state + " status=" + status);
                lastState = state;
            }
            if ("finished".equals(state)) {
                saveBuildLog(buildId);
                if (!"SUCCESS".equals(status)) {
                    throw new IllegalStateException(
                            "Build " + buildId + " finished with non-SUCCESS status: " + response.body());
                }
                return;
            }
            java.util.concurrent.TimeUnit.SECONDS.sleep(5);
        }
        throw new IllegalStateException("Build " + buildId + " did not finish within 3 minutes");
    }

    private static void saveBuildLog(String buildId) {
        try {
            var response = tcHttp.send(
                    java.net.http.HttpRequest.newBuilder()
                            .uri(java.net.URI.create(
                                    tcBaseUrl + "/httpAuth/downloadBuildLog.html?buildId=" + buildId))
                            .header("Authorization", superUserAuthHeader)
                            .GET().build(),
                    java.net.http.HttpResponse.BodyHandlers.ofString()
            );
            java.nio.file.Path logDir = java.nio.file.Path.of(
                    System.getProperty("java.io.tmpdir"), "tc-it-logs", CONTAINER_PREFIX);
            Files.createDirectories(logDir);
            Files.writeString(logDir.resolve("build-" + buildId + ".log"), response.body());
            log("Build log saved to " + logDir.resolve("build-" + buildId + ".log")
                    + " (status=" + response.statusCode() + ")");
        } catch (Exception e) {
            log("Could not save build log: " + e.getMessage());
        }
    }

    private static String extractJwtFromBuild(String buildId) throws Exception {
        // jwt.token is a password parameter — masked in resulting-properties.
        // The build step writes it to jwt.txt; we download that artifact instead.
        var response = tcHttp.send(
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

    private static void verifyJwtClaims(String jwt) throws Exception {
        com.nimbusds.jwt.SignedJWT parsed = com.nimbusds.jwt.SignedJWT.parse(jwt);
        com.nimbusds.jwt.JWTClaimsSet claims = parsed.getJWTClaimsSet();

        org.assertj.core.api.Assertions.assertThat(claims.getIssuer())
                .as("iss must equal TC_HTTPS_BASE").isEqualTo(TC_HTTPS_BASE);
        org.assertj.core.api.Assertions.assertThat(claims.getAudience())
                .as("aud must contain octopusExternalId").contains(octopusExternalId);
        org.assertj.core.api.Assertions.assertThat(claims.getExpirationTime())
                .as("JWT must not be expired").isAfter(new java.util.Date());

        // Verify signature against the JWKS served by TC (via Caddy TLS)
        // tcHttp trusts the self-signed cert via TlsTrustManager
        var jwksResponse = tcHttp.send(
                java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create(
                                "https://localhost:" + caddy.getMappedPort(443) + "/.well-known/jwks.json"))
                        .GET().build(),
                java.net.http.HttpResponse.BodyHandlers.ofString()
        );
        com.nimbusds.jose.jwk.JWKSet jwks = com.nimbusds.jose.jwk.JWKSet.parse(jwksResponse.body());
        com.nimbusds.jose.jwk.source.ImmutableJWKSet<com.nimbusds.jose.proc.SecurityContext> keySource =
                new com.nimbusds.jose.jwk.source.ImmutableJWKSet<>(jwks);
        com.nimbusds.jose.proc.JWSVerificationKeySelector<com.nimbusds.jose.proc.SecurityContext> keySelector =
                new com.nimbusds.jose.proc.JWSVerificationKeySelector<>(
                        parsed.getHeader().getAlgorithm(), keySource);
        com.nimbusds.jwt.proc.DefaultJWTProcessor<com.nimbusds.jose.proc.SecurityContext> processor =
                new com.nimbusds.jwt.proc.DefaultJWTProcessor<>();
        processor.setJWSKeySelector(keySelector);
        processor.process(parsed, null); // throws if signature invalid
    }

    private static String exchangeJwtWithOctopus(String jwt) throws Exception {
        // Discover token endpoint from Octopus's own OIDC discovery doc
        var discoveryResponse = octopusHttp.send(
                java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create(octopusBaseUrl + "/.well-known/openid-configuration"))
                        .GET().build(),
                java.net.http.HttpResponse.BodyHandlers.ofString()
        );
        String tokenEndpointStr = (String) parseJson(discoveryResponse.body()).get("token_endpoint");
        if (tokenEndpointStr == null) throw new IllegalStateException(
                "token_endpoint not found in Octopus discovery doc: " + discoveryResponse.body());

        // Rewrite the token endpoint to use the mapped localhost URL
        java.net.URI rawEndpoint = java.net.URI.create(tokenEndpointStr);
        java.net.URI tokenEndpoint = java.net.URI.create(
                octopusBaseUrl + rawEndpoint.getRawPath()
                + (rawEndpoint.getRawQuery() != null ? "?" + rawEndpoint.getRawQuery() : ""));

        // Exchange the JWT — anonymous (no API key)
        String exchangeBody = """
                {"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange",
                 "audience":"%s",
                 "subject_token":"%s",
                 "subject_token_type":"urn:ietf:params:oauth:token-type:jwt"}
                """.formatted(octopusExternalId, jwt);

        var exchangeResponse = octopusHttp.send(
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

        String accessToken = (String) parseJson(exchangeResponse.body()).get("access_token");
        if (accessToken == null) throw new IllegalStateException(
                "access_token not found in Octopus response: " + exchangeResponse.body());
        return accessToken;
    }

    /**
     * Blocks until Enter is pressed, keeping all containers alive for manual UI testing.
     *
     * Run with:
     *   TESTCONTAINERS_RYUK_DISABLED=true \
     *   JAVA_HOME=$(jenv prefix 21) \
     *   mvn verify -pl integration-tests -Dit.test=OidcFlowIT#manualTestingPause -Dmanual
     *
     * Add to /etc/hosts (once):
     *   127.0.0.1  teamcity-tls
     *
     * Then browse to https://teamcity-tls:<port> printed below.
     * Accept the cert warning (self-signed CA), log in with empty username + the token below.
     */
    @Test
    void manualTestingPause() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(
                System.getProperty("manual") != null,
                "Skipped — pass -Dmanual to activate manual testing pause"
        );

        int caddyPort = caddy.getMappedPort(443);
        String httpsUrl = "https://teamcity-tls:" + caddyPort;
        // superUserAuthHeader is "Basic <base64(:token)>" — decode and split on ":" to get the token
        String superUserToken = superUserAuthHeader.replace("Basic ", "");
        String decodedToken = new String(Base64.getDecoder().decode(superUserToken)).split(":", 2)[1];

        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════════╗");
        System.out.println("║  Stack is ready for manual testing                               ║");
        System.out.println("║                                                                  ║");
        System.out.printf( "║  TeamCity:    %-51s║%n", httpsUrl);
        System.out.printf( "║  Login:       %-51s║%n", "(empty username)");
        System.out.printf( "║  Password:    %-51s║%n", decodedToken);
        System.out.println("║                                                                  ║");
        System.out.printf( "║  Octopus (browser): %-47s║%n", octopusBaseUrl);
        System.out.printf( "║  Octopus (Try Exchange URL): %-38s║%n", "http://octopus:8080");
        System.out.printf( "║  API key:     %-51s║%n", OCTOPUS_ADMIN_API_KEY);
        System.out.printf( "║  Octopus ExternalId (JWT aud): %-35s║%n", octopusExternalId);
        System.out.println("║                                                                  ║");
        System.out.println("║  /etc/hosts:  127.0.0.1  teamcity-tls                           ║");
        System.out.println("║  Cert warning: accept in browser (self-signed CA)               ║");
        System.out.println("║                                                                  ║");
        System.out.println("║  Press Ctrl+C to stop all containers                            ║");
        System.out.println("╚══════════════════════════════════════════════════════════════════╝");
        System.out.println();

        Thread.sleep(Long.MAX_VALUE);
    }
}
