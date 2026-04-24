package com.octopus.teamcity.oidc.it;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;

import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Base64;


@Testcontainers
public class OidcFlowIT {

    private static final int TC_PORT = 8111;
    private static final String TC_IMAGE = "jetbrains/teamcity-server:2025.11";
    private static final String AGENT_IMAGE = "jetbrains/teamcity-agent:2025.11";
    private static final String OCTOPUS_IMAGE = "octopusdeploy/octopusdeploy:2025.4";
    private static final String CADDY_IMAGE = "caddy:2";
    private static final String MSSQL_IMAGE = "mcr.microsoft.com/mssql/server:2022-latest";

    private static final String OCTOPUS_ADMIN_API_KEY = generateApiKey();

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

    private static String generateApiKey() {
        final var rng = new java.security.SecureRandom();
        final var sb = new StringBuilder("API-FAKEKEY");
        for (var i = 0; i < 21; i++) sb.append(rng.nextInt(10));
        return sb.toString();
    }

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

    /** Generated at test startup — CA and server cert/key for the Caddy TLS proxy. */
    private static final TlsCertificateGenerator.Result TLS;
    /**
     * The TC container's JVM cacerts with the test CA cert added, so that
     * JwtTestController's HttpClient can reach Caddy over HTTPS without
     * an SSLHandshakeException. Built on the host (where we have write access)
     * and bind-mounted read-only into the container at startup.
     */
    private static final Path TC_CACERTS_WITH_TEST_CA;
    static {
        try {
            // Include TESTCONTAINERS_HOST_OVERRIDE (e.g. "docker" in DinD) as a SAN so
            // that TLS verification succeeds when connecting via the mapped port host.
            final var tcHostOverride = System.getenv("TESTCONTAINERS_HOST_OVERRIDE");
            TLS = (tcHostOverride != null && !tcHostOverride.isBlank())
                    ? TlsCertificateGenerator.generate(CADDY_ALIAS, "localhost", tcHostOverride)
                    : TlsCertificateGenerator.generate(CADDY_ALIAS, "localhost");
            TC_CACERTS_WITH_TEST_CA = buildCacertsWithTestCa(TLS.caCert());
        } catch (final Exception e) {
            throw new RuntimeException("Failed to prepare TC runtime files", e);
        }
    }

    /** Copies the host JVM's cacerts and adds the test CA so TC can talk to Caddy. */
    private static Path buildCacertsWithTestCa(final java.security.cert.Certificate caCert) throws Exception {
        final var javaHome = System.getProperty("java.home");
        final var hostCacerts = Path.of(javaHome, "lib", "security", "cacerts");

        final var ks = KeyStore.getInstance("JKS");
        final var pass = "changeit".toCharArray();
        if (Files.exists(hostCacerts)) {
            try (final var in = Files.newInputStream(hostCacerts)) {
                ks.load(in, pass);
            }
        } else {
            ks.load(null, pass);
        }

        ks.setCertificateEntry("test-ca", caCert);

        final var tmp = Files.createTempFile("tc-cacerts-", ".jks");
        try (final var out = Files.newOutputStream(tmp)) {
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
                    MountableFile.forHostPath(TLS.caCertPem().toString()),
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
            .withEnv("TEAMCITY_SERVER_OPTS", "-Dteamcity.startup.maintenance=false"
                    // octopus-tls resolves to a Docker-internal (site-local) IP — bypass the
                    // private-address SSRF check so Try Exchange can reach it in this test env.
                    + " -Dteamcity.oidc.allowPrivateExchangeUrls=true")
            // Copy the plugin zip via the Docker API so it works with a remote (DinD) daemon.
            // withFileSystemBind would fail because the DinD daemon can't see paths inside
            // the Maven container's /tmp.
            .withCopyFileToContainer(
                    MountableFile.forHostPath(PLUGIN_ZIP.toString()),
                    "/data/teamcity_server/datadir/plugins/" + PLUGIN_ZIP.getFileName())
            // Replace the JVM truststore with one that includes our test CA, so that
            // JwtTestController's HttpClient can reach Caddy over HTTPS.
            .withCopyFileToContainer(
                    MountableFile.forHostPath(TC_CACERTS_WITH_TEST_CA.toString()),
                    "/opt/java/openjdk/lib/security/cacerts")
            .withCreateContainerCmdModifier(cmd -> {
                cmd.withName(CONTAINER_PREFIX + "-teamcity");
                // Docker's withCopyFileToContainer creates the plugins/ directory as root:root,
                // which prevents tcuser from creating subdirectories (.tools, .bundledTools).
                // Fix: start as root, chown the directory, then exec TC as tcuser.
                cmd.withUser("root");
                cmd.withCmd("/bin/sh", "-c",
                        // Make the custom cacerts world-readable (withCopyFileToContainer
                        // copies with the host file's mode; if it's 0600 the tcuser JVM
                        // can't read it, causing SSLContext to initialise with no trust
                        // anchors and all outbound TLS connections to fail).
                        "chmod 644 /opt/java/openjdk/lib/security/cacerts" +
                        " && chown -R tcuser:tcuser /data/teamcity_server/datadir/plugins" +
                        " && exec runuser -u tcuser -- /run-services.sh");
            })
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
                    MountableFile.forHostPath(TLS.serverCertPem().toString()),
                    "/etc/caddy/tls/server.crt"
            )
            .withCopyFileToContainer(
                    MountableFile.forHostPath(TLS.serverKeyPem().toString()),
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

    static void log(final String msg) {
        System.out.println("[OidcFlowIT] " + java.time.LocalTime.now() + " " + msg);
    }

    @BeforeAll
    static void setup() throws Exception {
        tcBaseUrl = "http://" + teamcity.getHost() + ":" + teamcity.getMappedPort(TC_PORT);
        octopusBaseUrl = "http://" + octopus.getHost() + ":" + octopus.getMappedPort(8080);
        log("Containers up. TC=" + tcBaseUrl + " Octopus=" + octopusBaseUrl);

        final var ssl = TlsTrustManager.buildSslContext(TLS.caCert());
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
        final var token = extractTcSuperUserTokenWithRetry();
        final var encoded = java.util.Base64.getEncoder().encodeToString((":" + token).getBytes());
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

    private static void acceptTcLicenseAgreementIfRequired() throws Exception {
        final var deadline = System.currentTimeMillis() + Duration.ofMinutes(2).toMillis();
        while (System.currentTimeMillis() < deadline) {
            final var result = teamcity.execInContainer(
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
        final var deadline = System.currentTimeMillis() + Duration.ofMinutes(5).toMillis();
        while (System.currentTimeMillis() < deadline) {
            final var r = tcHttp.send(
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
        final var deadline = System.currentTimeMillis() + Duration.ofSeconds(60).toMillis();
        while (System.currentTimeMillis() < deadline) {
            final var result = teamcity.execInContainer(
                    "grep", "-o", "Super user authentication token: [0-9]*",
                    "/opt/teamcity/logs/teamcity-server.log"
            );
            final var matcher = java.util.regex.Pattern.compile(
                    "Super user authentication token: (\\d+)"
            ).matcher(result.getStdout().trim());
            if (matcher.find()) return matcher.group(1);
            java.util.concurrent.TimeUnit.SECONDS.sleep(5);
        }
        throw new IllegalStateException("TC super user token not found in log after 60s");
    }

    private static void configureTcServerRootUrl() throws Exception {
        final var page = tcHttp.send(
                java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create(tcBaseUrl + "/httpAuth/admin/admin.html?item=serverConfigGeneral"))
                        .header("Authorization", superUserAuthHeader)
                        .GET().build(),
                java.net.http.HttpResponse.BodyHandlers.ofString()
        );
        final var csrfMatcher = java.util.regex.Pattern.compile(
                "tc-csrf-token\" content=\"([^\"]+)\""
        ).matcher(page.body());
        if (!csrfMatcher.find()) throw new IllegalStateException("CSRF token not found");
        final var csrf = csrfMatcher.group(1);

        final var encodedUrl = TC_HTTPS_BASE.replace(":", "%3A").replace("/", "%2F");
        final var form = "rootUrl=" + encodedUrl + "&submitSettings=store&tc-csrf-token=" + csrf;
        final var postResponse = tcHttp.send(
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
        final var deadline = System.currentTimeMillis() + Duration.ofMinutes(1).toMillis();
        while (System.currentTimeMillis() < deadline) {
            final var response = tcHttp.send(
                    java.net.http.HttpRequest.newBuilder()
                            .uri(java.net.URI.create(tcBaseUrl + "/httpAuth/app/rest/server"))
                            .header("Authorization", superUserAuthHeader)
                            .header("Accept", "application/json")
                            .GET().build(),
                    java.net.http.HttpResponse.BodyHandlers.ofString()
            );
            final var rootUrl = (String) parseJson(response.body()).get("webUrl");
            if (TC_HTTPS_BASE.equals(rootUrl)) {
                log("TC root URL confirmed: " + rootUrl);
                return;
            }
            log("TC root URL not yet updated (got: " + rootUrl + "), retrying...");
            java.util.concurrent.TimeUnit.SECONDS.sleep(3);
        }
        throw new IllegalStateException("TC root URL did not update to " + TC_HTTPS_BASE + " within 1 minute");
    }

    private static void createTcProjectAndBuildConfig(final String audience) throws Exception {
        // Create project
        final var projectJson = """
                {"id":"OidcTest","name":"OidcTest","parentProject":{"id":"_Root"}}
                """;
        tcPost("/httpAuth/app/rest/projects", projectJson);

        // Create build config
        final var buildConfigJson = """
                {"id":"OidcTest_Build","name":"OidcTest Build","project":{"id":"OidcTest"}}
                """;
        tcPost("/httpAuth/app/rest/buildTypes", buildConfigJson);

        // Add JWT build feature — audience is the Octopus ExternalId GUID
        final var featureJson = """
                {"type":"oidc-plugin","properties":{"property":[
                  {"name":"audience","value":"%s"},
                  {"name":"ttl_minutes","value":"10"},
                  {"name":"enabled_claims","value":"sub,iss,aud"}
                ]}}
                """.formatted(audience);
        tcPost("/httpAuth/app/rest/buildTypes/OidcTest_Build/features", featureJson);

        // Write jwt.token to a file artifact so we can retrieve it via the artifacts API.
        // The resulting-properties API masks password parameters; artifact file content is not masked.
        final var stepJson = """
                {"type":"simpleRunner","name":"capture-jwt","properties":{"property":[
                  {"name":"script.content","value":"JWT=%jwt.token%\\nprintf 'JWT (first 50): %.50s\\\\n' \\"$JWT\\"\\nprintf '%s' \\"$JWT\\" > jwt.txt"},
                  {"name":"use.custom.script","value":"true"}
                ]}}
                """;
        tcPost("/httpAuth/app/rest/buildTypes/OidcTest_Build/steps", stepJson);

        // Publish jwt.txt as an artifact so the test can download it via the artifacts API
        tcPut("/httpAuth/app/rest/buildTypes/OidcTest_Build/settings/artifactRules", "jwt.txt");

    }

    private static JSONObject parseJson(final String body) {
        try {
            return (JSONObject) new JSONParser(JSONParser.DEFAULT_PERMISSIVE_MODE).parse(body);
        } catch (final net.minidev.json.parser.ParseException e) {
            throw new IllegalStateException("Failed to parse JSON: " + body, e);
        }
    }

    private static void tcPut(final String path, final String textBody) throws Exception {
        final var response = tcHttp.send(
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

    private static void tcPost(final String path, final String json) throws Exception {
        final var response = tcHttp.send(
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
        final var deadline = System.currentTimeMillis() + Duration.ofMinutes(3).toMillis();
        while (System.currentTimeMillis() < deadline) {
            final var response = tcHttp.send(
                    java.net.http.HttpRequest.newBuilder()
                            .uri(java.net.URI.create(
                                    tcBaseUrl + "/httpAuth/app/rest/agents?locator=authorized:false"))
                            .header("Authorization", superUserAuthHeader)
                            .header("Accept", "application/json")
                            .GET().build(),
                    java.net.http.HttpResponse.BodyHandlers.ofString()
            );
            final var agentList = (JSONArray) parseJson(response.body()).get("agent");
            if (agentList != null && !agentList.isEmpty()) {
                final var agentId = String.valueOf(((JSONObject) agentList.getFirst()).get("id"));
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
                final var jwks = parseJson(jwksResponse.body());
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
                    final var issuer = (String) parseJson(discoveryResponse.body()).get("issuer");
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

    private static void waitForAgentIdle() throws Exception {
        log("Waiting for agent to become idle...");
        final var deadline = System.currentTimeMillis() + Duration.ofMinutes(5).toMillis();
        while (System.currentTimeMillis() < deadline) {
            final var response = tcHttp.send(
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
            final var agentList = (JSONArray) parseJson(response.body()).get("agent");
            if (agentList != null) {
                for (final var item : agentList) {
                    final var agentObj = (JSONObject) item;
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
        final var userId = (String) parseJson(userResponse).get("Id");
        if (userId == null) throw new IllegalStateException(
                "Could not extract user Id from Octopus response: " + userResponse);

        // Fetch ExternalId — the GUID Octopus expects in the JWT aud claim
        final var identitiesResponse = octopusGet(
                "/api/serviceaccounts/" + userId + "/oidcidentities/v1?skip=0&take=1");
        final var externalId = (String) parseJson(identitiesResponse).get("ExternalId");
        if (externalId == null) throw new IllegalStateException(
                "Could not extract ExternalId from Octopus response: " + identitiesResponse);

        // Store userId for use in attachOctopusOidcIdentity
        octopusServiceAccountId = userId;
        return externalId;
    }

    private static void attachOctopusOidcIdentity() throws Exception {
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
        final var queueResponse = triggerBuild();
        final var buildId = String.valueOf(parseJson(queueResponse).get("id"));
        if (buildId == null || buildId.equals("null")) throw new IllegalStateException(
                "Could not parse build id from: " + queueResponse);
        log("Build queued, id=" + buildId);

        // 2. Wait for build to finish
        log("Waiting for build to finish...");
        waitForBuildSuccess(buildId);
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

    private static String triggerBuild() throws Exception {
        final var body = """
                {"buildType":{"id":"OidcTest_Build"}}
                """;
        final var response = tcHttp.send(
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

    private static void waitForBuildSuccess(final String buildId) throws Exception {
        final var deadline = System.currentTimeMillis() + Duration.ofMinutes(3).toMillis();
        String lastState = null;
        while (System.currentTimeMillis() < deadline) {
            final var response = tcHttp.send(
                    java.net.http.HttpRequest.newBuilder()
                            .uri(java.net.URI.create(
                                    tcBaseUrl + "/httpAuth/app/rest/builds/id:" + buildId))
                            .header("Authorization", superUserAuthHeader)
                            .header("Accept", "application/json")
                            .GET().build(),
                    java.net.http.HttpResponse.BodyHandlers.ofString()
            );
            final var build = parseJson(response.body());
            final var state = String.valueOf(build.get("state"));
            final var status = String.valueOf(build.get("status"));
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

    private static void saveBuildLog(final String buildId) {
        try {
            final var response = tcHttp.send(
                    java.net.http.HttpRequest.newBuilder()
                            .uri(java.net.URI.create(
                                    tcBaseUrl + "/httpAuth/downloadBuildLog.html?buildId=" + buildId))
                            .header("Authorization", superUserAuthHeader)
                            .GET().build(),
                    java.net.http.HttpResponse.BodyHandlers.ofString()
            );
            final var logDir = java.nio.file.Path.of(
                    System.getProperty("java.io.tmpdir"), "tc-it-logs", CONTAINER_PREFIX);
            Files.createDirectories(logDir);
            Files.writeString(logDir.resolve("build-" + buildId + ".log"), response.body());
            log("Build log saved to " + logDir.resolve("build-" + buildId + ".log")
                    + " (status=" + response.statusCode() + ")");
        } catch (final Exception e) {
            log("Could not save build log: " + e.getMessage());
        }
    }

    private static String extractJwtFromBuild(final String buildId) throws Exception {
        // jwt.token is a password parameter — masked in resulting-properties.
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
        final var tokenEndpointStr = (String) parseJson(discoveryResponse.body()).get("token_endpoint");
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

        final var accessToken = (String) parseJson(exchangeResponse.body()).get("access_token");
        if (accessToken == null) throw new IllegalStateException(
                "access_token not found in Octopus response: " + exchangeResponse.body());
        return accessToken;
    }

    /**
     * Blocks until Enter is pressed, keeping all containers alive for manual UI testing.
     * Run with:
     *   TESTCONTAINERS_RYUK_DISABLED=true \
     *   JAVA_HOME=$(jenv prefix 21) \
     *   mvn verify -pl integration-tests -Dit.test=OidcFlowIT#manualTestingPause -Dmanual
     * Add to /etc/hosts (once):
     *   127.0.0.1  teamcity-tls
     * Then browse to https://teamcity-tls:<port> printed below.
     * Accept the cert warning (self-signed CA), log in with empty username + the token below.
     */
    @Test
    void manualTestingPause() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(
                System.getProperty("manual") != null,
                "Skipped — pass -Dmanual to activate manual testing pause"
        );

        final int caddyPort = caddy.getMappedPort(443);
        final var httpsUrl = "https://teamcity-tls:" + caddyPort;
        // superUserAuthHeader is "Basic <base64(:token)>" — decode and split on ":" to get the token
        final var superUserToken = superUserAuthHeader.replace("Basic ", "");
        final var decodedToken = new String(Base64.getDecoder().decode(superUserToken)).split(":", 2)[1];

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
