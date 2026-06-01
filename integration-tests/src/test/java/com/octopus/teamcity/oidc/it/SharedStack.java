package com.octopus.teamcity.oidc.it;

import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.PortBinding;
import com.github.dockerjava.api.model.Ports;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;

/**
 * The full integration-test stack (Docker network + MSSQL + Octopus + TeamCity + Caddy TLS proxy
 * + build agent), started <b>once per JVM</b> and shared across the integration tests that can
 * tolerate a shared TeamCity server.
 * <p>
 * This deliberately uses the Testcontainers <i>singleton container</i> pattern — containers are
 * static fields started manually via {@link #ensureStarted()} and are <b>not</b> annotated with
 * {@code @Container}/{@code @Testcontainers}, which would stop them after each test class. Ryuk
 * reaps them at JVM exit (in manual mode, {@code TESTCONTAINERS_RYUK_DISABLED=true} keeps them up
 * for inspection and the {@code docker rm -f} teardown in CLAUDE.md applies).
 * <p>
 * <b>Single-fork assumption:</b> sharing relies on all IT classes running in one JVM. Maven
 * Failsafe's defaults ({@code forkCount=1}, {@code reuseForks=true}, no parallelism) guarantee
 * this. If a future change adds {@code forkCount > 1} or parallel execution, each fork would spin
 * up its own stack — revisit this class then.
 * <p>
 * Each consuming test class still runs its own {@code @BeforeAll} to bring the shared server into
 * the global configuration it needs (e.g. root URL): the root URL is global server state, so
 * classes that disagree on it (JwtPluginIT wants {@code http://localhost:<port>}, OidcFlowIT wants
 * {@code https://teamcity-tls}) each re-set it before their tests, which is safe because classes
 * run sequentially. KeyRotationWarmupIT is the one test that cannot share the server (it asserts
 * on pristine global signing-key state), so it keeps its own container and only reuses
 * {@link TeamCityClient}.
 */
final class SharedStack {

    private SharedStack() {
    }

    static final int TC_PORT = 8111;
    /**
     * Fixed host port for the TeamCity container in manual mode (-Dmanual). Stable across restarts
     * so the browser URL doesn't change. CI uses the auto-allocated port to avoid clashes.
     */
    private static final int MANUAL_TC_HOST_PORT = 18111;
    private static final boolean MANUAL_MODE = System.getProperty("manual") != null;

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
    private static final String TC_ALT_ALIAS = "teamcity-public-tls";
    private static final String OCTOPUS_CADDY_ALIAS = "octopus-tls";

    /** TC root URL / JWT issuer when fronted by the Caddy TLS proxy. */
    static final String TC_HTTPS_BASE = "https://teamcity-tls";

    static final String CONTAINER_PREFIX = "jwt-it-"
            + java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));

    private static final Path PLUGIN_ZIP = requirePluginZip();

    /** Generated at startup — CA and server cert/key for the Caddy TLS proxy. */
    private static final TlsCertificateGenerator.Result TLS;
    /**
     * The TC container's JVM cacerts with the test CA added, so JwtTestController's HttpClient can
     * reach Caddy over HTTPS without an SSLHandshakeException. Built on the host (where we have
     * write access) and copied into the container at startup.
     */
    private static final Path TC_CACERTS_WITH_TEST_CA;

    static {
        try {
            // All three aliases are always included as SANs: the Caddy container always gets all
            // three network aliases regardless of environment. TESTCONTAINERS_HOST_OVERRIDE adds
            // an extra SAN so TLS verification also succeeds via the mapped-port host in DinD.
            final var tcHostOverride = System.getenv("TESTCONTAINERS_HOST_OVERRIDE");
            TLS = (tcHostOverride != null && !tcHostOverride.isBlank())
                    ? TlsCertificateGenerator.generate(CADDY_ALIAS, TC_ALT_ALIAS, OCTOPUS_CADDY_ALIAS, "localhost", tcHostOverride)
                    : TlsCertificateGenerator.generate(CADDY_ALIAS, TC_ALT_ALIAS, OCTOPUS_CADDY_ALIAS, "localhost");
            TC_CACERTS_WITH_TEST_CA = buildCacertsWithTestCa(TLS.caCert());
        } catch (final Exception e) {
            throw new RuntimeException("Failed to prepare TC runtime files", e);
        }
    }

    private static final Network NETWORK = Network.newNetwork();

    private static final GenericContainer<?> MSSQL = new GenericContainer<>(MSSQL_IMAGE)
            .withNetwork(NETWORK)
            .withNetworkAliases("mssql")
            .withExposedPorts(1433)
            .withEnv("ACCEPT_EULA", "Y")
            .withEnv("MSSQL_SA_PASSWORD", MSSQL_PASSWORD)
            .withCreateContainerCmdModifier(cmd -> cmd.withName(CONTAINER_PREFIX + "-mssql"))
            // Wait for SQL Server to be fully initialized and accepting connections, not just the
            // TCP port being open — Octopus will crash if it connects too early.
            .waitingFor(Wait.forLogMessage(".*SQL Server is now ready for client connections.*\\n", 1)
                    .withStartupTimeout(Duration.ofMinutes(3)));

    // ADO.NET connection string using the Docker network alias for MSSQL
    private static final String OCTOPUS_DB_CONNECTION_STRING =
            "Server=mssql,1433;Database=Octopus;User Id=sa;Password=" + MSSQL_PASSWORD + ";TrustServerCertificate=true";

    private static final GenericContainer<?> OCTOPUS = new GenericContainer<>(OCTOPUS_IMAGE)
            .withNetwork(NETWORK)
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
                    "/usr/local/share/ca-certificates/test-ca.crt")
            .withCreateContainerCmdModifier(cmd -> cmd.withName(CONTAINER_PREFIX + "-octopus"))
            .dependsOn(MSSQL)
            .waitingFor(Wait.forHttp("/api").forStatusCode(200).withStartupTimeout(Duration.ofMinutes(10)));

    private static final GenericContainer<?> TEAMCITY = new GenericContainer<>(TC_IMAGE)
            .withNetwork(NETWORK)
            .withNetworkAliases(TC_INTERNAL_ALIAS)
            .withExposedPorts(TC_PORT)
            .withEnv("TEAMCITY_SERVER_OPTS", "-Dteamcity.startup.maintenance=false"
                    // octopus-tls resolves to a Docker-internal (site-local) IP — bypass the
                    // private-address SSRF check so Try Exchange can reach it in this test env.
                    + " -Dteamcity.oidc.allowPrivateExchangeUrls=true")
            // Copy the plugin zip via the Docker API so it works with a remote (DinD) daemon.
            // withFileSystemBind would fail because the DinD daemon can't see paths inside the
            // Maven container's /tmp.
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
                        // Make the custom cacerts world-readable (withCopyFileToContainer copies
                        // with the host file's mode; if it's 0600 the tcuser JVM can't read it,
                        // causing SSLContext to initialize with no trust anchors and all outbound
                        // TLS connections to fail).
                        "chmod 644 /opt/java/openjdk/lib/security/cacerts" +
                        " && chown -R tcuser:tcuser /data/teamcity_server/datadir/plugins" +
                        " && exec runuser -u tcuser -- /run-services.sh");
                // In manual mode, pin the TC host port so the browser URL is stable across
                // container restarts. CI keeps the testcontainers auto-allocated port.
                if (MANUAL_MODE) {
                    cmd.getHostConfig().withPortBindings(new PortBinding(
                            Ports.Binding.bindPort(MANUAL_TC_HOST_PORT),
                            new ExposedPort(TC_PORT)));
                }
            })
            .waitingFor(Wait.forHttp("/mnt/").forStatusCode(200).withStartupTimeout(Duration.ofMinutes(5)));

    private static final GenericContainer<?> CADDY = new GenericContainer<>(CADDY_IMAGE)
            .withNetwork(NETWORK)
            .withNetworkAliases(CADDY_ALIAS, TC_ALT_ALIAS, OCTOPUS_CADDY_ALIAS)
            .withExposedPorts(443, 8443)
            .withCopyFileToContainer(
                    MountableFile.forClasspathResource("Caddyfile"),
                    "/etc/caddy/Caddyfile")
            .withCopyFileToContainer(
                    MountableFile.forHostPath(TLS.serverCertPem().toString()),
                    "/etc/caddy/tls/server.crt")
            .withCopyFileToContainer(
                    MountableFile.forHostPath(TLS.serverKeyPem().toString()),
                    "/etc/caddy/tls/server.key")
            .withCreateContainerCmdModifier(cmd -> cmd.withName(CONTAINER_PREFIX + "-caddy"))
            .waitingFor(Wait.forListeningPort().withStartupTimeout(Duration.ofMinutes(1)));

    private static final GenericContainer<?> AGENT = new GenericContainer<>(AGENT_IMAGE)
            .withNetwork(NETWORK)
            // Connect directly to TC over plain HTTP — the agent doesn't need to go through Caddy
            // and would fail TLS verification anyway (self-signed cert, no custom truststore). The
            // JWT iss claim comes from TC's configured root URL, not from how the agent connects.
            .withEnv("SERVER_URL", "http://" + TC_INTERNAL_ALIAS + ":" + TC_PORT)
            .withCreateContainerCmdModifier(cmd -> cmd.withName(CONTAINER_PREFIX + "-agent"))
            .dependsOn(TEAMCITY);

    private static boolean started;
    private static TeamCityClient teamCity;
    private static String tcBaseUrl;
    private static String octopusBaseUrl;
    private static HttpClient octopusHttp;
    private static HttpClient caddyTlsHttp;

    /** Starts the whole stack (idempotent) and brings TeamCity to a ready, authenticated state. */
    static synchronized void ensureStarted() {
        if (started) return;
        try {
            // Start in dependency order (manual .start() does not honour .dependsOn()).
            MSSQL.start();
            OCTOPUS.start();
            TEAMCITY.start();
            CADDY.start();
            AGENT.start();

            tcBaseUrl = "http://" + TEAMCITY.getHost() + ":" + TEAMCITY.getMappedPort(TC_PORT);
            octopusBaseUrl = "http://" + OCTOPUS.getHost() + ":" + OCTOPUS.getMappedPort(8080);

            octopusHttp = HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();
            caddyTlsHttp = HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .connectTimeout(Duration.ofSeconds(10))
                    .sslContext(TlsTrustManager.buildSslContext(TLS.caCert()))
                    .build();

            teamCity = TeamCityClient.bringUp(TEAMCITY, tcBaseUrl);
            started = true;
        } catch (final Exception e) {
            throw new IllegalStateException("Failed to start the shared integration-test stack", e);
        }
    }

    // -------------------------------------------------------------------------
    // Accessors (all imply ensureStarted())
    // -------------------------------------------------------------------------

    static TeamCityClient teamCity() {
        ensureStarted();
        return teamCity;
    }

    /** Host-reachable {@code http://host:port} for the TeamCity REST/UI port. */
    static String tcBaseUrl() {
        ensureStarted();
        return tcBaseUrl;
    }

    /** TeamCity container handle — for {@code execInContainer} log access and the manual-mode banner. */
    static GenericContainer<?> teamcity() {
        ensureStarted();
        return TEAMCITY;
    }

    /** {@code https://host:port} for the Caddy-fronted TLS endpoint (port 443). */
    static String caddyHttpsBase() {
        ensureStarted();
        return "https://" + CADDY.getHost() + ":" + CADDY.getMappedPort(443);
    }

    /** Host-mapped Caddy HTTPS port (used by the manual-mode banner). */
    static int caddyHttpsPort() {
        ensureStarted();
        return CADDY.getMappedPort(443);
    }

    /** TLS-trusting client (trusts the generated test CA) for Caddy HTTPS calls. */
    static HttpClient caddyTlsHttp() {
        ensureStarted();
        return caddyTlsHttp;
    }

    static String octopusBaseUrl() {
        ensureStarted();
        return octopusBaseUrl;
    }

    static HttpClient octopusHttp() {
        ensureStarted();
        return octopusHttp;
    }

    static String octopusApiKey() {
        return OCTOPUS_ADMIN_API_KEY;
    }

    static GenericContainer<?> octopus() {
        ensureStarted();
        return OCTOPUS;
    }

    static GenericContainer<?> caddy() {
        ensureStarted();
        return CADDY;
    }

    static GenericContainer<?> agent() {
        ensureStarted();
        return AGENT;
    }

    // -------------------------------------------------------------------------
    // Host setup helpers
    // -------------------------------------------------------------------------

    private static String generateApiKey() {
        final var rng = new java.security.SecureRandom();
        final var sb = new StringBuilder("API-FAKEKEY");
        for (var i = 0; i < 21; i++) sb.append(rng.nextInt(10));
        return sb.toString();
    }

    private static Path requirePluginZip() {
        final var targetDir = Path.of(
                System.getProperty("project.basedir", "."),
                "../target/").normalize();
        try (final var stream = java.nio.file.Files.list(targetDir)) {
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
}
