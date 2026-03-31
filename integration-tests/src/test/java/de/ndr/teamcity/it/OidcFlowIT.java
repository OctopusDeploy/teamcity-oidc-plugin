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

        // TODO: implement setup steps (see Tasks 5 and 6)
    }

    @Test
    void teamCityJwtIsAcceptedByOctopus() throws Exception {
        fail("not implemented yet");
    }
}
