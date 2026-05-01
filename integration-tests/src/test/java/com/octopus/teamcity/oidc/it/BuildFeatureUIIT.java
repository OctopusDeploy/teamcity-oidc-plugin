package com.octopus.teamcity.oidc.it;

import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
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
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Browser-driven UI integration tests for the JWT build feature editor.
 * <p>
 * Spins up a real TeamCity server with the plugin, creates a project and build type
 * via the REST API, then uses Playwright/Chromium to drive the build feature editor
 * and verify that form interactions persist correctly.
 * <p>
 * Run with: {@code mvn verify -pl integration-tests -Dit.test=BuildFeatureUIIT}
 * Build the plugin zip first: {@code mvn package -DskipTests}
 */
@Testcontainers
public class BuildFeatureUIIT {

    private static final int TC_PORT = 8111;
    private static final String TC_IMAGE = "jetbrains/teamcity-server:2025.11";
    private static final String PROJECT_ID = "UITest";
    private static final String BUILD_TYPE_ID = "UITest_Build";

    private static final Path PLUGIN_ZIP = requirePluginZip();

    @Container
    static final GenericContainer<?> teamcity = new GenericContainer<>(TC_IMAGE)
            .withExposedPorts(TC_PORT)
            .withEnv("TEAMCITY_SERVER_OPTS", "-Dteamcity.startup.maintenance=false")
            .withCopyFileToContainer(
                    MountableFile.forHostPath(PLUGIN_ZIP),
                    "/data/teamcity_server/datadir/plugins/" + PLUGIN_ZIP.getFileName()
            )
            .waitingFor(Wait.forHttp("/mnt/").forStatusCode(200).withStartupTimeout(Duration.ofMinutes(5)));

    static String baseUrl;
    static HttpClient http;
    static String superUserToken;
    static String superUserAuthHeader;

    /** ID of the JWT build feature; refreshed in @BeforeEach to ensure clean state. */
    static String featureId;

    static Playwright playwright;
    static Browser browser;

    @BeforeAll
    static void setUpSuite() throws Exception {
        baseUrl = "http://" + teamcity.getHost() + ":" + teamcity.getMappedPort(TC_PORT);
        http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(10))
                .cookieHandler(new CookieManager())
                .build();

        acceptLicenseAgreementIfRequired();
        waitForTcReady();

        superUserToken = extractSuperUserTokenWithRetry();
        superUserAuthHeader = "Basic " + Base64.getEncoder().encodeToString((":" + superUserToken).getBytes());

        configureServerRootUrl();
        createProjectAndBuildType();
        featureId = addBuildFeature();

        playwright = Playwright.create();
        browser = playwright.chromium().launch(new BrowserType.LaunchOptions().setHeadless(true));
    }

    @AfterAll
    static void tearDownSuite() {
        if (browser != null) browser.close();
        if (playwright != null) playwright.close();
    }

    /**
     * Delete and re-create the build feature before each test so every test starts
     * from a known clean state (default algorithm, TTL, empty claims, empty audience).
     */
    @BeforeEach
    void resetFeature() throws Exception {
        tcDelete("/httpAuth/app/rest/buildTypes/" + BUILD_TYPE_ID + "/features/" + featureId);
        featureId = addBuildFeature();
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    @Test
    void allClaimsEnabledByDefaultInUi() {
        try (final var context = newLoggedInContext()) {
            final var page = context.newPage();
            navigateToFeatureEditor(page);

            final var allClaims = new String[]{
                "branch", "build_type_external_id", "project_external_id",
                "triggered_by", "triggered_by_id", "build_number"
            };
            for (final var claim : allClaims) {
                assertThat(page.locator(".jwt-claim-cb[value='" + claim + "']").isChecked())
                        .as("checkbox for claim '%s' should be checked when claims property is empty", claim)
                        .isTrue();
            }
        }
    }

    @Test
    void uncheckingClaimPersistsAfterSave() throws Exception {
        try (final var context = newLoggedInContext()) {
            final var page = context.newPage();
            navigateToFeatureEditor(page);
            page.locator(".jwt-claim-cb[value='build_number']").uncheck();
            saveBuildFeature(page);
        }

        final var props = readFeatureProperties();
        final var claims = (String) props.get("claims");
        assertThat(claims)
                .as("saved claims should list all except build_number")
                .isNotNull()
                .contains("branch")
                .contains("build_type_external_id")
                .contains("project_external_id")
                .contains("triggered_by")
                .contains("triggered_by_id")
                .doesNotContain("build_number");
    }

    @Test
    void recheckingAllClaimsSavesEmptyPropertyValue() throws Exception {
        // Phase 1: uncheck one claim so claims becomes non-empty
        try (final var ctx = newLoggedInContext()) {
            final var page = ctx.newPage();
            navigateToFeatureEditor(page);
            page.locator(".jwt-claim-cb[value='build_number']").uncheck();
            saveBuildFeature(page);
        }

        // Phase 2: re-check every checkbox, verify empty claims (= "all enabled") is stored
        try (final var ctx = newLoggedInContext()) {
            final var page = ctx.newPage();
            navigateToFeatureEditor(page);
            for (final var cb : page.locator(".jwt-claim-cb").all()) {
                cb.check();
            }
            saveBuildFeature(page);
        }

        assertThat((String) readFeatureProperties().get("claims"))
                .as("all claims checked should store empty string (meaning all enabled)")
                .isNullOrEmpty();
    }

    @Test
    void algorithmSelectionPersistsAfterSave() throws Exception {
        try (final var context = newLoggedInContext()) {
            final var page = context.newPage();
            navigateToFeatureEditor(page);
            page.selectOption("#algorithm", "ES256");
            saveBuildFeature(page);
        }

        assertThat(readFeatureProperties().get("algorithm"))
                .as("algorithm should be ES256 after selecting and saving")
                .isEqualTo("ES256");
    }

    @Test
    void ttlMinutesPersistsAfterSave() throws Exception {
        try (final var context = newLoggedInContext()) {
            final var page = context.newPage();
            navigateToFeatureEditor(page);
            page.locator("#ttl_minutes").fill("15");
            saveBuildFeature(page);
        }

        assertThat(readFeatureProperties().get("ttl_minutes"))
                .as("ttl_minutes should be 15 after saving")
                .isEqualTo("15");
    }

    @Test
    void audiencePersistsAfterSave() throws Exception {
        try (final var context = newLoggedInContext()) {
            final var page = context.newPage();
            navigateToFeatureEditor(page);
            page.locator("#audience").fill("api://MyTestAudience");
            saveBuildFeature(page);
        }

        assertThat(readFeatureProperties().get("audience"))
                .as("audience should match saved value")
                .isEqualTo("api://MyTestAudience");
    }

    // -------------------------------------------------------------------------
    // Playwright helpers
    // -------------------------------------------------------------------------

    /**
     * Creates a new browser context authenticated as the TC superuser.
     * Opens a throwaway page to perform the login, then closes it;
     * the session cookie is retained by the context.
     */
    private BrowserContext newLoggedInContext() {
        final var context = browser.newContext();
        final var page = context.newPage();
        try {
            page.navigate(baseUrl + "/login.html?super=1");
            page.waitForLoadState();
            // TC login page: leave username empty, enter token as password
            page.locator("input[name='password'], input[type='password']").first().fill(superUserToken);
            page.locator("input[type='submit'], button[type='submit']").first().click();
            page.waitForLoadState();
        } finally {
            page.close();
        }
        return context;
    }

    private void navigateToFeatureEditor(final Page page) {
        page.navigate(baseUrl + "/admin/editBuildTypeFragment.html?init=1&id=" + BUILD_TYPE_ID
                + "&featureId=" + featureId);
        page.waitForLoadState();
    }

    private void saveBuildFeature(final Page page) {
        page.locator(".submitButton, input[value='Save']").first().click();
        page.waitForLoadState();
    }

    // -------------------------------------------------------------------------
    // REST API helpers
    // -------------------------------------------------------------------------

    /**
     * Reads the current build feature's properties and returns them as a name→value map.
     */
    private JSONObject readFeatureProperties() throws Exception {
        final var response = http.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/httpAuth/app/rest/buildTypes/" + BUILD_TYPE_ID
                                + "/features/" + featureId + "?fields=properties(property)"))
                        .header("Authorization", superUserAuthHeader)
                        .header("Accept", "application/json")
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString()
        );
        assertThat(response.statusCode()).as("feature properties GET").isEqualTo(200);
        final var propsContainer = (JSONObject) parseJson(response.body()).get("properties");
        final var propArray = (JSONArray) propsContainer.get("property");
        final var result = new JSONObject();
        for (final var item : propArray) {
            final var prop = (JSONObject) item;
            result.put((String) prop.get("name"), prop.get("value"));
        }
        return result;
    }

    private static String addBuildFeature() throws Exception {
        final var featureJson = """
                {"type":"oidc-plugin","properties":{"property":[
                    {"name":"ttl_minutes","value":"10"},
                    {"name":"algorithm","value":"RS256"},
                    {"name":"claims","value":""},
                    {"name":"audience","value":""}
                ]}}
                """;
        final var response = http.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/httpAuth/app/rest/buildTypes/" + BUILD_TYPE_ID + "/features"))
                        .header("Authorization", superUserAuthHeader)
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(featureJson))
                        .build(),
                HttpResponse.BodyHandlers.ofString()
        );
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException("Failed to add build feature: " + response.statusCode() + ": " + response.body());
        }
        return (String) parseJson(response.body()).get("id");
    }

    private static void createProjectAndBuildType() throws Exception {
        tcPost("/httpAuth/app/rest/projects",
                "{\"id\":\"" + PROJECT_ID + "\",\"name\":\"UI Test\",\"parentProject\":{\"id\":\"_Root\"}}");
        tcPost("/httpAuth/app/rest/buildTypes",
                "{\"id\":\"" + BUILD_TYPE_ID + "\",\"name\":\"UI Test Build\",\"project\":{\"id\":\"" + PROJECT_ID + "\"}}");
    }

    private static void tcPost(final String path, final String json) throws Exception {
        final var response = http.send(
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
            throw new IllegalStateException("TC POST " + path + " returned " + response.statusCode() + ": " + response.body());
        }
    }

    private static void tcDelete(final String path) throws Exception {
        http.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + path))
                        .header("Authorization", superUserAuthHeader)
                        .DELETE().build(),
                HttpResponse.BodyHandlers.ofString()
        );
    }

    private static JSONObject parseJson(final String body) {
        try {
            return (JSONObject) new JSONParser(JSONParser.DEFAULT_PERMISSIVE_MODE).parse(body);
        } catch (final net.minidev.json.parser.ParseException e) {
            throw new IllegalStateException("Failed to parse JSON: " + body, e);
        }
    }

    // -------------------------------------------------------------------------
    // TC container setup helpers (same pattern as JwtPluginIT)
    // -------------------------------------------------------------------------

    private static Path requirePluginZip() {
        final var targetDir = Path.of(
                System.getProperty("project.basedir", "."), "../target/").normalize();
        try (var stream = java.nio.file.Files.list(targetDir)) {
            return stream
                    .filter(p -> p.getFileName().toString().matches("Octopus\\.TeamCity\\.OIDC\\..*\\.zip"))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException(
                            "Plugin zip not found in " + targetDir.toAbsolutePath()
                            + ". Run 'mvn package -DskipTests' first."));
        } catch (java.io.IOException e) {
            throw new IllegalStateException("Could not list " + targetDir.toAbsolutePath(), e);
        }
    }

    private static void acceptLicenseAgreementIfRequired() throws Exception {
        final var deadline = System.currentTimeMillis() + Duration.ofMinutes(2).toMillis();
        while (System.currentTimeMillis() < deadline) {
            if (teamcity.execInContainer("grep", "-q",
                    "Review and accept TeamCity license agreement",
                    "/opt/teamcity/logs/teamcity-server.log").getExitCode() == 0) {
                break;
            }
            TimeUnit.SECONDS.sleep(3);
        }
        teamcity.execInContainer("sh", "-c",
                "curl -sc /tmp/tc-cookies.txt http://localhost:8111/mnt/ > /dev/null && " +
                "curl -sb /tmp/tc-cookies.txt -X POST http://localhost:8111/mnt/do/acceptLicenseAgreement");
    }

    private static void waitForTcReady() throws Exception {
        final var deadline = System.currentTimeMillis() + Duration.ofMinutes(5).toMillis();
        while (System.currentTimeMillis() < deadline) {
            final var r = http.send(
                    HttpRequest.newBuilder().uri(URI.create(baseUrl + "/")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() == 401 || r.statusCode() == 200) return;
            TimeUnit.SECONDS.sleep(3);
        }
        throw new IllegalStateException("TeamCity did not become ready in time");
    }

    private static void configureServerRootUrl() throws Exception {
        final var page = http.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/httpAuth/admin/admin.html?item=serverConfigGeneral"))
                        .header("Authorization", superUserAuthHeader)
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());
        final var m = Pattern.compile("tc-csrf-token\" content=\"([^\"]+)\"").matcher(page.body());
        if (!m.find()) throw new IllegalStateException("CSRF token not found on global settings page");
        final var csrf = m.group(1);
        final var form = "rootUrl=" + URI.create(baseUrl).toASCIIString().replace(":", "%3A").replace("/", "%2F")
                       + "&submitSettings=store&tc-csrf-token=" + csrf;
        http.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/httpAuth/admin/serverConfigGeneral.html"))
                        .header("Authorization", superUserAuthHeader)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(form))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static String extractSuperUserTokenWithRetry() throws Exception {
        final var deadline = System.currentTimeMillis() + Duration.ofSeconds(60).toMillis();
        while (System.currentTimeMillis() < deadline) {
            final var result = teamcity.execInContainer(
                    "grep", "-o", "Super user authentication token: [0-9]*",
                    "/opt/teamcity/logs/teamcity-server.log");
            final var matcher = Pattern.compile("Super user authentication token: (\\d+)").matcher(result.getStdout().trim());
            if (matcher.find()) return matcher.group(1);
            TimeUnit.SECONDS.sleep(5);
        }
        throw new IllegalStateException("TC super user token not found in log after 60s");
    }
}
