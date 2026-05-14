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
        // No CookieManager: TC only enforces CSRF on POSTs that already hold a session cookie,
        // so keeping the client stateless lets us POST to the REST API with basic auth alone.
        http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(10))
                .build();

        acceptLicenseAgreementIfRequired();
        waitForTcReady();

        superUserToken = extractSuperUserTokenWithRetry();
        superUserAuthHeader = "Basic " + Base64.getEncoder().encodeToString((":" + superUserToken).getBytes());

        configureServerRootUrl();
        createAdminUserToBypassFirstRunWizard();
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
    void allDimensionsUncheckedByDefaultInUi() {
        try (final var context = newLoggedInContext()) {
            final var page = context.newPage();
            navigateToFeatureEditor(page);

            final var checkboxes = page.locator(".jwt-subject-dimension-cb").all();
            assertThat(checkboxes).as("at least one optional-dimension checkbox should be rendered").isNotEmpty();
            for (final var cb : checkboxes) {
                assertThat(cb.isChecked())
                        .as("dimension '%s' should be unchecked when subject_dimensions is empty",
                                cb.getAttribute("value"))
                        .isFalse();
            }
        }
    }

    @Test
    void checkingDimensionPersistsAfterSave() throws Exception {
        // Uses trigger_type because the branch checkbox is only rendered when the build
        // type has a VCS root; this test's build type doesn't.
        try (final var context = newLoggedInContext()) {
            final var page = context.newPage();
            navigateToFeatureEditor(page);
            page.locator(".jwt-subject-dimension-cb[value='trigger_type']").check();
            saveBuildFeature(page);
        }

        assertThat((String) readFeatureProperties().get("subject_dimensions"))
                .as("saved subject_dimensions should list trigger_type")
                .isEqualTo("trigger_type");
    }

    @Test
    void uncheckingAllDimensionsSavesEmptyPropertyValue() throws Exception {
        // Phase 1: check both dimensions so subject_dimensions becomes non-empty
        try (final var ctx = newLoggedInContext()) {
            final var page = ctx.newPage();
            navigateToFeatureEditor(page);
            for (final var cb : page.locator(".jwt-subject-dimension-cb").all()) {
                cb.check();
            }
            saveBuildFeature(page);
        }

        // Phase 2: uncheck every checkbox, verify empty subject_dimensions is stored
        try (final var ctx = newLoggedInContext()) {
            final var page = ctx.newPage();
            navigateToFeatureEditor(page);
            for (final var cb : page.locator(".jwt-subject-dimension-cb").all()) {
                cb.uncheck();
            }
            saveBuildFeature(page);
        }

        assertThat((String) readFeatureProperties().get("subject_dimensions"))
                .as("all dimensions unchecked should store empty string (the default-minimal sub)")
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

    @Test
    void liveSubjectPreviewIsMinimalByDefault() {
        try (final var context = newLoggedInContext()) {
            final var page = context.newPage();
            navigateToFeatureEditor(page);
            // With no optional dimensions configured (the default), the preview should be just
            // project + build_type using the build type's actual internal IDs.
            assertThat(page.locator("#jwtSubjectPreview").inputValue())
                    .matches("project:[a-zA-Z0-9_]+:build_type:[a-zA-Z0-9_]+");
        }
    }

    @Test
    void liveSubjectPreviewReflectsCheckboxToggle() {
        try (final var context = newLoggedInContext()) {
            final var page = context.newPage();
            navigateToFeatureEditor(page);
            final var beforeToggle = page.locator("#jwtSubjectPreview").inputValue();
            assertThat(beforeToggle).doesNotContain(":trigger_type:");

            page.locator(".jwt-subject-dimension-cb[value='trigger_type']").check();
            assertThat(page.locator("#jwtSubjectPreview").inputValue())
                    .as("preview should append :trigger_type:<placeholder> when the checkbox is enabled")
                    .startsWith(beforeToggle)
                    .contains(":trigger_type:");

            page.locator(".jwt-subject-dimension-cb[value='trigger_type']").uncheck();
            assertThat(page.locator("#jwtSubjectPreview").inputValue())
                    .as("preview should revert to the minimal form when the checkbox is disabled")
                    .isEqualTo(beforeToggle);
        }
    }

    @Test
    void savedSubjectDimensionsArePreCheckedOnReopen() throws Exception {
        // Configure the feature with subject_dimensions=trigger_type via REST so the UI has
        // a non-default state to load. Opening the dialog should reflect that — trigger_type
        // checkbox checked, preview includes the segment — without further user interaction.
        setFeatureProperty("subject_dimensions", "trigger_type");

        try (final var context = newLoggedInContext()) {
            final var page = context.newPage();
            navigateToFeatureEditor(page);
            assertThat(page.locator(".jwt-subject-dimension-cb[value='trigger_type']").isChecked())
                    .as("trigger_type checkbox should be pre-checked from the saved value")
                    .isTrue();
            assertThat(page.locator("#jwtSubjectPreview").inputValue())
                    .as("preview should include the trigger_type segment from the saved state")
                    .contains(":trigger_type:");
        }
    }

    @Test
    void invalidTtlShowsValidationErrorAndDoesNotSave() throws Exception {
        try (final var context = newLoggedInContext()) {
            final var page = context.newPage();
            navigateToFeatureEditor(page);
            // 999999 is well above the 1440 hard cap; TC's properties processor rejects it.
            page.locator("#ttl_minutes").fill("999999");
            page.locator("#submitBuildFeatureId").click();
            // Wait for the server-side validation response — the error span starts empty
            // and TC populates it via the failed-save AJAX response.
            page.locator("#error_ttl_minutes").filter(new com.microsoft.playwright.Locator.FilterOptions()
                    .setHasText("Token lifetime")).waitFor();
            assertThat(page.locator("#submitBuildFeatureId").isVisible())
                    .as("modal should still be open after validation failure")
                    .isTrue();
        }

        // Confirm via REST that the persisted value is unchanged.
        assertThat(readFeatureProperties().get("ttl_minutes"))
                .as("invalid TTL should not have persisted")
                .isEqualTo("10");
    }

    @Test
    void unknownSubjectDimensionShowsValidationErrorAndDoesNotSave() throws Exception {
        try (final var context = newLoggedInContext()) {
            final var page = context.newPage();
            navigateToFeatureEditor(page);
            // The UI checkboxes never produce invalid values, but a direct edit (REST /
            // Kotlin DSL) could. Simulate that by writing a garbage value into the hidden
            // form field via JS and clicking Save. Dispatch input + change so any TC dirty-
            // state detection notices the field changed.
            page.evaluate("(() => {"
                    + " const el = document.getElementById('subject_dimensions');"
                    + " el.value = 'brnach';"
                    + " el.dispatchEvent(new Event('input', {bubbles: true}));"
                    + " el.dispatchEvent(new Event('change', {bubbles: true}));"
                    + "})()");
            page.locator("#submitBuildFeatureId").click();
            page.locator("#error_subject_dimensions").filter(new com.microsoft.playwright.Locator.FilterOptions()
                    .setHasText("brnach")).waitFor();
            assertThat(page.locator("#submitBuildFeatureId").isVisible())
                    .as("modal should still be open after validation failure")
                    .isTrue();
        }

        // Confirm via REST that the persisted value is unchanged (still empty / default).
        assertThat((String) readFeatureProperties().get("subject_dimensions"))
                .as("invalid dimension value should not have persisted")
                .isNullOrEmpty();
    }

    // -------------------------------------------------------------------------
    // Playwright helpers
    // -------------------------------------------------------------------------

    /**
     * Creates a browser context that authenticates every request via HTTP Basic auth using
     * the TC super-user token. Bypasses the login form (which would otherwise need to drive
     * the RSA-encrypted password flow) — TC accepts super-user Basic auth on admin URLs
     * directly. The first-run "Create Administrator Account" wizard is separately satisfied
     * by createAdminUserToBypassFirstRunWizard.
     */
    private BrowserContext newLoggedInContext() {
        return browser.newContext(new com.microsoft.playwright.Browser.NewContextOptions()
                .setExtraHTTPHeaders(java.util.Map.of("Authorization", superUserAuthHeader)));
    }

    private void navigateToFeatureEditor(final Page page) {
        // The TC build feature editor is a modal: navigate to the features list, then click
        // Edit, which triggers BS.BuildFeatureDialog.showEditDialog (a JS function that
        // AJAX-loads /admin/showFeatureParams.html into a modal). Waiting on the feature
        // title before clicking ensures the row is rendered; waiting on a known field
        // inside the dialog confirms the modal has rendered before tests interact with it.
        page.navigate(baseUrl + "/admin/editBuildFeatures.html?id=buildType:" + BUILD_TYPE_ID);
        page.waitForLoadState();
        try {
            page.locator("text=OIDC Identity Token").first().waitFor();
            page.locator("td.edit a").first().click();
            // #subject_dimensions is a hidden input — wait for it to be attached to the DOM
            // (Playwright's default waitFor requires visible, which a hidden input never becomes).
            page.locator("#subject_dimensions").waitFor(new com.microsoft.playwright.Locator.WaitForOptions()
                    .setState(com.microsoft.playwright.options.WaitForSelectorState.ATTACHED));
        } catch (final RuntimeException e) {
            try {
                page.screenshot(new com.microsoft.playwright.Page.ScreenshotOptions()
                        .setPath(java.nio.file.Paths.get("/tmp/uiit-failed-" + System.currentTimeMillis() + ".png"))
                        .setFullPage(true));
                java.nio.file.Files.writeString(
                        java.nio.file.Paths.get("/tmp/uiit-failed-" + System.currentTimeMillis() + ".html"),
                        page.content());
                System.err.println("UIIT navigation failed; page URL=" + page.url());
            } catch (final Exception ignored) {}
            throw e;
        }
    }

    private void saveBuildFeature(final Page page) {
        // The Save button lives in the modal's chrome (not the JSP fragment). After
        // clicking, wait for it to become hidden — TC reuses the modal DOM so we can't
        // wait for DETACHED, but visibility flips when the modal opens/closes.
        page.locator("#submitBuildFeatureId").click();
        page.locator("#submitBuildFeatureId").waitFor(new com.microsoft.playwright.Locator.WaitForOptions()
                .setState(com.microsoft.playwright.options.WaitForSelectorState.HIDDEN));
        page.waitForLoadState(com.microsoft.playwright.options.LoadState.NETWORKIDLE);
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

    /** Sets a single feature property via REST PUT (bypasses any UI flow). TC's REST API
     *  uses /parameters/ in the URL even though the JSON field is "properties". */
    private void setFeatureProperty(final String name, final String value) throws Exception {
        final var response = http.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/httpAuth/app/rest/buildTypes/" + BUILD_TYPE_ID
                                + "/features/" + featureId + "/parameters/" + name))
                        .header("Authorization", superUserAuthHeader)
                        .header("Content-Type", "text/plain")
                        .PUT(HttpRequest.BodyPublishers.ofString(value))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException("Setting feature property " + name + " failed: "
                    + response.statusCode() + ": " + response.body());
        }
    }

    private static String addBuildFeature() throws Exception {
        final var featureJson = """
                {"type":"oidc-plugin","properties":{"property":[
                    {"name":"ttl_minutes","value":"10"},
                    {"name":"algorithm","value":"RS256"},
                    {"name":"subject_dimensions","value":""},
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

    /**
     * Until a user with admin privileges exists, browser navigation to any admin URL is
     * intercepted by TC's first-run "Create Administrator Account" wizard. Creating one
     * via REST (super-user-authenticated) satisfies the wizard's gate so the browser
     * flow can proceed straight to the admin pages.
     */
    private static void createAdminUserToBypassFirstRunWizard() throws Exception {
        tcPost("/httpAuth/app/rest/users",
                "{\"username\":\"admin\",\"password\":\"admin\","
                        + "\"roles\":{\"role\":[{\"roleId\":\"SYSTEM_ADMIN\",\"scope\":\"g\"}]}}");
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
        // Set the root URL to a fake https://... so the plugin's HTTPS-required validation
        // passes (it only checks the URL string starts with "https://", not that the host
        // actually serves TLS). Playwright continues to hit baseUrl over plain HTTP.
        final var httpsRootUrl = baseUrl.replaceFirst("^http://", "https://");
        final var form = "rootUrl=" + URI.create(httpsRootUrl).toASCIIString().replace(":", "%3A").replace("/", "%2F")
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
