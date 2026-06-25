package com.octopus.teamcity.oidc.it;

import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Locator;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import com.microsoft.playwright.assertions.PlaywrightAssertions;
import com.microsoft.playwright.options.LoadState;
import com.microsoft.playwright.options.SelectOption;
import com.microsoft.playwright.options.WaitForSelectorState;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;

import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Browser-driven UI integration tests for the JWT build feature editor.
 * <p>
 * Uses the shared {@link SharedStack} TeamCity server, sets the global server root URL it needs
 * (a fake {@code https://} form of the mapped URL, so the plugin's HTTPS-required validation
 * passes — Playwright still drives the UI over plain HTTP), creates a project and build type via
 * the REST API, then uses Playwright/Chromium to drive the build feature editor.
 * <p>
 * Run with: {@code mvn verify -pl integration-tests -Dit.test=BuildFeatureUIIT}
 * Build the plugin zip first: {@code mvn package -DskipTests}
 */
public class BuildFeatureUIIT {

    private static final String PROJECT_ID = "UITest";
    private static final String BUILD_TYPE_ID = "UITest_Build";

    static String baseUrl;
    static TeamCityClient tc;
    static String superUserAuthHeader;

    /** ID of the JWT build feature; refreshed in @BeforeEach to ensure clean state. */
    static String featureId;

    static Playwright playwright;
    static Browser browser;

    /** Name of the currently-running test, used to name failure-capture artifacts. */
    private String currentTestName = "unknown";

    @BeforeAll
    static void setUpSuite() throws Exception {
        SharedStack.ensureStarted();
        tc = SharedStack.teamCity();
        baseUrl = SharedStack.tcBaseUrl();
        superUserAuthHeader = tc.authHeader();

        // Set the global root URL to a fake https:// form of the mapped URL so the plugin's
        // HTTPS-required validation passes (it only checks the scheme; Playwright still drives the
        // UI over plain HTTP). createAdminUser satisfies TC's first-run "Create Administrator" gate.
        tc.setRootUrl(baseUrl.replaceFirst("^http://", "https://"));
        tc.createAdminUser("admin", "admin");
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
    void captureTestName(final TestInfo info) {
        currentTestName = info.getTestMethod().map(java.lang.reflect.Method::getName).orElse("unknown");
    }

    @BeforeEach
    void resetFeature() throws Exception {
        tc.delete("/httpAuth/app/rest/buildTypes/" + BUILD_TYPE_ID + "/features/" + featureId);
        featureId = addBuildFeature();
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    @Test
    void allDimensionsUncheckedByDefaultInUi() {
        inFeatureEditor(page -> {
            final var checkboxes = page.locator(".jwt-subject-dimension-cb").all();
            assertThat(checkboxes).as("at least one optional-dimension checkbox should be rendered").isNotEmpty();
            for (final var cb : checkboxes) {
                // Assert via a value-specific locator so the auto-retrying assertion's failure
                // message names the dimension — LocatorAssertions has no AssertJ-style .as().
                // (Web-first assertion: the checkbox may not have painted at first check.)
                final var value = cb.getAttribute("value");
                PlaywrightAssertions.assertThat(page.locator(".jwt-subject-dimension-cb[value='" + value + "']"))
                        .not().isChecked();
            }
        });
    }

    @Test
    void checkingDimensionPersistsAfterSave() throws Exception {
        editFeature(page ->
                page.locator(".jwt-subject-dimension-cb[value='trigger_type']").check());

        assertThat((String) tc.featureProperties(BUILD_TYPE_ID, featureId).get("subject_dimensions"))
                .as("saved subject_dimensions should list trigger_type")
                .isEqualTo("trigger_type");
    }

    @Test
    void uncheckingAllDimensionsSavesEmptyPropertyValue() throws Exception {
        // Phase 1: check all dimensions so subject_dimensions becomes non-empty
        editFeature(page -> forEachDimensionCheckbox(page, Locator::check));
        // Phase 2: uncheck every checkbox, verify empty subject_dimensions is stored
        editFeature(page -> forEachDimensionCheckbox(page, Locator::uncheck));

        assertThat((String) tc.featureProperties(BUILD_TYPE_ID, featureId).get("subject_dimensions"))
                .as("all dimensions unchecked should store empty string (the default-minimal sub)")
                .isNullOrEmpty();
    }

    @Test
    void algorithmSelectionPersistsAfterSave() throws Exception {
        editFeature(page -> page.selectOption("#algorithm", "ES256"));

        assertThat(tc.featureProperties(BUILD_TYPE_ID, featureId).get("algorithm"))
                .as("algorithm should be ES256 after selecting and saving")
                .isEqualTo("ES256");
    }

    @Test
    void ttlMinutesPersistsAfterSave() throws Exception {
        editFeature(page -> page.locator("#ttl_minutes").fill("15"));

        assertThat(tc.featureProperties(BUILD_TYPE_ID, featureId).get("ttl_minutes"))
                .as("ttl_minutes should be 15 after saving")
                .isEqualTo("15");
    }

    @Test
    void audiencePersistsAfterSave() throws Exception {
        editFeature(page -> page.locator("#audience").fill("api://MyTestAudience"));

        assertThat(tc.featureProperties(BUILD_TYPE_ID, featureId).get("audience"))
                .as("audience should match saved value")
                .isEqualTo("api://MyTestAudience");
    }

    @Test
    void liveSubjectPreviewIsMinimalByDefault() {
        inFeatureEditor(page ->
                // With no optional dimensions configured (the default), the preview should be just
                // project + build_type using the build type's actual internal IDs.
                assertThat(page.locator("#jwtSubjectPreview").inputValue())
                        .matches("project:[a-zA-Z0-9_]+:build_type:[a-zA-Z0-9_]+"));
    }

    @Test
    void liveSubjectPreviewReflectsCheckboxToggle() {
        inFeatureEditor(page -> {
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
        });
    }

    @Test
    void savedSubjectDimensionsArePreCheckedOnReopen() throws Exception {
        // Configure the feature with subject_dimensions=trigger_type via REST so the UI has
        // a non-default state to load. Opening the dialog should reflect that — trigger_type
        // checkbox checked, preview includes the segment — without further user interaction.
        tc.setFeatureProperty(BUILD_TYPE_ID, featureId, "subject_dimensions", "trigger_type");

        inFeatureEditor(page -> {
            PlaywrightAssertions.assertThat(page.locator(".jwt-subject-dimension-cb[value='trigger_type']"))
                    .isChecked();
            assertThat(page.locator("#jwtSubjectPreview").inputValue())
                    .as("preview should include the trigger_type segment from the saved state")
                    .contains(":trigger_type:");
        });
    }

    @Test
    void invalidTtlShowsValidationErrorAndDoesNotSave() throws Exception {
        inFeatureEditor(page -> {
            // 999999 is well above the 1440 hard cap; TC's properties processor rejects it.
            page.locator("#ttl_minutes").fill("999999");
            page.locator("#submitBuildFeatureId").click();
            // Wait for the server-side validation response — the error span starts empty
            // and TC populates it via the failed-save AJAX response.
            page.locator("#error_ttl_minutes").filter(new Locator.FilterOptions()
                    .setHasText("Token lifetime")).waitFor();
            assertThat(page.locator("#submitBuildFeatureId").isVisible())
                    .as("modal should still be open after validation failure")
                    .isTrue();
        });

        // Confirm via REST that the persisted value is unchanged.
        assertThat(tc.featureProperties(BUILD_TYPE_ID, featureId).get("ttl_minutes"))
                .as("invalid TTL should not have persisted")
                .isEqualTo("10");
    }

    @Test
    void connectionSelectionLocksInlineFieldsToConnectionValues() throws Exception {
        // Create a connection at _Root so it is visible to the UITest project.
        final var connectionId = tc.createOidcConnection("_Root", "UI Test Conn",
                "api://ui-test-audience", 30, "ES256", "");

        inFeatureEditor(page -> {
            // The readonly Issuer (iss) row is always visible at the top with a real URL.
            PlaywrightAssertions.assertThat(page.locator("#jwtIssuerUrl")).isVisible();
            assertThat(page.locator("#jwtIssuerUrl").inputValue()).startsWith("https://");
            assertThat(page.locator("#jwtIssuerUrl").getAttribute("readonly")).isNotNull();

            // Connection dropdown must exist and list the new connection.
            PlaywrightAssertions.assertThat(page.locator("#connection_id")).isVisible();
            assertThat(page.locator("#connection_id option").allInnerTexts()
                    .stream().map(String::trim).toList()).contains("UI Test Conn");

            // Initial state: no connection selected — inline fields editable, no jwt-locked class.
            PlaywrightAssertions.assertThat(page.locator("#audience")).isVisible();
            PlaywrightAssertions.assertThat(page.locator("#audience")).isEditable();
            assertThat(page.locator("#audience").evaluate("el => el.classList.contains('jwt-locked')"))
                    .isEqualTo(false);

            page.selectOption("#connection_id",
                    new SelectOption().setValue(connectionId));

            // Inline fields remain visible but switch to readonly mode populated with the
            // connection's values and styled with the jwt-locked gray treatment.
            PlaywrightAssertions.assertThat(page.locator("#audience")).isVisible();
            assertThat(page.locator("#audience").inputValue()).isEqualTo("api://ui-test-audience");
            assertThat(page.locator("#audience").getAttribute("readonly")).isNotNull();
            assertThat(page.locator("#audience").evaluate("el => el.classList.contains('jwt-locked')"))
                    .isEqualTo(true);
            assertThat(page.locator("#ttl_minutes").inputValue()).isEqualTo("30");
            assertThat(page.locator("#algorithm").inputValue()).isEqualTo("ES256");
            PlaywrightAssertions.assertThat(page.locator("#algorithm")).isDisabled();

            // Switch back to "(none)".
            page.selectOption("#connection_id",
                    new SelectOption().setValue(""));

            // Inline fields are editable again and the jwt-locked class is removed.
            PlaywrightAssertions.assertThat(page.locator("#audience")).isEditable();
            assertThat(page.locator("#audience").getAttribute("readonly")).isNull();
            assertThat(page.locator("#audience").evaluate("el => el.classList.contains('jwt-locked')"))
                    .isEqualTo(false);
            PlaywrightAssertions.assertThat(page.locator("#algorithm")).isEnabled();
        });
    }

    @Test
    void connectionSelectionPersistsAfterSave() throws Exception {
        final var connectionId = tc.createOidcConnection("_Root", "UI Test Conn Persist",
                "api://ui-test-persist", 20, "RS256", "");

        editFeature(page -> page.selectOption("#connection_id",
                new SelectOption().setValue(connectionId)));

        assertThat(tc.featureProperties(BUILD_TYPE_ID, featureId).get("connection_id"))
                .as("connection_id should persist to the saved build feature properties")
                .isEqualTo(connectionId);

        // Reopen the editor and verify the dropdown still reflects the saved selection,
        // and that the inline fields are in connection-locked mode populated from the
        // connection's values.
        inFeatureEditor(page -> {
            assertThat(page.locator("#connection_id").inputValue()).isEqualTo(connectionId);
            assertThat(page.locator("#audience").inputValue()).isEqualTo("api://ui-test-persist");
            assertThat(page.locator("#audience").getAttribute("readonly")).isNotNull();
            assertThat(page.locator("#ttl_minutes").inputValue()).isEqualTo("20");
            assertThat(page.locator("#algorithm").inputValue()).isEqualTo("RS256");
            PlaywrightAssertions.assertThat(page.locator("#algorithm")).isDisabled();
        });
    }

    @Test
    void connectionWithSubjectScopingChecksAndDisablesCheckboxes() throws Exception {
        // Use trigger_type — the branch checkbox is only rendered when the build type
        // has a VCS root attached, while trigger_type is always present.
        final var connectionId = tc.createOidcConnection("_Root", "UI Test Conn Subjects",
                "api://ui-test-subj", 20, "RS256", "trigger_type");

        inFeatureEditor(page -> {
            final var triggerType = page.locator(".jwt-subject-dimension-cb[value='trigger_type']");

            // Pre-selection: unchecked and editable.
            PlaywrightAssertions.assertThat(triggerType).not().isChecked();
            PlaywrightAssertions.assertThat(triggerType).isEnabled();

            page.selectOption("#connection_id",
                    new SelectOption().setValue(connectionId));

            // Connection-selected: matching dimensions are checked AND disabled.
            PlaywrightAssertions.assertThat(triggerType).isChecked();
            PlaywrightAssertions.assertThat(triggerType).isDisabled();
            // Live preview reflects the connection's dimensions.
            assertThat(page.locator("#jwtSubjectPreview").inputValue()).contains(":trigger_type:");

            // Switch back: checkbox returns to unchecked + enabled.
            page.selectOption("#connection_id",
                    new SelectOption().setValue(""));
            PlaywrightAssertions.assertThat(triggerType).not().isChecked();
            PlaywrightAssertions.assertThat(triggerType).isEnabled();
        });
    }

    @Test
    void unknownSubjectDimensionShowsValidationErrorAndDoesNotSave() throws Exception {
        inFeatureEditor(page -> {
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
            page.locator("#error_subject_dimensions").filter(new Locator.FilterOptions()
                    .setHasText("brnach")).waitFor();
            assertThat(page.locator("#submitBuildFeatureId").isVisible())
                    .as("modal should still be open after validation failure")
                    .isTrue();
        });

        // Confirm via REST that the persisted value is unchanged (still empty / default).
        assertThat((String) tc.featureProperties(BUILD_TYPE_ID, featureId).get("subject_dimensions"))
                .as("invalid dimension value should not have persisted")
                .isNullOrEmpty();
    }

    // -------------------------------------------------------------------------
    // Playwright helpers
    // -------------------------------------------------------------------------

    /**
     * Opens a fresh logged-in browser context, navigates to the feature editor, and runs
     * {@code action}. Does not click Save — use for read-only inspection or for tests that
     * explicitly handle their own save / validation-error flow.
     */
    private void inFeatureEditor(final Consumer<Page> action) {
        try (final var context = newLoggedInContext()) {
            final var page = context.newPage();
            try {
                navigateToFeatureEditor(page);
                action.accept(page);
            } catch (final RuntimeException | AssertionError e) {
                // Capture a screenshot + page HTML before the context closes, so UI failures
                // (e.g. a save rejected by validation, leaving the modal open) are diagnosable.
                captureFailureArtifacts(page);
                throw e;
            }
        }
    }

    /**
     * Opens a fresh feature editor, runs {@code action}, then clicks Save and waits for the
     * modal to close. Built on top of {@link #inFeatureEditor} — use for the common
     * "edit one field and save" pattern.
     */
    private void editFeature(final Consumer<Page> action) {
        inFeatureEditor(page -> {
            action.accept(page);
            saveBuildFeature(page);
        });
    }

    /** Applies {@code action} to every {@code .jwt-subject-dimension-cb} on the page. */
    private void forEachDimensionCheckbox(final Page page, final Consumer<Locator> action) {
        for (final var cb : page.locator(".jwt-subject-dimension-cb").all()) {
            action.accept(cb);
        }
    }

    /**
     * Creates a browser context that authenticates every request via HTTP Basic auth using
     * the TC super-user token. Bypasses the login form (which would otherwise need to drive
     * the RSA-encrypted password flow) — TC accepts super-user Basic auth on admin URLs
     * directly. The first-run "Create Administrator Account" wizard is separately satisfied
     * by createAdminUserToBypassFirstRunWizard.
     */
    private BrowserContext newLoggedInContext() {
        return browser.newContext(new Browser.NewContextOptions()
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
        page.locator("text=OIDC Identity Token").first().waitFor();
        page.locator("td.edit a").first().click();
        // #subject_dimensions is a hidden input — wait for it to be attached to the DOM
        // (Playwright's default waitFor requires visible, which a hidden input never becomes).
        page.locator("#subject_dimensions").waitFor(new Locator.WaitForOptions()
                .setState(WaitForSelectorState.ATTACHED));
    }

    /**
     * On a UI test failure, save a full-page screenshot and the page HTML under
     * {@code target/playwright-failures/} and emit a TeamCity {@code publishArtifacts} service
     * message so they appear on the build's Artifacts tab (TeamCity renders PNGs inline).
     * Best-effort: never let capture problems mask the original test failure.
     */
    private void captureFailureArtifacts(final Page page) {
        try {
            final var dir = java.nio.file.Paths.get("target/playwright-failures");
            java.nio.file.Files.createDirectories(dir);
            final var base = currentTestName + "-" + System.currentTimeMillis();
            final var png = dir.resolve(base + ".png");
            final var html = dir.resolve(base + ".html");
            page.screenshot(new Page.ScreenshotOptions().setPath(png).setFullPage(true));
            java.nio.file.Files.writeString(html, page.content());
            System.out.println("##teamcity[publishArtifacts '"
                    + png.toAbsolutePath() + " => playwright-failures']");
            System.out.println("##teamcity[publishArtifacts '"
                    + html.toAbsolutePath() + " => playwright-failures']");
            System.err.println("UIIT failure artifacts saved: " + png.toAbsolutePath()
                    + " and " + html.toAbsolutePath() + " (page URL=" + page.url() + ")");
        } catch (final Exception ignored) {
            // Capture is diagnostic only — swallow so the real assertion failure surfaces.
        }
    }

    private void saveBuildFeature(final Page page) {
        // The Save button lives in the modal's chrome (not the JSP fragment). After
        // clicking, wait for it to become hidden — TC reuses the modal DOM so we can't
        // wait for DETACHED, but visibility flips when the modal opens/closes.
        page.locator("#submitBuildFeatureId").click();
        page.locator("#submitBuildFeatureId").waitFor(new Locator.WaitForOptions()
                .setState(WaitForSelectorState.HIDDEN));
        page.waitForLoadState(LoadState.NETWORKIDLE);
    }

    // -------------------------------------------------------------------------
    // REST API helpers
    // -------------------------------------------------------------------------

    private static String addBuildFeature() throws Exception {
        final var featureJson = """
                {"type":"oidc-plugin","properties":{"property":[
                    {"name":"ttl_minutes","value":"10"},
                    {"name":"algorithm","value":"RS256"},
                    {"name":"subject_dimensions","value":""},
                    {"name":"audience","value":""}
                ]}}
                """;
        final var body = tc.post("/httpAuth/app/rest/buildTypes/" + BUILD_TYPE_ID + "/features", featureJson);
        return (String) Json.parse(body).get("id");
    }

    private static void createProjectAndBuildType() throws Exception {
        tc.createProject(PROJECT_ID, "UI Test", "_Root");
        tc.createBuildType(BUILD_TYPE_ID, "UI Test Build", PROJECT_ID);
    }
}
