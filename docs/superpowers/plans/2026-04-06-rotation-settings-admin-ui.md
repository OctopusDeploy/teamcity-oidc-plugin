# Rotation Settings Admin UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a rotation settings section to the "JWT build feature" admin tab so operators can enable/disable automatic rotation, configure the cron schedule, view status, and trigger an immediate rotation via AJAX.

**Architecture:** A new `RotationSettingsController` handles save; `JwtBuildFeatureAdminPage` is extended to inject `RotationSettingsManager` and populate rotation model attributes; `jwtBuildFeatureSettings.jsp` gains a rotation section above the JWKS block with two AJAX buttons.

**Tech Stack:** Java 21, Spring 5.3 `CronExpression`, `net.minidev.json`, TeamCity `BaseController` / `AdminPage`, JSP with vanilla `fetch()`.

---

## File Structure

- **Create** `oidc-plugin-server/src/main/java/com/octopus/teamcity/oidc/RotationSettingsController.java` — POST endpoint to save rotation settings
- **Create** `oidc-plugin-server/src/test/java/com/octopus/teamcity/oidc/RotationSettingsControllerTest.java`
- **Modify** `oidc-plugin-server/src/main/java/com/octopus/teamcity/oidc/JwtBuildFeatureAdminPage.java` — inject `RotationSettingsManager`, populate four model attributes
- **Modify** `oidc-plugin-server/src/main/resources/buildServerResources/jwtBuildFeatureSettings.jsp` — rotation section above JWKS
- **Modify** `oidc-plugin-server/src/main/resources/META-INF/build-server-plugin-jwt-plugin.xml` — register `rotationSettingsController` bean

---

## Context for the codebase

- `KeyRotationController` at `oidc-plugin-server/src/main/java/com/octopus/teamcity/oidc/KeyRotationController.java` is the exact pattern to follow: public constructor takes `(WebControllerManager, <domain>, ExtensionHolder)`, package-private constructor takes `(WebControllerManager, <domain>, CSRFFilter)` for testing. Guards: POST check → CSRF → permission → logic.
- `RotationSettingsManager` at `…/RotationSettingsManager.java` — `load()` returns `RotationSettings`, `save(RotationSettings)` persists.
- `RotationSettings` record: `boolean enabled`, `String cronSchedule`, `@Nullable Instant lastRotatedAt`.
- `JwtBuildFeatureAdminPage` at `…/JwtBuildFeatureAdminPage.java` — extends `AdminPage`, constructor takes `(PagePlaces, PluginDescriptor, JwtKeyManager)`. Add `RotationSettingsManager` as a fourth parameter; Spring's `default-autowire="constructor"` will inject it automatically since `rotationSettingsManager` is already a bean.
- Spring XML at `…/META-INF/build-server-plugin-jwt-plugin.xml`. The `rotationSettingsManager` factory-bean is already declared. Just add a `rotationSettingsController` bean.
- Run tests: `JAVA_HOME=/Users/matt/Library/Java/JavaVirtualMachines/corretto-21.0.1/Contents/Home mvn test -pl oidc-plugin-server -q`
- TC CSRF token in JavaScript: `BS.CSRF.token` — pass as `X-TC-CSRF-Token` header in `fetch()`.
- `KeyRotationController` returns `{"status":"rotated"}` on success. `RotationSettingsController` returns `{"ok":true,"message":"Settings saved"}`.

---

## Task 1: `RotationSettingsController`

**Files:**
- Create: `oidc-plugin-server/src/main/java/com/octopus/teamcity/oidc/RotationSettingsController.java`
- Create: `oidc-plugin-server/src/test/java/com/octopus/teamcity/oidc/RotationSettingsControllerTest.java`
- Modify: `oidc-plugin-server/src/main/resources/META-INF/build-server-plugin-jwt-plugin.xml`

- [ ] **Step 1: Write the failing tests**

```java
package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.auth.Permission;
import jetbrains.buildServer.users.SUser;
import jetbrains.buildServer.web.CSRFFilter;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import jetbrains.buildServer.web.util.SessionUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class RotationSettingsControllerTest {

    @Mock private WebControllerManager controllerManager;
    @Mock private CSRFFilter csrfFilter;
    @TempDir private File tempDir;

    @BeforeEach
    void setUp() {
        lenient().when(csrfFilter.validateRequest(any(), any())).thenReturn(true);
    }

    private RotationSettingsController controller(RotationSettingsManager mgr) {
        return new RotationSettingsController(controllerManager, mgr, csrfFilter);
    }

    private SUser adminUser() {
        SUser user = mock(SUser.class);
        when(user.isPermissionGrantedGlobally(Permission.MANAGE_SERVER_INSTALLATION)).thenReturn(true);
        return user;
    }

    @Test
    void registersAtExpectedPath() {
        new RotationSettingsController(controllerManager, new RotationSettingsManager(tempDir), csrfFilter);
        verify(controllerManager).registerController(eq(RotationSettingsController.PATH), any());
    }

    @Test
    void savesValidSettings() throws Exception {
        RotationSettingsManager mgr = new RotationSettingsManager(tempDir);
        RotationSettingsController controller = controller(mgr);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("enabled")).thenReturn("true");
        when(request.getParameter("cronSchedule")).thenReturn("0 0 2 * * *");
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        try (MockedStatic<SessionUser> su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(request)).thenReturn(adminUser());
            controller.doHandle(request, response);
        }

        RotationSettings saved = mgr.load();
        assertThat(saved.enabled()).isTrue();
        assertThat(saved.cronSchedule()).isEqualTo("0 0 2 * * *");
        assertThat(writer.toString()).contains("\"ok\":true");
    }

    @Test
    void preservesLastRotatedAtWhenSaving() throws Exception {
        RotationSettingsManager mgr = new RotationSettingsManager(tempDir);
        Instant original = Instant.parse("2026-01-01T03:00:00Z");
        mgr.save(new RotationSettings(true, RotationSettings.DEFAULT_SCHEDULE, original));
        RotationSettingsController controller = controller(mgr);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("enabled")).thenReturn("false");
        when(request.getParameter("cronSchedule")).thenReturn("0 0 4 * * *");
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(response.getWriter()).thenReturn(new PrintWriter(new StringWriter()));

        try (MockedStatic<SessionUser> su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(request)).thenReturn(adminUser());
            controller.doHandle(request, response);
        }

        assertThat(mgr.load().lastRotatedAt()).isEqualTo(original);
    }

    @Test
    void rejectsInvalidCronSchedule() throws Exception {
        RotationSettingsManager mgr = new RotationSettingsManager(tempDir);
        RotationSettingsController controller = controller(mgr);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("enabled")).thenReturn("true");
        when(request.getParameter("cronSchedule")).thenReturn("not a cron");
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        try (MockedStatic<SessionUser> su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(request)).thenReturn(adminUser());
            controller.doHandle(request, response);
        }

        assertThat(writer.toString()).contains("\"ok\":false");
        assertThat(mgr.load().cronSchedule()).isEqualTo(RotationSettings.DEFAULT_SCHEDULE);
    }

    @Test
    void getRequestReturns405() throws Exception {
        RotationSettingsController controller = controller(new RotationSettingsManager(tempDir));
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("GET");
        HttpServletResponse response = mock(HttpServletResponse.class);
        controller.doHandle(request, response);
        verify(response).setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        verify(csrfFilter, never()).validateRequest(any(), any());
    }

    @Test
    void csrfFailureReturnsEarlyWithoutSaving() throws Exception {
        RotationSettingsManager mgr = new RotationSettingsManager(tempDir);
        when(csrfFilter.validateRequest(any(), any())).thenReturn(false);
        RotationSettingsController controller = controller(mgr);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("POST");
        HttpServletResponse response = mock(HttpServletResponse.class);
        controller.doHandle(request, response);

        verify(response, never()).setContentType(anyString());
        assertThat(mgr.load().cronSchedule()).isEqualTo(RotationSettings.DEFAULT_SCHEDULE);
    }

    @Test
    void nonAdminReturns403() throws Exception {
        RotationSettingsController controller = controller(new RotationSettingsManager(tempDir));

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("POST");
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));

        SUser nonAdmin = mock(SUser.class);
        when(nonAdmin.isPermissionGrantedGlobally(Permission.MANAGE_SERVER_INSTALLATION)).thenReturn(false);

        try (MockedStatic<SessionUser> su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(request)).thenReturn(nonAdmin);
            controller.doHandle(request, response);
        }

        verify(response).setStatus(HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    void nullSessionUserReturns403() throws Exception {
        RotationSettingsController controller = controller(new RotationSettingsManager(tempDir));

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("POST");
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(response.getWriter()).thenReturn(new PrintWriter(new StringWriter()));

        try (MockedStatic<SessionUser> su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(request)).thenReturn(null);
            controller.doHandle(request, response);
        }

        verify(response).setStatus(HttpServletResponse.SC_FORBIDDEN);
    }
}
```

- [ ] **Step 2: Run tests — expect FAIL (compilation error)**

```bash
JAVA_HOME=/Users/matt/Library/Java/JavaVirtualMachines/corretto-21.0.1/Contents/Home \
  mvn test -pl oidc-plugin-server -Dtest=RotationSettingsControllerTest -q 2>&1 | tail -5
```

Expected: compilation failure (`RotationSettingsController` does not exist)

- [ ] **Step 3: Write the implementation**

```java
package com.octopus.teamcity.oidc;

import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.controllers.BaseController;
import jetbrains.buildServer.serverSide.auth.Permission;
import jetbrains.buildServer.users.SUser;
import jetbrains.buildServer.web.CSRFFilter;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import jetbrains.buildServer.web.util.SessionUser;
import net.minidev.json.JSONObject;
import org.jetbrains.annotations.NotNull;
import org.springframework.scheduling.support.CronExpression;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RotationSettingsController extends BaseController {
    private static final Logger LOG = Logger.getLogger(RotationSettingsController.class.getName());
    static final String PATH = "/admin/jwtRotationSettings.html";

    private final RotationSettingsManager settingsManager;
    private final CSRFFilter csrfFilter;

    public RotationSettingsController(@NotNull WebControllerManager controllerManager,
                                      @NotNull RotationSettingsManager settingsManager,
                                      @NotNull ExtensionHolder extensionHolder) {
        this(controllerManager, settingsManager, new CSRFFilter(extensionHolder));
    }

    RotationSettingsController(@NotNull WebControllerManager controllerManager,
                               @NotNull RotationSettingsManager settingsManager,
                               @NotNull CSRFFilter csrfFilter) {
        this.settingsManager = settingsManager;
        this.csrfFilter = csrfFilter;
        controllerManager.registerController(PATH, this);
        LOG.info("JWT plugin: RotationSettingsController registered at " + PATH);
    }

    @Override
    protected ModelAndView doHandle(@NotNull HttpServletRequest request,
                                    @NotNull HttpServletResponse response) throws IOException {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return null;
        }

        if (!csrfFilter.validateRequest(request, response)) {
            return null;
        }

        SUser user = SessionUser.getUser(request);
        if (user == null || !user.isPermissionGrantedGlobally(Permission.MANAGE_SERVER_INSTALLATION)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            writeJson(response, false, "Access denied");
            return null;
        }

        response.setContentType("application/json;charset=UTF-8");

        String cronSchedule = request.getParameter("cronSchedule");
        if (cronSchedule == null || cronSchedule.isBlank()) {
            writeJson(response, false, "Missing required parameter: cronSchedule");
            return null;
        }
        try {
            CronExpression.parse(cronSchedule);
        } catch (IllegalArgumentException e) {
            writeJson(response, false, "Invalid cron schedule: " + e.getMessage());
            return null;
        }

        boolean enabled = "true".equalsIgnoreCase(request.getParameter("enabled"));
        RotationSettings current = settingsManager.load();
        settingsManager.save(new RotationSettings(enabled, cronSchedule, current.lastRotatedAt()));

        LOG.info("JWT plugin: rotation settings updated (enabled=" + enabled + ", schedule=" + cronSchedule + ")");
        writeJson(response, true, "Settings saved");
        return null;
    }

    private static void writeJson(HttpServletResponse response, boolean ok, String message) throws IOException {
        JSONObject json = new JSONObject();
        json.put("ok", ok);
        json.put("message", message);
        response.getWriter().write(json.toJSONString());
    }
}
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
JAVA_HOME=/Users/matt/Library/Java/JavaVirtualMachines/corretto-21.0.1/Contents/Home \
  mvn test -pl oidc-plugin-server -Dtest=RotationSettingsControllerTest -q 2>&1 | tail -5
```

Expected: BUILD SUCCESS

- [ ] **Step 5: Add bean to Spring XML**

In `oidc-plugin-server/src/main/resources/META-INF/build-server-plugin-jwt-plugin.xml`, add after `keyRotationController`:

```xml
    <bean id="rotationSettingsController" class="com.octopus.teamcity.oidc.RotationSettingsController"/>
```

Full updated file:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-3.0.xsd"
       default-autowire="constructor">
    <bean id="jwtKeyManager" class="com.octopus.teamcity.oidc.JwtKeyManager"/>
    <bean id="rotationSettingsManager"
          factory-bean="jwtKeyManager"
          factory-method="createRotationSettingsManager"/>
    <bean id="keyRotationScheduler" class="com.octopus.teamcity.oidc.KeyRotationScheduler"/>
    <bean id="jwtBuildFeature" class="com.octopus.teamcity.oidc.JwtBuildFeature" />
    <bean id="jwtBuildStartContext" class="com.octopus.teamcity.oidc.JwtBuildStartContext" init-method="register" />
    <bean id="jwtPasswordsProvider" class="com.octopus.teamcity.oidc.JwtPasswordsProvider" init-method="register" />
    <bean id="jwtBuildParametersProvider" class="com.octopus.teamcity.oidc.JwtBuildParametersProvider" init-method="register" />
    <bean id="jwtBuildFeatureAdminPage" class="com.octopus.teamcity.oidc.JwtBuildFeatureAdminPage"/>
    <bean id="keyRotationController" class="com.octopus.teamcity.oidc.KeyRotationController"/>
    <bean id="rotationSettingsController" class="com.octopus.teamcity.oidc.RotationSettingsController"/>
    <bean id="wellKnownPublicFilter" class="com.octopus.teamcity.oidc.WellKnownPublicFilter"/>
    <bean id="jwtTestController" class="com.octopus.teamcity.oidc.JwtTestController"/>
</beans>
```

- [ ] **Step 6: Run all tests**

```bash
JAVA_HOME=/Users/matt/Library/Java/JavaVirtualMachines/corretto-21.0.1/Contents/Home \
  mvn test -pl oidc-plugin-server -q 2>&1 | tail -5
```

Expected: BUILD SUCCESS

- [ ] **Step 7: Commit**

```bash
git add oidc-plugin-server/src/main/java/com/octopus/teamcity/oidc/RotationSettingsController.java \
        oidc-plugin-server/src/test/java/com/octopus/teamcity/oidc/RotationSettingsControllerTest.java \
        oidc-plugin-server/src/main/resources/META-INF/build-server-plugin-jwt-plugin.xml
git commit --no-gpg-sign -m "feat: add RotationSettingsController for AJAX save of rotation config"
```

---

## Task 2: Extend `JwtBuildFeatureAdminPage` with rotation model attributes

**Files:**
- Modify: `oidc-plugin-server/src/main/java/com/octopus/teamcity/oidc/JwtBuildFeatureAdminPage.java`

No unit test added here — `AdminPage` subclasses require full TC container internals that are not available in unit tests. Correctness verified by compile success and manual smoke test.

- [ ] **Step 1: Update `JwtBuildFeatureAdminPage`**

Replace the full file content:

```java
package com.octopus.teamcity.oidc;

import com.nimbusds.jose.jwk.JWKSet;
import jetbrains.buildServer.controllers.admin.AdminPage;
import jetbrains.buildServer.serverSide.auth.Permission;
import jetbrains.buildServer.web.openapi.PagePlaces;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.PositionConstraint;
import org.jetbrains.annotations.NotNull;
import org.springframework.scheduling.support.CronExpression;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Map;

public class JwtBuildFeatureAdminPage extends AdminPage {
    private static final String PAGE = "jwtBuildFeatureSettings.jsp";
    private static final String TAB_TITLE = "JWT build feature";
    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneOffset.UTC);

    @NotNull private final JwtKeyManager keyManager;
    @NotNull private final RotationSettingsManager settingsManager;

    public JwtBuildFeatureAdminPage(@NotNull PagePlaces pagePlaces,
                                    @NotNull PluginDescriptor descriptor,
                                    @NotNull JwtKeyManager keyManager,
                                    @NotNull RotationSettingsManager settingsManager) {
        super(pagePlaces);
        this.keyManager = keyManager;
        this.settingsManager = settingsManager;
        setPluginName("jwtPlugin");
        setIncludeUrl(descriptor.getPluginResourcesPath(PAGE));
        setTabTitle(TAB_TITLE);
        setPosition(PositionConstraint.after("clouds", "email", "jabber"));
        register();
    }

    @Override
    public void fillModel(@NotNull Map<String, Object> model, @NotNull HttpServletRequest request) {
        super.fillModel(model, request);

        JWKSet jwks = new JWKSet(keyManager.getPublicKeys());
        String jwksJson = jwks.toString();
        model.put("jwks", jwksJson);
        model.put("jwksBase64", Base64.getEncoder().encodeToString(jwksJson.getBytes(StandardCharsets.UTF_8)));

        RotationSettings settings = settingsManager.load();
        model.put("rotationEnabled", settings.enabled());
        model.put("cronSchedule", settings.cronSchedule());

        if (settings.lastRotatedAt() != null) {
            model.put("lastRotatedAt", FMT.format(settings.lastRotatedAt()) + " UTC");
        } else {
            model.put("lastRotatedAt", "Never");
        }

        if (settings.enabled() && settings.lastRotatedAt() != null) {
            try {
                CronExpression cron = CronExpression.parse(settings.cronSchedule());
                LocalDateTime last = settings.lastRotatedAt().atZone(ZoneOffset.UTC).toLocalDateTime();
                LocalDateTime next = cron.next(last);
                model.put("nextDue", next != null
                        ? FMT.format(next.atZone(ZoneOffset.UTC).toInstant()) + " UTC"
                        : null);
            } catch (IllegalArgumentException e) {
                model.put("nextDue", null);
            }
        } else {
            model.put("nextDue", null);
        }
    }

    @Override
    public boolean isAvailable(@NotNull HttpServletRequest request) {
        return super.isAvailable(request) && checkHasGlobalPermission(request, Permission.CHANGE_SERVER_SETTINGS);
    }

    @NotNull
    @Override
    public String getGroup() {
        return INTEGRATIONS_GROUP;
    }
}
```

- [ ] **Step 2: Compile**

```bash
JAVA_HOME=/Users/matt/Library/Java/JavaVirtualMachines/corretto-21.0.1/Contents/Home \
  mvn compile -pl oidc-plugin-server -q 2>&1 | tail -5
```

Expected: BUILD SUCCESS

- [ ] **Step 3: Run all tests**

```bash
JAVA_HOME=/Users/matt/Library/Java/JavaVirtualMachines/corretto-21.0.1/Contents/Home \
  mvn test -pl oidc-plugin-server -q 2>&1 | tail -5
```

Expected: BUILD SUCCESS (Spring's `default-autowire="constructor"` will inject `rotationSettingsManager` automatically — it is already declared as a bean)

- [ ] **Step 4: Commit**

```bash
git add oidc-plugin-server/src/main/java/com/octopus/teamcity/oidc/JwtBuildFeatureAdminPage.java
git commit --no-gpg-sign -m "feat: populate rotation model attributes in JwtBuildFeatureAdminPage"
```

---

## Task 3: JSP rotation section

**Files:**
- Modify: `oidc-plugin-server/src/main/resources/buildServerResources/jwtBuildFeatureSettings.jsp`

- [ ] **Step 1: Replace the JSP**

The current JSP is short. Replace it entirely with:

```jsp
<%@ include file="/include-internal.jsp"%>
<%@ taglib prefix="props" tagdir="/WEB-INF/tags/props" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page import="jetbrains.buildServer.serverSide.auth.Permission" %>
<%@ page import="jetbrains.buildServer.web.util.SessionUser" %>
<%
    var currentUser = SessionUser.getUser(request);
    if (currentUser == null || !currentUser.isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS)) {
        response.sendError(javax.servlet.http.HttpServletResponse.SC_FORBIDDEN);
        return;
    }
%>

<h2>Key Rotation</h2>

<table>
  <tr>
    <td>
      <label>
        <input type="checkbox" id="rotationEnabled" <c:if test="${rotationEnabled}">checked</c:if>>
        Enable automatic rotation
      </label>
    </td>
  </tr>
  <tr>
    <td>
      <label for="cronSchedule">Cron schedule (6-field: second minute hour day month weekday):</label><br/>
      <input type="text" id="cronSchedule" size="25" value="<c:out value="${cronSchedule}"/>"/>
      &nbsp;
      <input type="button" value="Save" onclick="jwtSaveRotationSettings()"/>
      &nbsp;
      <input type="button" value="Rotate now" onclick="jwtRotateNow()"/>
    </td>
  </tr>
  <tr>
    <td>
      <span style="color:#555;font-size:0.9em">
        Last rotated: <c:out value="${lastRotatedAt}"/>
        <c:if test="${not empty nextDue}">
          &nbsp;|&nbsp; Next due: <c:out value="${nextDue}"/>
        </c:if>
      </span>
    </td>
  </tr>
  <tr>
    <td>
      <span id="jwtSaveResult" style="display:none"></span>
      <span id="jwtRotateResult" style="display:none"></span>
    </td>
  </tr>
</table>

<script>
  function jwtSaveRotationSettings() {
    var enabled = document.getElementById('rotationEnabled').checked;
    var schedule = document.getElementById('cronSchedule').value;
    jwtAdminPost('/admin/jwtRotationSettings.html',
      'enabled=' + enabled + '&cronSchedule=' + encodeURIComponent(schedule),
      function(data) { jwtShowResult('jwtSaveResult', data.ok, data.message); },
      function() { jwtShowResult('jwtSaveResult', false, 'Request failed'); }
    );
  }

  function jwtRotateNow() {
    jwtAdminPost('/admin/jwtKeyRotate.html', '',
      function(data) {
        var ok = data.status === 'rotated';
        var msg = ok ? 'Keys rotated successfully' : (data.message || 'Rotation failed');
        jwtShowResult('jwtRotateResult', ok, msg);
        if (ok) {
          var now = new Date();
          var formatted = now.getUTCFullYear() + '-' +
            String(now.getUTCMonth() + 1).padStart(2, '0') + '-' +
            String(now.getUTCDate()).padStart(2, '0') + ' ' +
            String(now.getUTCHours()).padStart(2, '0') + ':' +
            String(now.getUTCMinutes()).padStart(2, '0') + ' UTC';
          document.querySelector('span[style*="color:#555"]').innerHTML =
            'Last rotated: ' + formatted;
        }
      },
      function() { jwtShowResult('jwtRotateResult', false, 'Request failed'); }
    );
  }

  function jwtAdminPost(url, body, onSuccess, onError) {
    fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-TC-CSRF-Token': BS.CSRF.token
      },
      body: body
    })
    .then(function(r) { return r.json(); })
    .then(onSuccess)
    .catch(onError);
  }

  function jwtShowResult(elementId, ok, message) {
    var el = document.getElementById(elementId);
    el.textContent = message;
    el.style.color = ok ? 'green' : 'red';
    el.style.display = 'inline';
  }
</script>

<h2>JWKS</h2>
<pre><c:out value="${jwks}"/></pre>
<a href="data:application/json;charset=utf-8;base64,${jwksBase64}" download="jwks.json">download</a>
```

- [ ] **Step 2: Compile**

```bash
JAVA_HOME=/Users/matt/Library/Java/JavaVirtualMachines/corretto-21.0.1/Contents/Home \
  mvn compile -pl oidc-plugin-server -q 2>&1 | tail -5
```

Expected: BUILD SUCCESS

- [ ] **Step 3: Run all tests**

```bash
JAVA_HOME=/Users/matt/Library/Java/JavaVirtualMachines/corretto-21.0.1/Contents/Home \
  mvn test -pl oidc-plugin-server -q 2>&1 | tail -5
```

Expected: BUILD SUCCESS

- [ ] **Step 4: Commit**

```bash
git add oidc-plugin-server/src/main/resources/buildServerResources/jwtBuildFeatureSettings.jsp
git commit --no-gpg-sign -m "feat: add rotation settings UI to JWT admin tab"
```

---

## Self-Review

**Spec coverage:**
- ✅ New `RotationSettingsController` POST endpoint — Task 1
- ✅ CSRF + permission guard on controller — Task 1
- ✅ Cron validation with `CronExpression.parse()` — Task 1
- ✅ `preservesLastRotatedAt` on save — Task 1
- ✅ `JwtBuildFeatureAdminPage` injects `RotationSettingsManager` — Task 2
- ✅ Four model attributes: `rotationEnabled`, `cronSchedule`, `lastRotatedAt`, `nextDue` — Task 2
- ✅ `nextDue` null when disabled or never rotated — Task 2
- ✅ Rotation section above JWKS — Task 3
- ✅ AJAX Save with inline feedback — Task 3
- ✅ AJAX Rotate now with inline feedback + status refresh — Task 3
- ✅ Spring XML wiring — Task 1
- ✅ `rotationSettingsController` bean registered — Task 1

**Placeholder scan:** None found.

**Type consistency:**
- `RotationSettingsController.PATH` defined in Task 1, referenced nowhere else — consistent.
- `RotationSettings(boolean, String, Instant)` constructor used correctly throughout.
- Model attribute names (`rotationEnabled`, `cronSchedule`, `lastRotatedAt`, `nextDue`) match between Task 2 (Java) and Task 3 (JSP EL expressions).
- `jwtSaveRotationSettings()`, `jwtRotateNow()`, `jwtAdminPost()`, `jwtShowResult()` — all defined and called within Task 3 only.
