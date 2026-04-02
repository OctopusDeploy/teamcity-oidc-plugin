# Test Connection Button — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a "Test Connection" button to the JWT build feature edit page that progressively verifies JWT issuance, OIDC discovery, JWKS signature, and optionally a cloud token exchange — all via a modal dialog.

**Architecture:** A new `JwtTestController` at `POST /admin/jwtTest.html` handles four steps (`jwt`, `discovery`, `jwks`, `exchange`), each returning `{"ok":true/false,"message":"..."}`. The `jwt` step also returns a `token` field. The JSP gains a button that opens a modal; inline JS fires the steps sequentially and renders each result as it arrives. HTTP calls (discovery/JWKS/exchange) use an injected `java.net.http.HttpClient` so tests can target a local server.

**Tech Stack:** Java 21, Nimbus JOSE+JWT, json-smart (`net.minidev.json`), `java.net.http.HttpClient`, JUnit 5 + Mockito, `com.sun.net.httpserver.HttpServer` (JDK built-in, no new deps) for test HTTP mocking, TeamCity `BaseController`.

---

## File Structure

| File | Action | Purpose |
|------|--------|---------|
| `jwt-plugin-server/src/main/java/de/ndr/teamcity/JwtTestController.java` | **Create** | Handles all four test steps; auth check; returns JSON |
| `jwt-plugin-server/src/test/java/de/ndr/teamcity/JwtTestControllerTest.java` | **Create** | Unit tests for all steps and auth |
| `jwt-plugin-server/src/main/resources/META-INF/build-server-plugin-jwt-plugin.xml` | **Modify** | Register `jwtTestController` bean |
| `jwt-plugin-server/src/main/resources/buildServerResources/editJwtBuildFeature.jsp` | **Modify** | Add button, modal HTML, and JS |

---

## Task 1: Controller skeleton + auth + `step=jwt`

**Files:**
- Create: `jwt-plugin-server/src/main/java/de/ndr/teamcity/JwtTestController.java`
- Create: `jwt-plugin-server/src/test/java/de/ndr/teamcity/JwtTestControllerTest.java`

### Background

`KeyRotationController` (at `jwt-plugin-server/src/main/java/de/ndr/teamcity/KeyRotationController.java`) is the pattern to follow: extends `BaseController`, injects `WebControllerManager` + domain beans via constructor, calls `controllerManager.registerController(PATH, this)`, checks `SessionUser.getUser(request)` + `MANAGE_SERVER_INSTALLATION`.

The `jwt` step issues a real signed JWT using the current key material from `JwtBuildFeature`. It returns `{"ok":true,"message":"JWT issued (kid: X, alg: RS256, ttl: 10m)","token":"<serialized>"}` — the `token` field is used by subsequent steps. The `step=jwt` response is the only one that includes a `token` field.

Fails fast with `{"ok":false,"message":"Root URL is not HTTPS — OIDC endpoints won't be reachable"}` if `buildServer.getRootUrl()` does not start with `https://`.

- [ ] **Step 1: Write failing tests**

Create `jwt-plugin-server/src/test/java/de/ndr/teamcity/JwtTestControllerTest.java`:

```java
package de.ndr.teamcity;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import jetbrains.buildServer.serverSide.ServerPaths;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.serverSide.auth.Permission;
import jetbrains.buildServer.users.SUser;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import jetbrains.buildServer.web.util.SessionUser;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
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
import java.net.http.HttpClient;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class JwtTestControllerTest {

    @Mock WebControllerManager controllerManager;
    @Mock SBuildServer buildServer;
    @Mock ServerPaths serverPaths;
    @Mock PluginDescriptor pluginDescriptor;

    @TempDir File tempDir;

    JwtBuildFeature feature;
    JwtTestController controller;
    // A real HttpClient is fine for steps that don't make network calls (jwt step)
    HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    void setup() {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        feature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);
        controller = new JwtTestController(controllerManager, feature, buildServer, httpClient);
    }

    // ---- auth ----

    @Test
    void nonAdminReturns403() throws Exception {
        HttpServletRequest req = mockPost(Map.of("step", "jwt"));
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getWriter()).thenReturn(new PrintWriter(new StringWriter()));

        try (MockedStatic<SessionUser> su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(req)).thenReturn(null);
            controller.doHandle(req, resp);
        }

        verify(resp).setStatus(HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    void nonPostReturns405() throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("GET");
        HttpServletResponse resp = mock(HttpServletResponse.class);

        controller.doHandle(req, resp);

        verify(resp).setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
    }

    // ---- step=jwt ----

    @Test
    void jwtStepRS256ReturnsSignedToken() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
        JSONObject result = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "10", "audience", "https://tc.example.com"
        ));

        assertThat((Boolean) result.get("ok")).isTrue();
        assertThat(result.getAsString("token")).isNotBlank();
        SignedJWT jwt = SignedJWT.parse(result.getAsString("token"));
        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
    }

    @Test
    void jwtStepES256ReturnsSignedToken() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
        JSONObject result = callStep(Map.of(
            "step", "jwt", "algorithm", "ES256", "ttl_minutes", "10", "audience", "https://tc.example.com"
        ));

        assertThat(result.getAsString("ok")).isEqualTo("true");
        SignedJWT jwt = SignedJWT.parse(result.getAsString("token"));
        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
    }

    @Test
    void jwtStepFailsWhenRootUrlIsNotHttps() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("http://tc.example.com");
        JSONObject result = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "10", "audience", "aud"
        ));

        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("not HTTPS");
    }

    // ---- helpers ----

    JSONObject callStep(Map<String, String> params) throws Exception {
        HttpServletRequest req = mockPost(params);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        StringWriter sw = new StringWriter();
        when(resp.getWriter()).thenReturn(new PrintWriter(sw));

        SUser admin = mock(SUser.class);
        when(admin.isPermissionGrantedGlobally(Permission.MANAGE_SERVER_INSTALLATION)).thenReturn(true);

        try (MockedStatic<SessionUser> su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(req)).thenReturn(admin);
            controller.doHandle(req, resp);
        }

        return (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(sw.toString());
    }

    HttpServletRequest mockPost(Map<String, String> params) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("POST");
        params.forEach((k, v) -> when(req.getParameter(k)).thenReturn(v));
        return req;
    }
}
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
JAVA_HOME=$(jenv javahome) mvn test -pl jwt-plugin-server -Dtest=JwtTestControllerTest -am 2>&1 | tail -20
```

Expected: compilation error — `JwtTestController` does not exist yet.

- [ ] **Step 3: Create `JwtTestController.java`**

Create `jwt-plugin-server/src/main/java/de/ndr/teamcity/JwtTestController.java`:

```java
package de.ndr.teamcity;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jetbrains.buildServer.controllers.BaseController;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.serverSide.auth.Permission;
import jetbrains.buildServer.users.SUser;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import jetbrains.buildServer.web.util.SessionUser;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.jetbrains.annotations.NotNull;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

public class JwtTestController extends BaseController {
    private static final Logger LOG = Logger.getLogger(JwtTestController.class.getName());
    static final String PATH = "/admin/jwtTest.html";

    private final JwtBuildFeature jwtBuildFeature;
    private final SBuildServer buildServer;
    private final HttpClient httpClient;

    public JwtTestController(@NotNull WebControllerManager controllerManager,
                              @NotNull JwtBuildFeature jwtBuildFeature,
                              @NotNull SBuildServer buildServer) {
        this(controllerManager, jwtBuildFeature, buildServer,
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build());
    }

    JwtTestController(@NotNull WebControllerManager controllerManager,
                      @NotNull JwtBuildFeature jwtBuildFeature,
                      @NotNull SBuildServer buildServer,
                      @NotNull HttpClient httpClient) {
        this.jwtBuildFeature = jwtBuildFeature;
        this.buildServer = buildServer;
        this.httpClient = httpClient;
        controllerManager.registerController(PATH, this);
        LOG.info("JWT plugin: JwtTestController registered at " + PATH);
    }

    @Override
    protected ModelAndView doHandle(@NotNull HttpServletRequest request,
                                    @NotNull HttpServletResponse response) throws IOException {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return null;
        }

        SUser user = SessionUser.getUser(request);
        if (user == null || !user.isPermissionGrantedGlobally(Permission.MANAGE_SERVER_INSTALLATION)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            writeJson(response, false, "Access denied");
            return null;
        }

        response.setContentType("application/json;charset=UTF-8");
        String step = request.getParameter("step");
        try {
            if ("jwt".equals(step)) {
                String[] result = stepJwt(request); // [message, serializedToken]
                JSONObject json = new JSONObject();
                json.put("ok", true);
                json.put("message", result[0]);
                json.put("token", result[1]);
                response.getWriter().write(json.toJSONString());
            } else {
                String message = switch (step) {
                    case "discovery" -> stepDiscovery();
                    case "jwks" -> stepJwks(request);
                    case "exchange" -> stepExchange(request);
                    default -> throw new IllegalArgumentException("Unknown step: " + step);
                };
                writeJson(response, true, message);
            }
        } catch (TestStepException e) {
            writeJson(response, false, e.getMessage());
        } catch (Exception e) {
            LOG.log(Level.WARNING, "JWT plugin: test step '" + step + "' failed", e);
            writeJson(response, false, e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
        }
        return null;
    }

    private String[] stepJwt(HttpServletRequest request) throws Exception {
        String rootUrl = buildServer.getRootUrl();
        if (rootUrl == null || !rootUrl.startsWith("https://")) {
            throw new TestStepException("Root URL is not HTTPS — OIDC endpoints won't be reachable");
        }
        String algorithm = request.getParameter("algorithm");
        if (algorithm == null || algorithm.isBlank()) algorithm = "RS256";
        int ttl = parseTtl(request.getParameter("ttl_minutes"));
        String audience = request.getParameter("audience");
        if (audience == null || audience.isBlank()) audience = rootUrl;

        JWSHeader header;
        JWSSigner signer;
        if ("ES256".equals(algorithm)) {
            ECKey ecKey = jwtBuildFeature.getEcKey();
            header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecKey.getKeyID()).build();
            signer = new ECDSASigner(ecKey);
        } else {
            RSAKey rsaKey = jwtBuildFeature.getRsaKey();
            header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build();
            signer = new RSASSASigner(rsaKey);
        }

        Date now = new Date();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .subject("test")
                .issuer(rootUrl)
                .audience(List.of(audience))
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + ttl * 60_000L))
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(signer);
        String serialized = jwt.serialize();
        String message = "JWT issued (kid: " + header.getKeyID() + ", alg: " + algorithm + ", ttl: " + ttl + "m)";
        return new String[]{message, serialized};
    }

    private String stepDiscovery() throws Exception {
        String rootUrl = buildServer.getRootUrl();
        String url = rootUrl + "/.well-known/openid-configuration";
        HttpResponse<String> resp = httpGet(url);
        if (resp.statusCode() != 200) {
            throw new TestStepException("Discovery endpoint returned HTTP " + resp.statusCode());
        }
        JSONObject doc = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(resp.body());
        String issuer = (String) doc.get("issuer");
        if (!rootUrl.equals(issuer)) {
            throw new TestStepException("issuer mismatch: expected \"" + rootUrl + "\", got \"" + issuer + "\"");
        }
        return "Discovery endpoint OK (issuer matches)";
    }

    private String stepJwks(HttpServletRequest request) throws Exception {
        String token = request.getParameter("token");
        String rootUrl = buildServer.getRootUrl();
        String url = rootUrl + "/.well-known/jwks.json";
        HttpResponse<String> resp = httpGet(url);
        if (resp.statusCode() != 200) {
            throw new TestStepException("JWKS endpoint returned HTTP " + resp.statusCode());
        }
        com.nimbusds.jose.jwk.JWKSet jwks = com.nimbusds.jose.jwk.JWKSet.parse(resp.body());
        SignedJWT jwt = SignedJWT.parse(token);
        String kid = jwt.getHeader().getKeyID();
        com.nimbusds.jose.jwk.JWK jwk = jwks.getKeyByKeyId(kid);
        if (jwk == null) {
            throw new TestStepException("Key ID not found in JWKS (kid: " + kid + ")");
        }
        boolean verified;
        if (jwk instanceof com.nimbusds.jose.jwk.RSAKey rsaKey) {
            verified = jwt.verify(new com.nimbusds.jose.crypto.RSASSAVerifier(rsaKey));
        } else if (jwk instanceof com.nimbusds.jose.jwk.ECKey ecKey) {
            verified = jwt.verify(new com.nimbusds.jose.crypto.ECDSAVerifier(ecKey));
        } else {
            throw new TestStepException("Unsupported key type in JWKS: " + jwk.getKeyType());
        }
        if (!verified) {
            throw new TestStepException("Signature verification failed");
        }
        return "JWKS OK — signature verified";
    }

    private String stepExchange(HttpServletRequest request) throws Exception {
        String token = request.getParameter("token");
        String serviceUrl = request.getParameter("serviceUrl");
        String audience = request.getParameter("audience");

        // Discover token endpoint from service's OIDC discovery doc
        String discoveryUrl = serviceUrl + "/.well-known/openid-configuration";
        HttpResponse<String> discoveryResp = httpGet(discoveryUrl);
        if (discoveryResp.statusCode() != 200) {
            throw new TestStepException("Service discovery returned HTTP " + discoveryResp.statusCode());
        }
        JSONObject discoveryDoc = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(discoveryResp.body());
        String tokenEndpoint = (String) discoveryDoc.get("token_endpoint");
        if (tokenEndpoint == null || tokenEndpoint.isBlank()) {
            throw new TestStepException("token_endpoint not found in service discovery document");
        }

        // Build exchange request body
        JSONObject body = new JSONObject();
        body.put("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange");
        body.put("audience", audience);
        body.put("subject_token", token);
        body.put("subject_token_type", "urn:ietf:params:oauth:token-type:jwt");

        HttpRequest exchangeReq = HttpRequest.newBuilder()
                .uri(URI.create(tokenEndpoint))
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body.toJSONString()))
                .build();
        HttpResponse<String> exchangeResp = httpClient.send(exchangeReq,
                HttpResponse.BodyHandlers.ofString());
        int status = exchangeResp.statusCode();
        String bodySnippet = exchangeResp.body().length() > 200
                ? exchangeResp.body().substring(0, 200) : exchangeResp.body();
        if (status < 200 || status >= 300) {
            throw new TestStepException("Exchange failed (HTTP " + status + "): " + bodySnippet);
        }
        return "Exchange succeeded (HTTP " + status + ")";
    }

    private HttpResponse<String> httpGet(String url) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(5))
                .GET()
                .build();
        try {
            return httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new TestStepException("Could not reach " + url + " — "
                    + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private static int parseTtl(String value) {
        try {
            return (value != null && !value.isBlank()) ? Integer.parseInt(value) : 10;
        } catch (NumberFormatException e) {
            return 10;
        }
    }

    private static void writeJson(HttpServletResponse response, boolean ok, String message) throws IOException {
        JSONObject json = new JSONObject();
        json.put("ok", ok);
        json.put("message", message);
        response.getWriter().write(json.toJSONString());
    }

    static class TestStepException extends Exception {
        TestStepException(String message) {
            super(message);
        }
    }
}
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
JAVA_HOME=$(jenv javahome) mvn test -pl jwt-plugin-server -Dtest=JwtTestControllerTest -am 2>&1 | tail -20
```

Expected: `Tests run: 5, Failures: 0, Errors: 0`

- [ ] **Step 5: Commit**

```bash
git add jwt-plugin-server/src/main/java/de/ndr/teamcity/JwtTestController.java \
        jwt-plugin-server/src/test/java/de/ndr/teamcity/JwtTestControllerTest.java
git commit -m "feat: add JwtTestController with step=jwt and auth checks"
```

---

## Task 2: `step=discovery` and `step=jwks`

**Files:**
- Modify: `jwt-plugin-server/src/test/java/de/ndr/teamcity/JwtTestControllerTest.java`

The controller code for these steps is already implemented in Task 1. This task adds tests for them using a real local HTTP server (no new dependencies — `com.sun.net.httpserver.HttpServer` ships in the JDK).

### Background

`com.sun.net.httpserver.HttpServer.create(new InetSocketAddress(0), 0)` binds to a random free port. `server.getAddress().getPort()` retrieves it after `server.start()`. Each context handler receives a `com.sun.net.httpserver.HttpExchange`; write the response body and call `exchange.close()`.

For the `step=jwks` test, the test server needs to serve the JWKS of the real `JwtBuildFeature` so that signature verification works. Get the JWKS JSON with:
```java
new com.nimbusds.jose.jwk.JWKSet(feature.getPublicKeys()).toString()
```

- [ ] **Step 1: Add discovery and JWKS tests**

Add these tests to `JwtTestControllerTest` (inside the class, after the existing tests):

```java
// ---- step=discovery ----

@Test
void discoveryStepSucceedsWhenIssuerMatches() throws Exception {
    // HttpServer.create() binds immediately — port is known before start()
    com.sun.net.httpserver.HttpServer server =
        com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(0), 0);
    int port = server.getAddress().getPort();
    String issuer = "http://localhost:" + port;
    addContext(server, "/.well-known/openid-configuration",
        200, "{\"issuer\":\"" + issuer + "\"}");
    server.start();
    when(buildServer.getRootUrl()).thenReturn(issuer);

    try {
        JSONObject result = callStep(Map.of("step", "discovery"));
        assertThat((Boolean) result.get("ok")).isTrue();
        assertThat(result.getAsString("message")).contains("Discovery endpoint OK");
    } finally {
        server.stop(0);
    }
}

@Test
void discoveryStepFailsWhenIssuerMismatches() throws Exception {
    // HttpServer.create() binds immediately — port is known before start()
    com.sun.net.httpserver.HttpServer server =
        com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(0), 0);
    addContext(server, "/.well-known/openid-configuration",
        200, "{\"issuer\":\"https://wrong.example.com\"}");
    server.start();
    int port = server.getAddress().getPort();
    when(buildServer.getRootUrl()).thenReturn("http://localhost:" + port);

    try {
        JSONObject result = callStep(Map.of("step", "discovery"));
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("issuer mismatch");
    } finally {
        server.stop(0);
    }
}

@Test
void discoveryStepFailsWhenServerUnreachable() throws Exception {
    when(buildServer.getRootUrl()).thenReturn("http://localhost:1"); // nothing listening on port 1
    JSONObject result = callStep(Map.of("step", "discovery"));
    assertThat((Boolean) result.get("ok")).isFalse();
    assertThat(result.getAsString("message")).contains("Could not reach");
}

// ---- step=jwks ----

@Test
void jwksStepVerifiesValidRs256Token() throws Exception {
    when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
    // Issue a real RS256 token
    JSONObject jwtResult = callStep(Map.of(
        "step", "jwt", "algorithm", "RS256", "ttl_minutes", "5", "audience", "aud"
    ));
    String token = jwtResult.getAsString("token");

    // Serve our JWKS on a local HTTP server
    String jwksJson = new com.nimbusds.jose.jwk.JWKSet(feature.getPublicKeys()).toString();
    com.sun.net.httpserver.HttpServer server =
        com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(0), 0);
    addContext(server, "/.well-known/jwks.json", 200, jwksJson);
    server.start();
    int port = server.getAddress().getPort();
    when(buildServer.getRootUrl()).thenReturn("http://localhost:" + port);

    try {
        JSONObject result = callStep(Map.of("step", "jwks", "token", token));
        assertThat((Boolean) result.get("ok")).isTrue();
        assertThat(result.getAsString("message")).contains("JWKS OK");
    } finally {
        server.stop(0);
    }
}

@Test
void jwksStepVerifiesValidEs256Token() throws Exception {
    when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
    JSONObject jwtResult = callStep(Map.of(
        "step", "jwt", "algorithm", "ES256", "ttl_minutes", "5", "audience", "aud"
    ));
    String token = jwtResult.getAsString("token");

    String jwksJson = new com.nimbusds.jose.jwk.JWKSet(feature.getPublicKeys()).toString();
    com.sun.net.httpserver.HttpServer server =
        com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(0), 0);
    addContext(server, "/.well-known/jwks.json", 200, jwksJson);
    server.start();
    int port = server.getAddress().getPort();
    when(buildServer.getRootUrl()).thenReturn("http://localhost:" + port);

    try {
        JSONObject result = callStep(Map.of("step", "jwks", "token", token));
        assertThat((Boolean) result.get("ok")).isTrue();
    } finally {
        server.stop(0);
    }
}

@Test
void jwksStepFailsWhenKidNotInJwks() throws Exception {
    when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
    JSONObject jwtResult = callStep(Map.of(
        "step", "jwt", "algorithm", "RS256", "ttl_minutes", "5", "audience", "aud"
    ));
    String token = jwtResult.getAsString("token");

    // Serve an empty JWKS
    com.sun.net.httpserver.HttpServer server =
        com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(0), 0);
    addContext(server, "/.well-known/jwks.json", 200, "{\"keys\":[]}");
    server.start();
    int port = server.getAddress().getPort();
    when(buildServer.getRootUrl()).thenReturn("http://localhost:" + port);

    try {
        JSONObject result = callStep(Map.of("step", "jwks", "token", token));
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("Key ID not found");
    } finally {
        server.stop(0);
    }
}
```

Also add this helper method inside the class (alongside the existing `callStep` and `mockPost` helpers):

```java
private static void addContext(com.sun.net.httpserver.HttpServer server,
                                String path, int status, String body) {
    server.createContext(path, exchange -> {
        byte[] bytes = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    });
}
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
JAVA_HOME=$(jenv javahome) mvn test -pl jwt-plugin-server -Dtest=JwtTestControllerTest -am 2>&1 | tail -20
```

Expected: compilation error on new test methods (helper methods missing).

- [ ] **Step 3: Run tests after adding helpers — verify they pass**

```bash
JAVA_HOME=$(jenv javahome) mvn test -pl jwt-plugin-server -Dtest=JwtTestControllerTest -am 2>&1 | tail -20
```

Expected: `Tests run: 11, Failures: 0, Errors: 0`

- [ ] **Step 4: Commit**

```bash
git add jwt-plugin-server/src/test/java/de/ndr/teamcity/JwtTestControllerTest.java
git commit -m "test: add discovery and JWKS step tests for JwtTestController"
```

---

## Task 3: `step=exchange`

**Files:**
- Modify: `jwt-plugin-server/src/test/java/de/ndr/teamcity/JwtTestControllerTest.java`

The exchange implementation is already in the controller from Task 1. This task adds tests using a local HTTP server that serves both a discovery doc and a token endpoint.

- [ ] **Step 1: Add exchange tests**

Add these tests inside `JwtTestControllerTest`:

```java
// ---- step=exchange ----

@Test
void exchangeStepSucceedsWhenTokenEndpointReturns200() throws Exception {
    // Issue a JWT first (HTTPS rootUrl required for step=jwt)
    when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
    JSONObject jwtResult = callStep(Map.of(
        "step", "jwt", "algorithm", "RS256", "ttl_minutes", "5", "audience", "my-ext-id"
    ));
    String token = jwtResult.getAsString("token");

    // Stand up a mock service that serves discovery + token endpoint
    com.sun.net.httpserver.HttpServer server =
        com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(0), 0);
    server.start();
    int port = server.getAddress().getPort();
    String serviceUrl = "http://localhost:" + port;
    String tokenEndpoint = serviceUrl + "/token";

    addContext(server, "/.well-known/openid-configuration", 200,
        "{\"issuer\":\"" + serviceUrl + "\",\"token_endpoint\":\"" + tokenEndpoint + "\"}");
    addContext(server, "/token", 200,
        "{\"access_token\":\"fake-token\",\"token_type\":\"Bearer\"}");

    try {
        JSONObject result = callStep(Map.of(
            "step", "exchange",
            "token", token,
            "serviceUrl", serviceUrl,
            "audience", "my-ext-id"
        ));
        assertThat((Boolean) result.get("ok")).isTrue();
        assertThat(result.getAsString("message")).contains("Exchange succeeded (HTTP 200)");
    } finally {
        server.stop(0);
    }
}

@Test
void exchangeStepFailsWhenTokenEndpointReturns401() throws Exception {
    when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
    JSONObject jwtResult = callStep(Map.of(
        "step", "jwt", "algorithm", "RS256", "ttl_minutes", "5", "audience", "aud"
    ));
    String token = jwtResult.getAsString("token");

    com.sun.net.httpserver.HttpServer server =
        com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(0), 0);
    server.start();
    int port = server.getAddress().getPort();
    String serviceUrl = "http://localhost:" + port;
    addContext(server, "/.well-known/openid-configuration", 200,
        "{\"token_endpoint\":\"" + serviceUrl + "/token\"}");
    addContext(server, "/token", 401, "{\"error\":\"invalid_token\"}");

    try {
        JSONObject result = callStep(Map.of(
            "step", "exchange", "token", token, "serviceUrl", serviceUrl, "audience", "aud"
        ));
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("Exchange failed (HTTP 401)");
    } finally {
        server.stop(0);
    }
}

@Test
void exchangeStepFailsWhenDiscoveryDocMissingTokenEndpoint() throws Exception {
    when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
    JSONObject jwtResult = callStep(Map.of(
        "step", "jwt", "algorithm", "RS256", "ttl_minutes", "5", "audience", "aud"
    ));
    String token = jwtResult.getAsString("token");

    com.sun.net.httpserver.HttpServer server =
        com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(0), 0);
    addContext(server, "/.well-known/openid-configuration", 200, "{\"issuer\":\"http://svc\"}");
    server.start();
    int port = server.getAddress().getPort();

    try {
        JSONObject result = callStep(Map.of(
            "step", "exchange", "token", token,
            "serviceUrl", "http://localhost:" + port, "audience", "aud"
        ));
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("token_endpoint not found");
    } finally {
        server.stop(0);
    }
}
```

- [ ] **Step 2: Run tests — verify they pass**

```bash
JAVA_HOME=$(jenv javahome) mvn test -pl jwt-plugin-server -Dtest=JwtTestControllerTest -am 2>&1 | tail -20
```

Expected: `Tests run: 14, Failures: 0, Errors: 0`

- [ ] **Step 3: Run full test suite**

```bash
JAVA_HOME=$(jenv javahome) mvn test -pl jwt-plugin-server -am 2>&1 | tail -10
```

Expected: all tests pass, 0 failures.

- [ ] **Step 4: Commit**

```bash
git add jwt-plugin-server/src/test/java/de/ndr/teamcity/JwtTestControllerTest.java
git commit -m "test: add exchange step tests for JwtTestController"
```

---

## Task 4: Spring XML registration + JSP button, modal, and JS

**Files:**
- Modify: `jwt-plugin-server/src/main/resources/META-INF/build-server-plugin-jwt-plugin.xml`
- Modify: `jwt-plugin-server/src/main/resources/buildServerResources/editJwtBuildFeature.jsp`

### Background

The existing JSP (`editJwtBuildFeature.jsp`) is a TC build feature edit form using `<l:settingsGroup>` (which renders a table) and `<props:textProperty>` / `<props:selectProperty>` for fields. Field IDs match their `name` attributes: `ttl_minutes`, `audience`, `algorithm`. The modal and its JS go after the closing `</l:settingsGroup>` tag.

The AJAX posts go to `${pageContext.request.contextPath}/admin/jwtTest.html` — the JSP EL expression is evaluated server-side so the correct context path is baked into the rendered HTML.

- [ ] **Step 1: Register the bean in Spring XML**

In `jwt-plugin-server/src/main/resources/META-INF/build-server-plugin-jwt-plugin.xml`, add one line before the closing `</beans>` tag:

```xml
    <bean id="jwtTestController" class="de.ndr.teamcity.JwtTestController"/>
```

The file uses `default-autowire="constructor"` so TC will inject `WebControllerManager`, `JwtBuildFeature`, and `SBuildServer` automatically.

- [ ] **Step 2: Add button, modal, and JS to the JSP**

Replace the entire content of `jwt-plugin-server/src/main/resources/buildServerResources/editJwtBuildFeature.jsp` with:

```jsp
<%@ include file="/include-internal.jsp"%>
<%@ taglib prefix="props" tagdir="/WEB-INF/tags/props" %>
<%@ taglib prefix="l" tagdir="/WEB-INF/tags/layout" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<l:settingsGroup title="JWT Build Feature">
    <tr>
        <th><label for="ttl_minutes">Token lifetime (minutes):</label></th>
        <td>
            <props:textProperty name="ttl_minutes" value="${empty propertiesBean.properties['ttl_minutes'] ? '10' : propertiesBean.properties['ttl_minutes']}" style="width:5em;"/>
            <span class="smallNote">How long the JWT is valid for. Default: 10 minutes.</span>
            <span class="error" id="error_ttl_minutes"></span>
        </td>
    </tr>
    <tr>
        <th><label for="audience">Audience (<code>aud</code>):</label></th>
        <td>
            <props:textProperty name="audience" value="${propertiesBean.properties['audience']}" style="width:30em;"/>
            <span class="smallNote">Value for the <code>aud</code> claim. Leave blank to use the TeamCity server URL. Cloud providers often require a specific value here (e.g. <code>api://AzureADTokenExchange</code>).</span>
            <span class="error" id="error_audience"></span>
        </td>
    </tr>
    <tr>
        <th><label for="algorithm">Signing algorithm:</label></th>
        <td>
            <props:selectProperty name="algorithm">
                <props:option value="RS256" selected="${empty propertiesBean.properties['algorithm'] || propertiesBean.properties['algorithm'] == 'RS256'}">RS256 (RSA, default)</props:option>
                <props:option value="ES256" selected="${propertiesBean.properties['algorithm'] == 'ES256'}">ES256 (ECDSA P-256)</props:option>
            </props:selectProperty>
            <span class="smallNote">ES256 produces smaller tokens and is widely supported by cloud providers.</span>
        </td>
    </tr>
    <tr>
        <th><label for="claims">Claims to include:</label></th>
        <td>
            <props:textProperty name="claims" value="${propertiesBean.properties['claims']}" style="width:40em;"/>
            <span class="smallNote">Comma-separated list of claims to include in the token. Leave blank to include all.
                Available: <code>branch</code>, <code>build_type_external_id</code>, <code>project_external_id</code>,
                <code>triggered_by</code>, <code>triggered_by_id</code>, <code>build_number</code>.</span>
            <span class="error" id="error_claims"></span>
        </td>
    </tr>
    <tr>
        <th></th>
        <td>
            <button type="button" onclick="jwtTestOpen()">Test Connection</button>
            <span class="smallNote">Verify JWT issuance and OIDC endpoints using the current settings above.</span>
        </td>
    </tr>
</l:settingsGroup>

<%-- Test Connection modal --%>
<div id="jwtTestModal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.6);z-index:10000;align-items:center;justify-content:center;">
    <div style="background:#2b2b2b;border:1px solid #555;border-radius:6px;padding:20px;min-width:480px;max-width:600px;font-size:13px;font-family:monospace;">
        <div style="font-weight:bold;color:#ccc;margin-bottom:14px;font-size:14px;">Test Connection</div>
        <div id="jwtRow0" style="margin-bottom:6px;color:#888;">○ JWT issuance</div>
        <div id="jwtRow1" style="margin-bottom:6px;color:#888;">○ OIDC discovery endpoint</div>
        <div id="jwtRow2" style="margin-bottom:6px;color:#888;">○ JWKS signature verification</div>
        <hr style="border:none;border-top:1px solid #444;margin:12px 0;"/>
        <div style="color:#aaa;margin-bottom:6px;">Optional: test token exchange</div>
        <div style="display:flex;gap:8px;align-items:center;">
            <input id="jwtServiceUrl" type="text" placeholder="https://octopus.example.com"
                   style="flex:1;background:#1e1e1e;border:1px solid #555;color:#ccc;padding:4px 6px;border-radius:3px;"
                   disabled/>
            <button type="button" id="jwtExchangeBtn" onclick="jwtTestExchange()" disabled
                    style="white-space:nowrap;">Try Exchange</button>
        </div>
        <div id="jwtRow3" style="margin-top:6px;min-height:18px;color:#888;"></div>
        <div style="text-align:right;margin-top:14px;">
            <button type="button" onclick="jwtTestClose()">Close</button>
        </div>
    </div>
</div>

<script type="text/javascript">
    var _jwtToken = null;
    var _jwtTestUrl = '${pageContext.request.contextPath}/admin/jwtTest.html';

    function jwtTestOpen() {
        _jwtToken = null;
        ['jwtRow0','jwtRow1','jwtRow2','jwtRow3'].forEach(function(id) {
            var el = document.getElementById(id);
            el.textContent = id === 'jwtRow3' ? '' : '○ Pending';
            el.style.color = '#888';
        });
        document.getElementById('jwtServiceUrl').disabled = true;
        document.getElementById('jwtServiceUrl').value = '';
        document.getElementById('jwtExchangeBtn').disabled = true;
        document.getElementById('jwtTestModal').style.display = 'flex';
        jwtTestRunChecks();
    }

    function jwtTestClose() {
        document.getElementById('jwtTestModal').style.display = 'none';
    }

    function jwtSetRow(id, ok, message) {
        var el = document.getElementById(id);
        el.textContent = (ok ? '✓ ' : '✗ ') + message;
        el.style.color = ok ? '#7ec87e' : '#e06c75';
    }

    function jwtPost(params) {
        var body = Object.entries(params)
            .map(function(e) { return encodeURIComponent(e[0]) + '=' + encodeURIComponent(e[1]); })
            .join('&');
        return fetch(_jwtTestUrl, {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: body
        }).then(function(r) { return r.json(); });
    }

    async function jwtTestRunChecks() {
        var algorithm = document.getElementById('algorithm').value;
        var ttl = document.getElementById('ttl_minutes').value || '10';
        var audience = document.getElementById('audience').value;

        document.getElementById('jwtRow0').textContent = '⏳ Issuing JWT...';
        var r1 = await jwtPost({step:'jwt', algorithm:algorithm, ttl_minutes:ttl, audience:audience});
        jwtSetRow('jwtRow0', r1.ok, r1.ok ? r1.message : r1.message);
        if (!r1.ok) return;
        _jwtToken = r1.token;

        document.getElementById('jwtRow1').textContent = '⏳ Checking discovery endpoint...';
        var r2 = await jwtPost({step:'discovery'});
        jwtSetRow('jwtRow1', r2.ok, r2.message);
        if (!r2.ok) return;

        document.getElementById('jwtRow2').textContent = '⏳ Verifying JWKS signature...';
        var r3 = await jwtPost({step:'jwks', token:_jwtToken});
        jwtSetRow('jwtRow2', r3.ok, r3.message);
        if (!r3.ok) return;

        document.getElementById('jwtServiceUrl').disabled = false;
        document.getElementById('jwtExchangeBtn').disabled = false;
    }

    async function jwtTestExchange() {
        var serviceUrl = document.getElementById('jwtServiceUrl').value.trim();
        if (!serviceUrl) return;
        var audience = document.getElementById('audience').value;
        document.getElementById('jwtExchangeBtn').disabled = true;
        document.getElementById('jwtRow3').textContent = '⏳ Trying exchange...';
        document.getElementById('jwtRow3').style.color = '#888';
        var r = await jwtPost({step:'exchange', token:_jwtToken, serviceUrl:serviceUrl, audience:audience});
        jwtSetRow('jwtRow3', r.ok, r.message);
        document.getElementById('jwtExchangeBtn').disabled = false;
    }
</script>
```

- [ ] **Step 3: Build and verify no compilation errors**

```bash
JAVA_HOME=$(jenv javahome) mvn package -pl jwt-plugin-server -am -DskipTests 2>&1 | tail -10
```

Expected: `BUILD SUCCESS`

- [ ] **Step 4: Run full test suite**

```bash
JAVA_HOME=$(jenv javahome) mvn test -pl jwt-plugin-server -am 2>&1 | tail -10
```

Expected: all tests pass, 0 failures.

- [ ] **Step 5: Commit**

```bash
git add jwt-plugin-server/src/main/resources/META-INF/build-server-plugin-jwt-plugin.xml \
        jwt-plugin-server/src/main/resources/buildServerResources/editJwtBuildFeature.jsp
git commit -m "feat: add Test Connection button, modal, and Spring bean registration"
```

---

## Running All Tests

```bash
JAVA_HOME=$(jenv javahome) mvn test -pl jwt-plugin-server -am 2>&1 | tail -15
```
