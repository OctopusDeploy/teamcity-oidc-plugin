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
        StringWriter sw = new StringWriter();
        when(resp.getWriter()).thenReturn(new PrintWriter(sw));

        try (MockedStatic<SessionUser> su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(req)).thenReturn(null);
            controller.doHandle(req, resp);
        }

        verify(resp).setStatus(HttpServletResponse.SC_FORBIDDEN);
        JSONObject body = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(sw.toString());
        assertThat((Boolean) body.get("ok")).isFalse();
        assertThat(body.getAsString("message")).isEqualTo("Access denied");
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

        assertThat((Boolean) result.get("ok")).isTrue();
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

    // ---- helpers ----

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
        lenient().when(req.getMethod()).thenReturn("POST");
        params.forEach((k, v) -> lenient().when(req.getParameter(k)).thenReturn(v));
        return req;
    }
}
