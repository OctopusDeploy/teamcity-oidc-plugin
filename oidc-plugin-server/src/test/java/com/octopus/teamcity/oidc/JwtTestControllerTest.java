package com.octopus.teamcity.oidc;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import jetbrains.buildServer.serverSide.ProjectManager;
import jetbrains.buildServer.serverSide.SBuildType;
import jetbrains.buildServer.serverSide.ServerPaths;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.serverSide.auth.Permission;
import jetbrains.buildServer.users.SUser;
import jetbrains.buildServer.web.CSRFFilter;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import jetbrains.buildServer.web.util.SessionUser;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
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
    @Mock ProjectManager projectManager;
    @Mock ServerPaths serverPaths;
    @Mock CSRFFilter csrfFilter;

    @TempDir File tempDir;

    JwtKeyManager keyManager;
    JwtTestController controller;
    HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    void setup() {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        keyManager = new JwtKeyManager(serverPaths);
        // Default: CSRF check passes. lenient() because some tests use GET (CSRF never reached).
        lenient().when(csrfFilter.validateRequest(any(), any())).thenReturn(true);
        controller = new JwtTestController(controllerManager, keyManager, buildServer, httpClient, csrfFilter);
    }

    // ---- auth ----

    @Test
    void nonAdminReturns403() throws Exception {
        final var req = mockPost(Map.of("step", "jwt"));
        final var resp = mock(HttpServletResponse.class);
        final var sw = new StringWriter();
        when(resp.getWriter()).thenReturn(new PrintWriter(sw));

        try (final var su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(req)).thenReturn(null);
            controller.doHandle(req, resp);
        }

        verify(resp).setStatus(HttpServletResponse.SC_FORBIDDEN);
        final var body = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(sw.toString());
        assertThat((Boolean) body.get("ok")).isFalse();
        assertThat(body.getAsString("message")).isEqualTo("Access denied");
    }

    @Test
    void nonPostReturns405() throws Exception {
        final var req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("GET");
        final var resp = mock(HttpServletResponse.class);

        controller.doHandle(req, resp);

        verify(resp).setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        verify(csrfFilter, never()).validateRequest(any(), any());
    }

    @Test
    void postWithFailedCsrfCheckReturnsWithoutProcessing() throws Exception {
        final var req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("POST");
        final var resp = mock(HttpServletResponse.class);
        when(csrfFilter.validateRequest(req, resp)).thenReturn(false);

        controller.doHandle(req, resp);

        // CSRFFilter owns the response; our code must not write anything
        verify(resp, never()).setStatus(anyInt());
        verify(resp, never()).setContentType(anyString());
        verify(resp, never()).getWriter();
    }

    // ---- step=jwt ----

    private void mockBuildType(final String externalId) {
        final var buildType = mock(SBuildType.class);
        when(buildType.getExternalId()).thenReturn(externalId);
        when(buildServer.getProjectManager()).thenReturn(projectManager);
        when(projectManager.findBuildTypeByExternalId(externalId)).thenReturn(buildType);
    }

    @Test
    void jwtStepRS256ReturnsSignedToken() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
        mockBuildType("MyBuildType");
        final var result = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "10",
            "audience", "https://tc.example.com", "buildTypeId", "buildType:MyBuildType"
        ));

        assertThat((Boolean) result.get("ok")).isTrue();
        assertThat(result.getAsString("token")).isNotBlank();
        final var jwt = SignedJWT.parse(result.getAsString("token"));
        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
    }

    @Test
    void jwtStepES256ReturnsSignedToken() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
        mockBuildType("MyBuildType");
        final var result = callStep(Map.of(
            "step", "jwt", "algorithm", "ES256", "ttl_minutes", "10",
            "audience", "https://tc.example.com", "buildTypeId", "buildType:MyBuildType"
        ));

        assertThat((Boolean) result.get("ok")).isTrue();
        final var jwt = SignedJWT.parse(result.getAsString("token"));
        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
    }

    @Test
    void jwtStepUsesBuildTypeExternalIdAsSubject() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
        mockBuildType("MyProject_MyBuild");
        final var result = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "10",
            "audience", "aud", "buildTypeId", "buildType:MyProject_MyBuild"
        ));

        assertThat((Boolean) result.get("ok")).isTrue();
        final var jwt = SignedJWT.parse(result.getAsString("token"));
        assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("MyProject_MyBuild");
        assertThat(result.getAsString("message")).contains("sub: MyProject_MyBuild");
    }

    @Test
    void jwtStepAcceptsBuildTypeIdWithoutPrefix() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
        mockBuildType("MyBuildType");
        final var result = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "10",
            "audience", "aud", "buildTypeId", "MyBuildType"
        ));

        assertThat((Boolean) result.get("ok")).isTrue();
        final var jwt = SignedJWT.parse(result.getAsString("token"));
        assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("MyBuildType");
    }

    @Test
    void jwtStepFailsWhenBuildTypeIdMissing() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
        final var result = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "10", "audience", "aud"
        ));

        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("buildTypeId");
    }

    @Test
    void jwtStepFailsWhenBuildTypeIdIsBlank() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
        final var result = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "10",
            "audience", "aud", "buildTypeId", ""
        ));

        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("buildTypeId");
    }

    @Test
    void jwtStepFailsWhenBuildTypeNotFound() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
        when(buildServer.getProjectManager()).thenReturn(projectManager);
        when(projectManager.findBuildTypeByExternalId("Unknown")).thenReturn(null);
        final var result = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "10",
            "audience", "aud", "buildTypeId", "Unknown"
        ));

        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("Build type not found");
    }

    @Test
    void jwtStepClampsTtlToOneDayMaximum() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
        mockBuildType("MyBuildType");
        final var result = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "999999",
            "audience", "aud", "buildTypeId", "buildType:MyBuildType"
        ));

        assertThat((Boolean) result.get("ok")).isTrue();
        final var jwt = SignedJWT.parse(result.getAsString("token"));
        final var ttlSeconds = (jwt.getJWTClaimsSet().getExpirationTime().getTime()
                - jwt.getJWTClaimsSet().getIssueTime().getTime()) / 1000;
        assertThat(ttlSeconds).isEqualTo(1440 * 60); // clamped to 24 hours
    }

    @Test
    void jwtStepFailsWhenRootUrlIsNotHttps() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("http://teamcity.example.com");
        final var result = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "10", "audience", "aud"
        ));

        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("not HTTPS");
    }

    // ---- step=discovery ----

    @Test
    void discoveryStepSucceedsWhenIssuerMatches() throws Exception {
        // HttpServer.create() binds immediately — port is known before start()
        final var server =
            com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(0), 0);
        final var port = server.getAddress().getPort();
        final var issuer = "http://localhost:" + port;
        addContext(server, "/.well-known/openid-configuration",
            200, "{\"issuer\":\"" + issuer + "\"}");
        server.start();
        when(buildServer.getRootUrl()).thenReturn(issuer);

        try {
            final var result = callStep(Map.of("step", "discovery"));
            assertThat((Boolean) result.get("ok")).isTrue();
            assertThat(result.getAsString("message")).contains("Discovery endpoint OK");
        } finally {
            server.stop(0);
        }
    }

    @Test
    void discoveryStepFailsWhenIssuerMismatches() throws Exception {
        // HttpServer.create() binds immediately — port is known before start()
        final var server =
            com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(0), 0);
        addContext(server, "/.well-known/openid-configuration",
            200, "{\"issuer\":\"https://wrong.example.com\"}");
        server.start();
        final var port = server.getAddress().getPort();
        when(buildServer.getRootUrl()).thenReturn("http://localhost:" + port);

        try {
            final var result = callStep(Map.of("step", "discovery"));
            assertThat((Boolean) result.get("ok")).isFalse();
            assertThat(result.getAsString("message")).contains("issuer mismatch");
        } finally {
            server.stop(0);
        }
    }

    @Test
    void discoveryStepFailsWhenServerUnreachable() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("http://localhost:1"); // nothing listening on port 1
        final var result = callStep(Map.of("step", "discovery"));
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("Could not reach");
    }

    // ---- step=jwks ----

    @Test
    void jwksStepVerifiesValidRs256Token() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
        mockBuildType("MyBuildType");
        // Issue a real RS256 token
        final var jwtResult = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "5",
            "audience", "aud", "buildTypeId", "buildType:MyBuildType"
        ));
        final var token = jwtResult.getAsString("token");

        // Serve our JWKS on a local HTTP server
        final var jwksJson = new com.nimbusds.jose.jwk.JWKSet(keyManager.getPublicKeys()).toString();
        final var server =
            com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(0), 0);
        addContext(server, "/.well-known/jwks.json", 200, jwksJson);
        server.start();
        final var port = server.getAddress().getPort();
        when(buildServer.getRootUrl()).thenReturn("http://localhost:" + port);

        try {
            final var result = callStep(Map.of("step", "jwks", "token", token));
            assertThat((Boolean) result.get("ok")).isTrue();
            assertThat(result.getAsString("message")).contains("JWKS OK");
        } finally {
            server.stop(0);
        }
    }

    @Test
    void jwksStepVerifiesValidEs256Token() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
        mockBuildType("MyBuildType");
        final var jwtResult = callStep(Map.of(
            "step", "jwt", "algorithm", "ES256", "ttl_minutes", "5",
            "audience", "aud", "buildTypeId", "buildType:MyBuildType"
        ));
        final var token = jwtResult.getAsString("token");

        final var jwksJson = new com.nimbusds.jose.jwk.JWKSet(keyManager.getPublicKeys()).toString();
        final var server =
            com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(0), 0);
        addContext(server, "/.well-known/jwks.json", 200, jwksJson);
        server.start();
        final var port = server.getAddress().getPort();
        when(buildServer.getRootUrl()).thenReturn("http://localhost:" + port);

        try {
            final var result = callStep(Map.of("step", "jwks", "token", token));
            assertThat((Boolean) result.get("ok")).isTrue();
        } finally {
            server.stop(0);
        }
    }

    @Test
    void jwksStepFailsWhenKidNotInJwks() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
        mockBuildType("MyBuildType");
        final var jwtResult = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "5",
            "audience", "aud", "buildTypeId", "buildType:MyBuildType"
        ));
        final var token = jwtResult.getAsString("token");

        // Serve an empty JWKS
        final var server =
            com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(0), 0);
        addContext(server, "/.well-known/jwks.json", 200, "{\"keys\":[]}");
        server.start();
        final var port = server.getAddress().getPort();
        when(buildServer.getRootUrl()).thenReturn("http://localhost:" + port);

        try {
            final var result = callStep(Map.of("step", "jwks", "token", token));
            assertThat((Boolean) result.get("ok")).isFalse();
            assertThat(result.getAsString("message")).contains("Key ID not found");
        } finally {
            server.stop(0);
        }
    }

    // ---- step=exchange ----

    @Test
    void exchangeStepSucceedsWhenTokenEndpointReturns200() throws Exception {
        // Issue a JWT first (HTTPS rootUrl required for step=jwt)
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
        mockBuildType("MyBuildType");
        final var jwtResult = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "5",
            "audience", "my-ext-id", "buildTypeId", "buildType:MyBuildType"
        ));
        final var token = jwtResult.getAsString("token");

        // Stand up a mock service that serves discovery + token endpoint
        final var server =
            com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(0), 0);
        final var port = server.getAddress().getPort();
        final var serviceUrl = "http://localhost:" + port;
        final var tokenEndpoint = serviceUrl + "/token";

        addContext(server, "/.well-known/openid-configuration", 200,
            "{\"issuer\":\"" + serviceUrl + "\",\"token_endpoint\":\"" + tokenEndpoint + "\"}");
        addContext(server, "/token", 200,
            "{\"access_token\":\"fake-token\",\"token_type\":\"Bearer\"}");
        server.start();

        try {
            final var result = callStep(Map.of(
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
        mockBuildType("MyBuildType");
        final var jwtResult = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "5",
            "audience", "aud", "buildTypeId", "buildType:MyBuildType"
        ));
        final var token = jwtResult.getAsString("token");

        final var server =
            com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(0), 0);
        server.start();
        final var port = server.getAddress().getPort();
        final var serviceUrl = "http://localhost:" + port;
        addContext(server, "/.well-known/openid-configuration", 200,
            "{\"token_endpoint\":\"" + serviceUrl + "/token\"}");
        addContext(server, "/token", 401, "{\"error\":\"invalid_token\"}");

        try {
            final var result = callStep(Map.of(
                "step", "exchange", "token", token, "serviceUrl", serviceUrl, "audience", "aud"
            ));
            assertThat((Boolean) result.get("ok")).isFalse();
            assertThat(result.getAsString("message")).contains("Exchange failed (HTTP 401)");
        } finally {
            server.stop(0);
        }
    }

    @Test
    void exchangeStepRewritesTokenEndpointHostnameToMatchServiceUrl() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
        mockBuildType("MyBuildType");
        final var jwtResult = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "5",
            "audience", "aud", "buildTypeId", "buildType:MyBuildType"
        ));
        final var token = jwtResult.getAsString("token");

        // Service runs on localhost but its discovery doc returns an internal hostname
        // in token_endpoint — controller must rewrite it to the serviceUrl origin.
        final var server =
            com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(0), 0);
        final var port = server.getAddress().getPort();
        final var serviceUrl = "http://localhost:" + port;
        // token_endpoint advertises an unreachable internal hostname
        addContext(server, "/.well-known/openid-configuration", 200,
            "{\"issuer\":\"http://internal-host\",\"token_endpoint\":\"http://internal-host/token\"}");
        addContext(server, "/token", 200,
            "{\"access_token\":\"ok\",\"token_type\":\"Bearer\"}");
        server.start();

        try {
            final var result = callStep(Map.of(
                "step", "exchange", "token", token, "serviceUrl", serviceUrl, "audience", "aud"
            ));
            assertThat((Boolean) result.get("ok")).isTrue();
            assertThat(result.getAsString("message")).contains("Exchange succeeded (HTTP 200)");
        } finally {
            server.stop(0);
        }
    }

    @Test
    void exchangeStepFailsWhenDiscoveryDocMissingTokenEndpoint() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
        mockBuildType("MyBuildType");
        final var jwtResult = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "5",
            "audience", "aud", "buildTypeId", "buildType:MyBuildType"
        ));
        final var token = jwtResult.getAsString("token");

        final var server =
            com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(0), 0);
        addContext(server, "/.well-known/openid-configuration", 200, "{\"issuer\":\"http://svc\"}");
        server.start();
        final var port = server.getAddress().getPort();

        try {
            final var result = callStep(Map.of(
                "step", "exchange", "token", token,
                "serviceUrl", "http://localhost:" + port, "audience", "aud"
            ));
            assertThat((Boolean) result.get("ok")).isFalse();
            assertThat(result.getAsString("message")).contains("token_endpoint not found");
        } finally {
            server.stop(0);
        }
    }

    // ---- step parameter validation ----

    @Test
    void missingStepReturnsError() throws Exception {
        final var result = callStep(Map.of());
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("step");
    }

    @Test
    void unknownStepReturnsError() throws Exception {
        final var result = callStep(Map.of("step", "bogus"));
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("bogus");
    }

    // ---- step=jwt defaults ----

    @Test
    void jwtStepDefaultsAlgorithmToRS256() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
        mockBuildType("MyBuildType");
        final var result = callStep(Map.of(
            "step", "jwt", "audience", "aud", "buildTypeId", "buildType:MyBuildType"
            // no algorithm param
        ));

        assertThat((Boolean) result.get("ok")).isTrue();
        final var jwt = SignedJWT.parse(result.getAsString("token"));
        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
    }

    @Test
    void jwtStepIncludesNbfEqualToIat() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
        mockBuildType("MyBuildType");
        final var result = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "10",
            "audience", "aud", "buildTypeId", "buildType:MyBuildType"
        ));

        assertThat((Boolean) result.get("ok")).isTrue();
        final var jwt = SignedJWT.parse(result.getAsString("token"));
        assertThat(jwt.getJWTClaimsSet().getNotBeforeTime()).isNotNull();
        assertThat(jwt.getJWTClaimsSet().getNotBeforeTime())
                .isEqualTo(jwt.getJWTClaimsSet().getIssueTime());
    }

    @Test
    void jwtStepDefaultsAudienceToRootUrl() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
        mockBuildType("MyBuildType");
        final var result = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "buildTypeId", "buildType:MyBuildType"
            // no audience param
        ));

        assertThat((Boolean) result.get("ok")).isTrue();
        final var jwt = SignedJWT.parse(result.getAsString("token"));
        assertThat(jwt.getJWTClaimsSet().getAudience()).containsExactly("https://tc.example.com");
    }

    // ---- step=jwks validation ----

    @Test
    void jwksStepFailsWhenTokenParamMissing() throws Exception {
        final var result = callStep(Map.of("step", "jwks"));
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("token");
    }

    @Test
    void jwksStepFailsWhenJwksEndpointReturnsNon200() throws Exception {
        final var server =
            com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(0), 0);
        addContext(server, "/.well-known/jwks.json", 500, "{}");
        server.start();
        final var port = server.getAddress().getPort();
        when(buildServer.getRootUrl()).thenReturn("http://localhost:" + port);

        try {
            final var result = callStep(Map.of("step", "jwks", "token", "dummy.token.here"));
            assertThat((Boolean) result.get("ok")).isFalse();
            assertThat(result.getAsString("message")).contains("JWKS endpoint returned HTTP 500");
        } finally {
            server.stop(0);
        }
    }

    // ---- step=exchange validation ----

    @Test
    void exchangeStepFailsWhenTokenParamMissing() throws Exception {
        final var result = callStep(Map.of("step", "exchange", "serviceUrl", "http://svc.example.com"));
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("token");
    }

    @Test
    void exchangeStepStripsTrailingSlashesFromServiceUrl() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
        mockBuildType("MyBuildType");
        final var jwtResult = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "5",
            "audience", "aud", "buildTypeId", "buildType:MyBuildType"
        ));
        final var token = jwtResult.getAsString("token");

        final var server =
            com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(0), 0);
        final var port = server.getAddress().getPort();
        final var serviceUrl = "http://localhost:" + port;
        addContext(server, "/.well-known/openid-configuration", 200,
            "{\"token_endpoint\":\"" + serviceUrl + "/token\"}");
        addContext(server, "/token", 200,
            "{\"access_token\":\"ok\",\"token_type\":\"Bearer\"}");
        server.start();

        try {
            final var result = callStep(Map.of(
                "step", "exchange", "token", token,
                "serviceUrl", serviceUrl + "///", // trailing slashes
                "audience", "aud"
            ));
            assertThat((Boolean) result.get("ok")).isTrue();
        } finally {
            server.stop(0);
        }
    }

    @Test
    void exchangeStepFailsWhenServiceUrlParamMissing() throws Exception {
        final var result = callStep(Map.of("step", "exchange", "token", "some.jwt.token"));
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("serviceUrl");
    }

    @Test
    void exchangeStepFailsWhenServiceUrlIsHttp() throws Exception {
        final var result = callStep(Map.of(
            "step", "exchange",
            "token", "some.jwt.token",
            "serviceUrl", "http://external.example.com",
            "audience", "aud"
        ));
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("HTTPS");
    }

    @Test
    void exchangeStepFailsWhenServiceDiscoveryReturnsNon200() throws Exception {
        final var server =
            com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(0), 0);
        addContext(server, "/.well-known/openid-configuration", 404, "not found");
        server.start();
        final var port = server.getAddress().getPort();

        try {
            final var result = callStep(Map.of(
                "step", "exchange", "token", "some.jwt.token",
                "serviceUrl", "http://localhost:" + port, "audience", "aud"
            ));
            assertThat((Boolean) result.get("ok")).isFalse();
            assertThat(result.getAsString("message")).contains("Service discovery returned HTTP 404");
        } finally {
            server.stop(0);
        }
    }

    // ---- helpers ----

    private static void addContext(final com.sun.net.httpserver.HttpServer server,
                                   final String path, final int status, final String body) {
        server.createContext(path, exchange -> {
            final var bytes = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
    }

    JSONObject callStep(final Map<String, String> params) throws Exception {
        final var req = mockPost(params);
        final var resp = mock(HttpServletResponse.class);
        final var sw = new StringWriter();
        when(resp.getWriter()).thenReturn(new PrintWriter(sw));

        final var admin = mock(SUser.class);
        when(admin.isPermissionGrantedGlobally(Permission.MANAGE_SERVER_INSTALLATION)).thenReturn(true);

        try (final var su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(req)).thenReturn(admin);
            controller.doHandle(req, resp);
        }

        return (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(sw.toString());
    }

    HttpServletRequest mockPost(final Map<String, String> params) {
        final var req = mock(HttpServletRequest.class);
        lenient().when(req.getMethod()).thenReturn("POST");
        params.forEach((k, v) -> lenient().when(req.getParameter(k)).thenReturn(v));
        return req;
    }
}
