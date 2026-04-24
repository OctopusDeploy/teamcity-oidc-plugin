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
import javax.servlet.http.HttpSession;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;

import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class JwtTestControllerTest {

    @Mock WebControllerManager controllerManager;
    @Mock SBuildServer buildServer;
    @Mock ProjectManager projectManager;
    @Mock ServerPaths serverPaths;
    @Mock CSRFFilter csrfFilter;
    @Mock HttpClient httpClient;

    @TempDir File tempDir;

    JwtKeyManager keyManager;
    JwtTestController controller;

    // Stub resolver: returns a known public IP for any hostname so tests don't require real DNS.
    // SSRF tests that need real address-family checks pass IP-literal URLs instead.
    private static final JwtTestController.AddressResolver PUBLIC_RESOLVER =
            host -> new InetAddress[]{InetAddress.getByAddress(new byte[]{93, -72, -40, 34})};

    @BeforeEach
    void setup() {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        keyManager = TestJwtKeyManagerFactory.create(serverPaths);
        // Default: CSRF check passes. lenient() because some tests use GET (CSRF never reached).
        lenient().when(csrfFilter.validateRequest(any(), any())).thenReturn(true);
        // Default: HTTPS root URL. lenient() because not all tests exercise this path.
        lenient().when(buildServer.getRootUrl()).thenReturn("https://tc.example.com");
        controller = new JwtTestController(controllerManager, keyManager, buildServer, httpClient, csrfFilter, PUBLIC_RESOLVER);
    }

    // ---- lifecycle ----

    @Test
    void destroyClosesHttpClient() throws Exception {
        controller.destroy();
        verify(httpClient).close();
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
        when(buildType.getProjectId()).thenReturn("project1");
        when(buildServer.getProjectManager()).thenReturn(projectManager);
        when(projectManager.findBuildTypeByExternalId(externalId)).thenReturn(buildType);
    }

    @Test
    void jwtStepRS256ReturnsSignedToken() throws Exception {
        mockBuildType("MyBuildType");
        final var session = createMockSession();
        final var result = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "10",
            "audience", "https://tc.example.com", "buildTypeId", "buildType:MyBuildType"
        ), session);

        assertThat((Boolean) result.get("ok")).isTrue();
        assertThat(result.getAsString("tokenRef")).isNotBlank();
        final var jwt = parseSessionToken(session, result.getAsString("tokenRef"));
        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
    }

    @Test
    void jwtStepES256ReturnsSignedToken() throws Exception {
        mockBuildType("MyBuildType");
        final var session = createMockSession();
        final var result = callStep(Map.of(
            "step", "jwt", "algorithm", "ES256", "ttl_minutes", "10",
            "audience", "https://tc.example.com", "buildTypeId", "buildType:MyBuildType"
        ), session);

        assertThat((Boolean) result.get("ok")).isTrue();
        final var jwt = parseSessionToken(session, result.getAsString("tokenRef"));
        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
    }

    @Test
    void jwtStepUsesBuildTypeExternalIdAsSubject() throws Exception {
        mockBuildType("MyProject_MyBuild");
        final var session = createMockSession();
        final var result = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "10",
            "audience", "aud", "buildTypeId", "buildType:MyProject_MyBuild"
        ), session);

        assertThat((Boolean) result.get("ok")).isTrue();
        final var jwt = parseSessionToken(session, result.getAsString("tokenRef"));
        assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("MyProject_MyBuild");
        assertThat(result.getAsString("message")).contains("sub: MyProject_MyBuild");
    }

    @Test
    void jwtStepAcceptsBuildTypeIdWithoutPrefix() throws Exception {
        mockBuildType("MyBuildType");
        final var session = createMockSession();
        final var result = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "10",
            "audience", "aud", "buildTypeId", "MyBuildType"
        ), session);

        assertThat((Boolean) result.get("ok")).isTrue();
        final var jwt = parseSessionToken(session, result.getAsString("tokenRef"));
        assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("MyBuildType");
    }

    @Test
    void jwtStepFailsWhenBuildTypeIdMissing() throws Exception {
        final var result = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "10", "audience", "aud"
        ));

        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("buildTypeId");
    }

    @Test
    void jwtStepFailsWhenBuildTypeIdIsBlank() throws Exception {
        final var result = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "10",
            "audience", "aud", "buildTypeId", ""
        ));

        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("buildTypeId");
    }

    @Test
    void jwtStepFailsWhenBuildTypeNotFound() throws Exception {
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
    void jwtStepFailsWhenUserLacksProjectPermission() throws Exception {
        // Only stub what is actually reached before the permission check throws.
        final var buildType = mock(SBuildType.class);
        when(buildType.getProjectId()).thenReturn("project1");
        when(buildServer.getProjectManager()).thenReturn(projectManager);
        when(projectManager.findBuildTypeByExternalId("MyBuildType")).thenReturn(buildType);

        final var result = callStep(
            Map.of("step", "jwt", "algorithm", "RS256", "audience", "aud", "buildTypeId", "buildType:MyBuildType"),
            /* editProject= */ false
        );

        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("Access denied");
    }

    @Test
    void jwtStepAlwaysUses1MinuteTtlRegardlessOfInput() throws Exception {
        mockBuildType("MyBuildType");
        final var session = createMockSession();
        final var result = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "999999",
            "audience", "aud", "buildTypeId", "buildType:MyBuildType"
        ), session);

        assertThat((Boolean) result.get("ok")).isTrue();
        final var jwt = parseSessionToken(session, result.getAsString("tokenRef"));
        final var ttlSeconds = (jwt.getJWTClaimsSet().getExpirationTime().getTime()
                - jwt.getJWTClaimsSet().getIssueTime().getTime()) / 1000;
        assertThat(ttlSeconds).isEqualTo(60); // always 1 minute for test tokens
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
    void discoveryStepFailsWhenRootUrlIsNotHttps() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("http://teamcity.example.com");
        final var result = callStep(Map.of("step", "discovery"));
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("not HTTPS");
    }

    @Test
    void discoveryStepSucceedsWhenIssuerMatches() throws Exception {
        doReturn(mockResponse(200, "{\"issuer\":\"https://tc.example.com\"}"))
            .when(httpClient).send(any(), any());

        final var result = callStep(Map.of("step", "discovery"));
        assertThat((Boolean) result.get("ok")).isTrue();
        assertThat(result.getAsString("message")).contains("Discovery endpoint OK");
    }

    @Test
    void discoveryStepFailsWhenIssuerMismatches() throws Exception {
        doReturn(mockResponse(200, "{\"issuer\":\"https://wrong.example.com\"}"))
            .when(httpClient).send(any(), any());

        final var result = callStep(Map.of("step", "discovery"));
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("issuer mismatch");
    }

    @Test
    void discoveryStepFailsWhenServerUnreachable() throws Exception {
        doThrow(new IOException("Connection refused")).when(httpClient).send(any(), any());

        final var result = callStep(Map.of("step", "discovery"));
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("Could not reach");
    }

    @Test
    void discoveryUrlStripsQueryStringFromRootUrl() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com?v=1");
        doReturn(mockResponse(200, "{}")).when(httpClient).send(any(), any());

        callStep(Map.of("step", "discovery"));

        final var captor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(httpClient).send(captor.capture(), any());
        assertThat(captor.getValue().uri().toString())
                .isEqualTo("https://tc.example.com/.well-known/openid-configuration");
    }

    @Test
    void jwksUrlStripsQueryStringFromRootUrl() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com?v=1");
        final var session = createMockSession();
        final var tokenRef = issueTokenRef(session);
        // Empty JWKS: parse succeeds, key lookup fails after send() — we only care the URL was right.
        doReturn(mockResponse(200, "{\"keys\":[]}")).when(httpClient).send(any(), any());

        callStep(Map.of("step", "jwks", "tokenRef", tokenRef), session);

        final var captor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(httpClient).send(captor.capture(), any());
        assertThat(captor.getValue().uri().toString())
                .isEqualTo("https://tc.example.com/.well-known/jwks.json");
    }

    // ---- step=jwks ----

    @Test
    void jwksStepFailsWhenRootUrlIsNotHttps() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("http://teamcity.example.com");
        final var result = callStep(Map.of("step", "jwks"));
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("not HTTPS");
    }

    @Test
    void jwksStepVerifiesValidRs256Token() throws Exception {
        final var session = createMockSession();
        mockBuildType("MyBuildType");
        final var jwtResult = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "5",
            "audience", "aud", "buildTypeId", "buildType:MyBuildType"
        ), session);
        final var tokenRef = jwtResult.getAsString("tokenRef");
        final var jwksJson = new com.nimbusds.jose.jwk.JWKSet(keyManager.getPublicKeys()).toString();

        doReturn(mockResponse(200, jwksJson)).when(httpClient).send(any(), any());
        final var result = callStep(Map.of("step", "jwks", "tokenRef", tokenRef), session);
        assertThat((Boolean) result.get("ok")).isTrue();
        assertThat(result.getAsString("message")).contains("JWKS OK");
    }

    @Test
    void jwksStepVerifiesValidEs256Token() throws Exception {
        final var session = createMockSession();
        mockBuildType("MyBuildType");
        final var jwtResult = callStep(Map.of(
            "step", "jwt", "algorithm", "ES256", "ttl_minutes", "5",
            "audience", "aud", "buildTypeId", "buildType:MyBuildType"
        ), session);
        final var tokenRef = jwtResult.getAsString("tokenRef");
        final var jwksJson = new com.nimbusds.jose.jwk.JWKSet(keyManager.getPublicKeys()).toString();

        doReturn(mockResponse(200, jwksJson)).when(httpClient).send(any(), any());
        final var result = callStep(Map.of("step", "jwks", "tokenRef", tokenRef), session);
        assertThat((Boolean) result.get("ok")).isTrue();
    }

    @Test
    void jwksStepFailsWhenKidNotInJwks() throws Exception {
        final var session = createMockSession();
        mockBuildType("MyBuildType");
        final var jwtResult = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "5",
            "audience", "aud", "buildTypeId", "buildType:MyBuildType"
        ), session);
        final var tokenRef = jwtResult.getAsString("tokenRef");

        doReturn(mockResponse(200, "{\"keys\":[]}")).when(httpClient).send(any(), any());
        final var result = callStep(Map.of("step", "jwks", "tokenRef", tokenRef), session);
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("Key ID not found");
    }

    // ---- step=exchange ----

    @Test
    void exchangeStepSucceedsWhenTokenEndpointReturns200() throws Exception {
        final var session = createMockSession();
        final var tokenRef = issueTokenRef(session);
        final var discovery = mockResponse(200, "{\"token_endpoint\":\"https://svc.example.com/token\"}");
        final var exchange = mockResponse(200, "{\"access_token\":\"fake-token\",\"token_type\":\"Bearer\"}");
        doReturn(discovery).doReturn(exchange).when(httpClient).send(any(), any());

        final var result = callStep(Map.of(
            "step", "exchange", "tokenRef", tokenRef,
            "serviceUrl", "https://svc.example.com", "audience", "my-ext-id"
        ), session);
        assertThat((Boolean) result.get("ok")).isTrue();
        assertThat(result.getAsString("message")).contains("Exchange succeeded (HTTP 200)");
    }

    @Test
    void exchangeStepFailsWhenTokenEndpointReturns401() throws Exception {
        final var session = createMockSession();
        final var tokenRef = issueTokenRef(session);
        final var discovery = mockResponse(200, "{\"token_endpoint\":\"https://svc.example.com/token\"}");
        final var tokenResp = mockResponse(401, "{\"error\":\"invalid_token\"}");
        doReturn(discovery).doReturn(tokenResp).when(httpClient).send(any(), any());

        final var result = callStep(Map.of(
            "step", "exchange", "tokenRef", tokenRef,
            "serviceUrl", "https://svc.example.com", "audience", "aud"
        ), session);
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("Exchange failed (HTTP 401)");
    }

    @Test
    void exchangeStepRewritesTokenEndpointHostnameToMatchServiceUrl() throws Exception {
        final var session = createMockSession();
        final var tokenRef = issueTokenRef(session);
        // discovery doc advertises an internal hostname in token_endpoint
        final var discovery = mockResponse(200,
            "{\"issuer\":\"http://internal-host\",\"token_endpoint\":\"http://internal-host/token\"}");
        final var exchange = mockResponse(200, "{\"access_token\":\"ok\",\"token_type\":\"Bearer\"}");
        doReturn(discovery).doReturn(exchange).when(httpClient).send(any(), any());

        final var result = callStep(Map.of(
            "step", "exchange", "tokenRef", tokenRef,
            "serviceUrl", "https://svc.example.com", "audience", "aud"
        ), session);
        assertThat((Boolean) result.get("ok")).isTrue();
        assertThat(result.getAsString("message")).contains("Exchange succeeded (HTTP 200)");
    }

    @Test
    void exchangeStepFailsWhenDiscoveryDocMissingTokenEndpoint() throws Exception {
        final var session = createMockSession();
        final var tokenRef = issueTokenRef(session);
        doReturn(mockResponse(200, "{\"issuer\":\"http://svc\"}")).when(httpClient).send(any(), any());

        final var result = callStep(Map.of(
            "step", "exchange", "tokenRef", tokenRef,
            "serviceUrl", "https://svc.example.com", "audience", "aud"
        ), session);
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("token_endpoint not found");
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
        mockBuildType("MyBuildType");
        final var session = createMockSession();
        final var result = callStep(Map.of(
            "step", "jwt", "audience", "aud", "buildTypeId", "buildType:MyBuildType"
            // no algorithm param
        ), session);

        assertThat((Boolean) result.get("ok")).isTrue();
        final var jwt = parseSessionToken(session, result.getAsString("tokenRef"));
        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
    }

    @Test
    void jwtStepIncludesNbfEqualToIat() throws Exception {
        mockBuildType("MyBuildType");
        final var session = createMockSession();
        final var result = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "10",
            "audience", "aud", "buildTypeId", "buildType:MyBuildType"
        ), session);

        assertThat((Boolean) result.get("ok")).isTrue();
        final var jwt = parseSessionToken(session, result.getAsString("tokenRef"));
        assertThat(jwt.getJWTClaimsSet().getNotBeforeTime()).isNotNull();
        assertThat(jwt.getJWTClaimsSet().getNotBeforeTime())
                .isEqualTo(jwt.getJWTClaimsSet().getIssueTime());
    }

    @Test
    void jwtStepNormalizesIssuerWhenRootUrlHasTrailingSlash() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com/");
        mockBuildType("MyBuildType");
        final var session = createMockSession();
        final var result = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256",
            "audience", "aud", "buildTypeId", "buildType:MyBuildType"
        ), session);

        assertThat((Boolean) result.get("ok")).isTrue();
        final var jwt = parseSessionToken(session, result.getAsString("tokenRef"));
        assertThat(jwt.getJWTClaimsSet().getIssuer()).isEqualTo("https://tc.example.com");
    }

    @Test
    void discoveryStepSucceedsWhenRootUrlHasTrailingSlashButIssuerIsNormalized() throws Exception {
        when(buildServer.getRootUrl()).thenReturn("https://tc.example.com/");
        doReturn(mockResponse(200, "{\"issuer\":\"https://tc.example.com\"}"))
            .when(httpClient).send(any(), any());

        final var result = callStep(Map.of("step", "discovery"));
        assertThat((Boolean) result.get("ok")).isTrue();
        assertThat(result.getAsString("message")).contains("Discovery endpoint OK");
    }

    @Test
    void jwtStepDefaultsAudienceToRootUrl() throws Exception {
        mockBuildType("MyBuildType");
        final var session = createMockSession();
        final var result = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "buildTypeId", "buildType:MyBuildType"
            // no audience param
        ), session);

        assertThat((Boolean) result.get("ok")).isTrue();
        final var jwt = parseSessionToken(session, result.getAsString("tokenRef"));
        assertThat(jwt.getJWTClaimsSet().getAudience()).containsExactly("https://tc.example.com");
    }

    // ---- step=jwks validation ----

    @Test
    void jwksStepFailsWhenJwksEndpointReturnsNon200() throws Exception {
        final var session = createMockSession();
        final var tokenRef = issueTokenRef(session);
        doReturn(mockResponse(500, "{}")).when(httpClient).send(any(), any());

        final var result = callStep(Map.of("step", "jwks", "tokenRef", tokenRef), session);
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("JWKS endpoint returned HTTP 500");
    }

    // ---- step=exchange validation ----

    @Test
    void exchangeStepStripsTrailingSlashesFromServiceUrl() throws Exception {
        final var session = createMockSession();
        final var tokenRef = issueTokenRef(session);
        final var discovery = mockResponse(200, "{\"token_endpoint\":\"https://svc.example.com/token\"}");
        final var exchange = mockResponse(200, "{\"access_token\":\"ok\",\"token_type\":\"Bearer\"}");
        doReturn(discovery).doReturn(exchange).when(httpClient).send(any(), any());

        final var result = callStep(Map.of(
            "step", "exchange", "tokenRef", tokenRef,
            "serviceUrl", "https://svc.example.com///", // trailing slashes
            "audience", "aud"
        ), session);
        assertThat((Boolean) result.get("ok")).isTrue();
    }

    @Test
    void exchangeStepFailsWhenServiceUrlParamMissing() throws Exception {
        // serviceUrl check happens before session lookup
        final var result = callStep(Map.of("step", "exchange"));
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("serviceUrl");
    }

    @Test
    void exchangeStepFailsWhenServiceUrlIsHttp() throws Exception {
        // HTTPS check happens before session lookup
        final var result = callStep(Map.of(
            "step", "exchange",
            "serviceUrl", "http://external.example.com",
            "audience", "aud"
        ));
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("HTTPS");
    }

    @Test
    void exchangeStepBlocksLoopbackAddress() throws Exception {
        // Private address check happens before session lookup
        controller = new JwtTestController(controllerManager, keyManager, buildServer, httpClient, csrfFilter);
        final var result = callStep(Map.of(
            "step", "exchange",
            "serviceUrl", "https://127.0.0.1", "audience", "aud"
        ));
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("private");
    }

    @Test
    void exchangeStepBlocksRfc1918Address() throws Exception {
        controller = new JwtTestController(controllerManager, keyManager, buildServer, httpClient, csrfFilter);
        final var result = callStep(Map.of(
            "step", "exchange",
            "serviceUrl", "https://192.168.1.100", "audience", "aud"
        ));
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("private");
    }

    @Test
    void exchangeStepBlocksLinkLocalAddress() throws Exception {
        controller = new JwtTestController(controllerManager, keyManager, buildServer, httpClient, csrfFilter);
        final var result = callStep(Map.of(
            "step", "exchange",
            "serviceUrl", "https://169.254.169.254", "audience", "aud"
        ));
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("private");
    }

    @Test
    void exchangeStepFailsWhenServiceDiscoveryReturnsNon200() throws Exception {
        final var session = createMockSession();
        final var tokenRef = issueTokenRef(session);
        doReturn(mockResponse(404, "not found")).when(httpClient).send(any(), any());

        final var result = callStep(Map.of(
            "step", "exchange", "tokenRef", tokenRef,
            "serviceUrl", "https://svc.example.com", "audience", "aud"
        ), session);
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("Service discovery returned HTTP 404");
    }

    // ---- session token tests ----

    @Test
    void jwtStepReturnsTokenRefNotRawToken() throws Exception {
        mockBuildType("MyBuildType");
        final var session = createMockSession();
        final var result = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256",
            "audience", "aud", "buildTypeId", "buildType:MyBuildType"
        ), session);

        assertThat((Boolean) result.get("ok")).isTrue();
        assertThat(result.get("token")).as("raw token must NOT be returned to browser").isNull();
        final var tokenRef = result.getAsString("tokenRef");
        assertThat(tokenRef).isNotBlank();
        assertThat(session.getAttribute(JwtTestController.SESSION_TOKEN_PREFIX + tokenRef))
                .as("token must be stored in session").isNotNull();
    }

    @Test
    void jwksStepUsesTokenFromSession() throws Exception {
        final var session = createMockSession();
        mockBuildType("MyBuildType");
        final var jwtResult = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256",
            "audience", "aud", "buildTypeId", "buildType:MyBuildType"
        ), session);
        final var tokenRef = jwtResult.getAsString("tokenRef");

        final var jwksJson = new com.nimbusds.jose.jwk.JWKSet(keyManager.getPublicKeys()).toString();
        doReturn(mockResponse(200, jwksJson)).when(httpClient).send(any(), any());

        final var result = callStep(Map.of("step", "jwks", "tokenRef", tokenRef), session);
        assertThat((Boolean) result.get("ok")).isTrue();
        assertThat(result.getAsString("message")).contains("JWKS OK");
    }

    @Test
    void jwksStepRemovesTokenFromSessionAfterVerification() throws Exception {
        final var session = createMockSession();
        mockBuildType("MyBuildType");
        final var jwtResult = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256",
            "audience", "aud", "buildTypeId", "buildType:MyBuildType"
        ), session);
        final var tokenRef = jwtResult.getAsString("tokenRef");
        final var jwksJson = new com.nimbusds.jose.jwk.JWKSet(keyManager.getPublicKeys()).toString();
        doReturn(mockResponse(200, jwksJson)).when(httpClient).send(any(), any());

        callStep(Map.of("step", "jwks", "tokenRef", tokenRef), session);

        assertThat(session.getAttribute(JwtTestController.SESSION_TOKEN_PREFIX + tokenRef))
                .as("token must be removed from session after use").isNull();
    }

    @Test
    void exchangeStepRemovesTokenFromSessionAfterUse() throws Exception {
        final var session = createMockSession();
        final var tokenRef = issueTokenRef(session);
        final var discovery = mockResponse(200, "{\"token_endpoint\":\"https://svc.example.com/token\"}");
        final var exchangeResp = mockResponse(200, "{\"access_token\":\"ok\"}");
        doReturn(discovery).doReturn(exchangeResp).when(httpClient).send(any(), any());

        callStep(Map.of("step", "exchange", "tokenRef", tokenRef,
            "serviceUrl", "https://svc.example.com", "audience", "aud"), session);

        assertThat(session.getAttribute(JwtTestController.SESSION_TOKEN_PREFIX + tokenRef))
                .as("token must be removed from session after use").isNull();
    }

    @Test
    void jwksStepFailsWhenNoSessionTokenForRef() throws Exception {
        final var result = callStep(Map.of("step", "jwks", "tokenRef", "nonexistent-guid"));
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("No active test token");
    }

    @Test
    void exchangeStepUsesTokenFromSession() throws Exception {
        final var session = createMockSession();
        final var tokenRef = issueTokenRef(session);

        final var discovery = mockResponse(200, "{\"token_endpoint\":\"https://svc.example.com/token\"}");
        final var exchange = mockResponse(200, "{\"access_token\":\"ok\",\"token_type\":\"Bearer\"}");
        doReturn(discovery).doReturn(exchange).when(httpClient).send(any(), any());

        final var result = callStep(Map.of(
            "step", "exchange", "tokenRef", tokenRef,
            "serviceUrl", "https://svc.example.com", "audience", "aud"
        ), session);
        assertThat((Boolean) result.get("ok")).isTrue();
    }

    @Test
    void exchangeStepFailsWhenNoSessionTokenForRef() throws Exception {
        final var result = callStep(Map.of(
            "step", "exchange", "tokenRef", "nonexistent-guid",
            "serviceUrl", "https://svc.example.com", "audience", "aud"
        ));
        assertThat((Boolean) result.get("ok")).isFalse();
        assertThat(result.getAsString("message")).contains("No active test token");
    }

    // ---- helpers ----

    @SuppressWarnings("unchecked")
    private static HttpResponse<String> mockResponse(final int status, final String body) {
        final HttpResponse<String> resp = mock(HttpResponse.class);
        // lenient: not every test exercises both statusCode() and body() on the same response
        lenient().when(resp.statusCode()).thenReturn(status);
        lenient().when(resp.body()).thenReturn(body);
        return resp;
    }

    JSONObject callStep(final Map<String, String> params) throws Exception {
        return callStep(params, true, createMockSession());
    }

    JSONObject callStep(final Map<String, String> params, final boolean editProject) throws Exception {
        return callStep(params, editProject, createMockSession());
    }

    JSONObject callStep(final Map<String, String> params, final HttpSession session) throws Exception {
        return callStep(params, true, session);
    }

    JSONObject callStep(final Map<String, String> params, final boolean editProject, final HttpSession session) throws Exception {
        final var req = mockPost(params, session);
        final var resp = mock(HttpServletResponse.class);
        final var sw = new StringWriter();
        when(resp.getWriter()).thenReturn(new PrintWriter(sw));

        final var admin = mock(SUser.class);
        when(admin.isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS)).thenReturn(true);
        lenient().when(admin.isPermissionGrantedForProject(any(), eq(Permission.EDIT_PROJECT))).thenReturn(editProject);

        try (final var su = mockStatic(SessionUser.class)) {
            su.when(() -> SessionUser.getUser(req)).thenReturn(admin);
            controller.doHandle(req, resp);
        }

        return (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(sw.toString());
    }

    HttpServletRequest mockPost(final Map<String, String> params) {
        return mockPost(params, createMockSession());
    }

    HttpServletRequest mockPost(final Map<String, String> params, final HttpSession session) {
        final var req = mock(HttpServletRequest.class);
        lenient().when(req.getMethod()).thenReturn("POST");
        params.forEach((k, v) -> lenient().when(req.getParameter(k)).thenReturn(v));
        lenient().when(req.getSession()).thenReturn(session);
        return req;
    }

    private HttpSession createMockSession() {
        final var store = new java.util.HashMap<String, Object>();
        final var session = mock(HttpSession.class);
        lenient().doAnswer(i -> store.get(i.getArgument(0, String.class))).when(session).getAttribute(anyString());
        lenient().doAnswer(i -> { store.put(i.getArgument(0, String.class), i.getArgument(1)); return null; })
                .when(session).setAttribute(anyString(), any());
        lenient().doAnswer(i -> { store.remove(i.getArgument(0, String.class)); return null; })
                .when(session).removeAttribute(anyString());
        return session;
    }

    private SignedJWT parseSessionToken(final HttpSession session, final String tokenRef) throws Exception {
        final var raw = (String) session.getAttribute(JwtTestController.SESSION_TOKEN_PREFIX + tokenRef);
        assertThat(raw).as("session token for ref " + tokenRef).isNotNull();
        return SignedJWT.parse(raw);
    }

    private String issueTokenRef(final HttpSession session) throws Exception {
        mockBuildType("MyBuildType");
        final var result = callStep(Map.of(
            "step", "jwt", "algorithm", "RS256", "ttl_minutes", "5",
            "audience", "aud", "buildTypeId", "buildType:MyBuildType"
        ), session);
        assertThat((Boolean) result.get("ok")).isTrue();
        return result.getAsString("tokenRef");
    }
}
