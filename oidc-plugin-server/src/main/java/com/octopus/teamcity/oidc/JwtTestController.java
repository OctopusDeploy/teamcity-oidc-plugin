package com.octopus.teamcity.oidc;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.controllers.BaseController;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.serverSide.SBuildType;
import jetbrains.buildServer.serverSide.auth.Permission;
import jetbrains.buildServer.users.SUser;
import jetbrains.buildServer.web.CSRFFilter;
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

    private final JwtKeyManager keyManager;
    private final SBuildServer buildServer;
    private final HttpClient httpClient;
    private final CSRFFilter csrfFilter;

    public JwtTestController(@NotNull WebControllerManager controllerManager,
                              @NotNull JwtKeyManager keyManager,
                              @NotNull SBuildServer buildServer,
                              @NotNull ExtensionHolder extensionHolder) {
        this(controllerManager, keyManager, buildServer,
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build(),
                new CSRFFilter(extensionHolder));
    }

    JwtTestController(@NotNull WebControllerManager controllerManager,
                      @NotNull JwtKeyManager keyManager,
                      @NotNull SBuildServer buildServer,
                      @NotNull HttpClient httpClient,
                      @NotNull CSRFFilter csrfFilter) {
        this.keyManager = keyManager;
        this.buildServer = buildServer;
        this.httpClient = httpClient;
        this.csrfFilter = csrfFilter;
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

        if (!csrfFilter.validateRequest(request, response)) {
            return null;
        }

        response.setContentType("application/json;charset=UTF-8");

        SUser user = SessionUser.getUser(request);
        if (user == null || !user.isPermissionGrantedGlobally(Permission.MANAGE_SERVER_INSTALLATION)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            writeJson(response, false, "Access denied");
            return null;
        }

        String step = request.getParameter("step");
        if (step == null || step.isBlank()) {
            writeJson(response, false, "Missing required parameter: step");
            return null;
        }
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
        if (!JwtKeyManager.isHttpsUrl(rootUrl)) {
            throw new TestStepException("Root URL is not HTTPS — OIDC endpoints won't be reachable");
        }
        String algorithm = request.getParameter("algorithm");
        if (algorithm == null || algorithm.isBlank()) algorithm = "RS256";
        int ttl = parseTtl(request.getParameter("ttl_minutes"));
        String audience = request.getParameter("audience");
        if (audience == null || audience.isBlank()) audience = rootUrl;

        String buildTypeId = request.getParameter("buildTypeId");
        if (buildTypeId == null || buildTypeId.isBlank()) {
            throw new TestStepException("Missing required parameter: buildTypeId");
        }
        // TC passes the id param as "buildType:<externalId>" — strip the prefix if present
        String externalId = buildTypeId.startsWith("buildType:")
                ? buildTypeId.substring("buildType:".length())
                : buildTypeId;
        SBuildType buildType = buildServer.getProjectManager().findBuildTypeByExternalId(externalId);
        if (buildType == null) {
            throw new TestStepException("Build type not found: " + buildTypeId);
        }
        String subject = buildType.getExternalId();

        Date now = new Date();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .subject(subject)
                .issuer(rootUrl)
                .audience(List.of(audience))
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + ttl * 60_000L))
                .build();

        SignedJWT jwt = keyManager.sign(claims, algorithm);
        String serialized = jwt.serialize();
        String message = "JWT issued (sub: " + subject + ", alg: " + algorithm + ", ttl: " + ttl + "m)";
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
        if (token == null || token.isBlank()) {
            throw new TestStepException("Missing required parameter: token");
        }
        String rootUrl = buildServer.getRootUrl();
        String url = rootUrl + "/.well-known/jwks.json";
        HttpResponse<String> resp = httpGet(url);
        if (resp.statusCode() != 200) {
            throw new TestStepException("JWKS endpoint returned HTTP " + resp.statusCode());
        }
        JWKSet jwks = JWKSet.parse(resp.body());
        SignedJWT jwt = SignedJWT.parse(token);
        String kid = jwt.getHeader().getKeyID();
        JWK jwk = jwks.getKeyByKeyId(kid);
        if (jwk == null) {
            throw new TestStepException("Key ID not found in JWKS (kid: " + kid + ")");
        }
        boolean verified;
        if (jwk instanceof RSAKey rsaKey) {
            verified = jwt.verify(new RSASSAVerifier(rsaKey));
        } else if (jwk instanceof ECKey ecKey) {
            verified = jwt.verify(new ECDSAVerifier(ecKey));
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
        if (token == null || token.isBlank()) {
            throw new TestStepException("Missing required parameter: token");
        }
        if (serviceUrl == null || serviceUrl.isBlank()) {
            throw new TestStepException("Missing required parameter: serviceUrl");
        }
        serviceUrl = serviceUrl.stripTrailing().replaceAll("/+$", "");
        if (!JwtKeyManager.isHttpsUrl(serviceUrl) && !isLocalhostUrl(serviceUrl)) {
            throw new TestStepException("serviceUrl must use HTTPS");
        }

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

        URI serviceUri = URI.create(serviceUrl);
        URI rawEndpointUri = URI.create(tokenEndpoint);
        URI resolvedEndpoint = new URI(serviceUri.getScheme(), serviceUri.getAuthority(),
                rawEndpointUri.getPath(), rawEndpointUri.getQuery(), null);

        String formBody = "grant_type=" + encode("urn:ietf:params:oauth:grant-type:token-exchange")
                + "&audience=" + encode(audience != null ? audience : "")
                + "&subject_token=" + encode(token)
                + "&subject_token_type=" + encode("urn:ietf:params:oauth:token-type:jwt");

        HttpRequest exchangeReq = HttpRequest.newBuilder()
                .uri(resolvedEndpoint)
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formBody))
                .build();
        HttpResponse<String> exchangeResp = httpClient.send(exchangeReq, HttpResponse.BodyHandlers.ofString());
        int status = exchangeResp.statusCode();
        String bodySnippet = exchangeResp.body().length() > 200
                ? exchangeResp.body().substring(0, 200) : exchangeResp.body();
        if (status < 200 || status >= 300) {
            throw new TestStepException("Exchange failed (HTTP " + status + "): " + bodySnippet);
        }
        return "Exchange succeeded (HTTP " + status + ")";
    }

    /** Allows HTTP for localhost/127.0.0.1 to support local development and testing. */
    private static boolean isLocalhostUrl(String url) {
        try {
            String host = URI.create(url).getHost();
            return "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host);
        } catch (Exception e) {
            return false;
        }
    }

    private static String encode(String value) {
        return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
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
            int ttl = (value != null && !value.isBlank()) ? Integer.parseInt(value) : 10;
            return Math.max(1, Math.min(ttl, 1440));
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
