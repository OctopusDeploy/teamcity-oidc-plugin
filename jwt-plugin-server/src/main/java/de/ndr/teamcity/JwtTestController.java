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
        if (token == null || token.isBlank()) {
            throw new TestStepException("Missing required parameter: token");
        }
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
        if (token == null || token.isBlank()) {
            throw new TestStepException("Missing required parameter: token");
        }
        if (serviceUrl == null || serviceUrl.isBlank()) {
            throw new TestStepException("Missing required parameter: serviceUrl");
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
