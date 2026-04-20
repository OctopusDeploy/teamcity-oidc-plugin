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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
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

    /** Resolves a hostname to its addresses; injectable so tests can stub DNS. */
    @FunctionalInterface
    interface AddressResolver {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    private final JwtKeyManager keyManager;
    private final SBuildServer buildServer;
    private final HttpClient httpClient;
    private final CSRFFilter csrfFilter;
    private final AddressResolver addressResolver;

    @Autowired
    public JwtTestController(@NotNull final WebControllerManager controllerManager,
                             @NotNull final JwtKeyManager keyManager,
                             @NotNull final SBuildServer buildServer,
                             @NotNull final ExtensionHolder extensionHolder) {
        this(controllerManager, keyManager, buildServer,
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build(),
                new CSRFFilter(extensionHolder), InetAddress::getAllByName);
    }

    JwtTestController(@NotNull final WebControllerManager controllerManager,
                      @NotNull final JwtKeyManager keyManager,
                      @NotNull final SBuildServer buildServer,
                      @NotNull final HttpClient httpClient,
                      @NotNull final CSRFFilter csrfFilter) {
        this(controllerManager, keyManager, buildServer, httpClient, csrfFilter, InetAddress::getAllByName);
    }

    JwtTestController(@NotNull final WebControllerManager controllerManager,
                      @NotNull final JwtKeyManager keyManager,
                      @NotNull final SBuildServer buildServer,
                      @NotNull final HttpClient httpClient,
                      @NotNull final CSRFFilter csrfFilter,
                      @NotNull final AddressResolver addressResolver) {
        this.keyManager = keyManager;
        this.buildServer = buildServer;
        this.httpClient = httpClient;
        this.csrfFilter = csrfFilter;
        this.addressResolver = addressResolver;
        controllerManager.registerController(PATH, this);
        LOG.info("JWT plugin: JwtTestController registered at " + PATH);
    }

    @Override
    protected ModelAndView doHandle(@NotNull final HttpServletRequest request,
                                    @NotNull final HttpServletResponse response) throws IOException {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return null;
        }

        if (!csrfFilter.validateRequest(request, response)) {
            return null;
        }

        response.setContentType("application/json;charset=UTF-8");

        final var user = SessionUser.getUser(request);
        if (user == null || !user.isPermissionGrantedGlobally(Permission.MANAGE_SERVER_INSTALLATION)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            writeJson(response, false, "Access denied");
            return null;
        }

        final var step = request.getParameter("step");
        if (step == null || step.isBlank()) {
            writeJson(response, false, "Missing required parameter: step");
            return null;
        }
        try {
            if ("jwt".equals(step)) {
                final var result = stepJwt(request); // [message, serializedToken]
                final var json = new JSONObject();
                json.put("ok", true);
                json.put("message", result[0]);
                json.put("token", result[1]);
                response.getWriter().write(json.toJSONString());
            } else {
                final var message = switch (step) {
                    case "discovery" -> stepDiscovery();
                    case "jwks" -> stepJwks(request);
                    case "exchange" -> stepExchange(request);
                    default -> throw new TestStepException("Unknown step: " + step);
                };
                writeJson(response, true, message);
            }
        } catch (final TestStepException e) {
            writeJson(response, false, e.getMessage());
        } catch (final Exception e) {
            LOG.log(Level.WARNING, "JWT plugin: test step '" + step + "' failed", e);
            writeJson(response, false, e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
        }
        return null;
    }

    private String[] stepJwt(final HttpServletRequest request) throws Exception {
        final var rootUrl = buildServer.getRootUrl();
        if (!JwtKeyManager.isHttpsUrl(rootUrl)) {
            throw new TestStepException("Root URL is not HTTPS — OIDC endpoints won't be reachable");
        }
        var algorithm = request.getParameter("algorithm");
        if (algorithm == null || algorithm.isBlank()) algorithm = "RS256";
        final var ttl = parseTtl(request.getParameter("ttl_minutes"));
        var audience = request.getParameter("audience");
        if (audience == null || audience.isBlank()) audience = rootUrl;

        final var buildTypeId = request.getParameter("buildTypeId");
        if (buildTypeId == null || buildTypeId.isBlank()) {
            throw new TestStepException("Missing required parameter: buildTypeId");
        }
        // TC passes the id param as "buildType:<externalId>" — strip the prefix if present
        final var externalId = buildTypeId.startsWith("buildType:")
                ? buildTypeId.substring("buildType:".length())
                : buildTypeId;
        final var buildType = buildServer.getProjectManager().findBuildTypeByExternalId(externalId);
        if (buildType == null) {
            throw new TestStepException("Build type not found: " + buildTypeId);
        }
        final var subject = buildType.getExternalId();

        final var now = new Date();
        final var claims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .subject(subject)
                .issuer(rootUrl)
                .audience(List.of(audience))
                .issueTime(now)
                .notBeforeTime(now)
                .expirationTime(new Date(now.getTime() + ttl * 60_000L))
                .build();

        final var jwt = keyManager.sign(claims, algorithm);
        final var serialized = jwt.serialize();
        final var message = "JWT issued (sub: " + subject + ", alg: " + algorithm + ", ttl: " + ttl + "m)";
        return new String[]{message, serialized};
    }

    private String stepDiscovery() throws Exception {
        final var rootUrl = buildServer.getRootUrl();
        if (!JwtKeyManager.isHttpsUrl(rootUrl)) {
            throw new TestStepException("Root URL is not HTTPS — OIDC endpoints won't be reachable");
        }
        final var url = rootUrl + "/.well-known/openid-configuration";
        final var resp = httpGet(url);
        if (resp.statusCode() != 200) {
            throw new TestStepException("Discovery endpoint returned HTTP " + resp.statusCode());
        }
        final var doc = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(resp.body());
        final var issuer = (String) doc.get("issuer");
        if (!rootUrl.equals(issuer)) {
            throw new TestStepException("issuer mismatch: expected \"" + rootUrl + "\", got \"" + issuer + "\"");
        }
        return "Discovery endpoint OK (issuer matches)";
    }

    private String stepJwks(final HttpServletRequest request) throws Exception {
        final var token = request.getParameter("token");
        if (token == null || token.isBlank()) {
            throw new TestStepException("Missing required parameter: token");
        }
        final var rootUrl = buildServer.getRootUrl();
        if (!JwtKeyManager.isHttpsUrl(rootUrl)) {
            throw new TestStepException("Root URL is not HTTPS — OIDC endpoints won't be reachable");
        }
        final var url = rootUrl + "/.well-known/jwks.json";
        final var resp = httpGet(url);
        if (resp.statusCode() != 200) {
            throw new TestStepException("JWKS endpoint returned HTTP " + resp.statusCode());
        }
        final var jwks = JWKSet.parse(resp.body());
        final var jwt = SignedJWT.parse(token);
        final var kid = jwt.getHeader().getKeyID();
        final var jwk = jwks.getKeyByKeyId(kid);
        if (jwk == null) {
            throw new TestStepException("Key ID not found in JWKS (kid: " + kid + ")");
        }
        final boolean verified;
        if (jwk instanceof final RSAKey rsaKey) {
            verified = jwt.verify(new RSASSAVerifier(rsaKey));
        } else if (jwk instanceof final ECKey ecKey) {
            verified = jwt.verify(new ECDSAVerifier(ecKey));
        } else {
            throw new TestStepException("Unsupported key type in JWKS: " + jwk.getKeyType());
        }
        if (!verified) {
            throw new TestStepException("Signature verification failed");
        }
        return "JWKS OK — signature verified";
    }

    private String stepExchange(final HttpServletRequest request) throws Exception {
        final var token = request.getParameter("token");
        var serviceUrl = request.getParameter("serviceUrl");
        final var audience = request.getParameter("audience");
        if (token == null || token.isBlank()) {
            throw new TestStepException("Missing required parameter: token");
        }
        if (serviceUrl == null || serviceUrl.isBlank()) {
            throw new TestStepException("Missing required parameter: serviceUrl");
        }
        serviceUrl = serviceUrl.stripTrailing().replaceAll("/+$", "");
        if (!JwtKeyManager.isHttpsUrl(serviceUrl)) {
            throw new TestStepException("serviceUrl must use HTTPS");
        }
        checkNotPrivateAddress(serviceUrl);

        final var discoveryUrl = serviceUrl + "/.well-known/openid-configuration";
        final var discoveryResp = httpGet(discoveryUrl);
        if (discoveryResp.statusCode() != 200) {
            throw new TestStepException("Service discovery returned HTTP " + discoveryResp.statusCode());
        }
        final var discoveryDoc = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(discoveryResp.body());
        final var tokenEndpoint = (String) discoveryDoc.get("token_endpoint");
        if (tokenEndpoint == null || tokenEndpoint.isBlank()) {
            throw new TestStepException("token_endpoint not found in service discovery document");
        }

        final var serviceUri = URI.create(serviceUrl);
        final var rawEndpointUri = URI.create(tokenEndpoint);
        final var resolvedEndpoint = new URI(serviceUri.getScheme(), serviceUri.getAuthority(),
                rawEndpointUri.getPath(), rawEndpointUri.getQuery(), null);

        final var formBody = "grant_type=" + encode("urn:ietf:params:oauth:grant-type:token-exchange")
                + "&audience=" + encode(audience != null ? audience : "")
                + "&subject_token=" + encode(token)
                + "&subject_token_type=" + encode("urn:ietf:params:oauth:token-type:jwt");

        final var exchangeReq = HttpRequest.newBuilder()
                .uri(resolvedEndpoint)
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formBody))
                .build();
        final var exchangeResp = httpClient.send(exchangeReq, HttpResponse.BodyHandlers.ofString());
        final var status = exchangeResp.statusCode();
        if (status < 200 || status >= 300) {
            final var bodySnippet = exchangeResp.body().length() > 200
                    ? exchangeResp.body().substring(0, 200) : exchangeResp.body();
            throw new TestStepException("Exchange failed (HTTP " + status + "): " + bodySnippet);
        }
        return "Exchange succeeded (HTTP " + status + ")";
    }

    /**
     * Resolves {@code url}'s hostname and rejects it if any resolved address is a loopback,
     * link-local, or RFC-1918 / site-local address. Prevents the exchange test step from being
     * used as an SSRF probe against internal infrastructure.
     */
    private void checkNotPrivateAddress(final String url) throws TestStepException {
        final var host = URI.create(url).getHost();
        final InetAddress[] addresses;
        try {
            addresses = addressResolver.resolve(host);
        } catch (final UnknownHostException e) {
            throw new TestStepException("Could not resolve host: " + host);
        }
        for (final var addr : addresses) {
            if (addr.isLoopbackAddress() || addr.isSiteLocalAddress()
                    || addr.isLinkLocalAddress() || addr.isAnyLocalAddress()) {
                throw new TestStepException(
                        "serviceUrl resolves to a private or link-local address — not allowed");
            }
        }
    }

    private static String encode(final String value) {
        return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
    }

    private HttpResponse<String> httpGet(final String url) throws Exception {
        final var req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(5))
                .GET()
                .build();
        try {
            return httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (final IOException e) {
            throw new TestStepException("Could not reach " + url + " — "
                    + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private static int parseTtl(final String value) {
        try {
            final var ttl = (value != null && !value.isBlank()) ? Integer.parseInt(value) : 10;
            return Math.max(1, Math.min(ttl, 1440));
        } catch (final NumberFormatException e) {
            return 10;
        }
    }

    private static void writeJson(final HttpServletResponse response, final boolean ok, final String message) throws IOException {
        final var json = new JSONObject();
        json.put("ok", ok);
        json.put("message", message);
        response.getWriter().write(json.toJSONString());
    }

    static class TestStepException extends Exception {
        TestStepException(final String message) {
            super(message);
        }
    }
}
