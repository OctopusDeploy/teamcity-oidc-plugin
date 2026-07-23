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
import jetbrains.buildServer.serverSide.impl.SecondaryNodeSecurityManager;
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
    static final String SESSION_TOKEN_PREFIX = "jwt.test.token.";

    /** Resolves a hostname to its addresses; injectable so tests can stub DNS. */
    @FunctionalInterface
    interface AddressResolver {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    private final JwtKeyManager keyManager;
    private final SBuildServer buildServer;
    private final OidcIssuerUrlProvider issuerUrlProvider;
    private final HttpClient httpClient;
    private final CSRFFilter csrfFilter;
    private final AddressResolver addressResolver;

    @Autowired
    public JwtTestController(@NotNull final WebControllerManager controllerManager,
                             @NotNull final JwtKeyManager keyManager,
                             @NotNull final SBuildServer buildServer,
                             @NotNull final OidcIssuerUrlProvider issuerUrlProvider,
                             @NotNull final ExtensionHolder extensionHolder) {
        this(controllerManager, keyManager, buildServer, issuerUrlProvider,
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build(),
                new CSRFFilter(extensionHolder), InetAddress::getAllByName);
    }

    JwtTestController(@NotNull final WebControllerManager controllerManager,
                      @NotNull final JwtKeyManager keyManager,
                      @NotNull final SBuildServer buildServer,
                      @NotNull final OidcIssuerUrlProvider issuerUrlProvider,
                      @NotNull final HttpClient httpClient,
                      @NotNull final CSRFFilter csrfFilter) {
        this(controllerManager, keyManager, buildServer, issuerUrlProvider, httpClient, csrfFilter, InetAddress::getAllByName);
    }

    JwtTestController(@NotNull final WebControllerManager controllerManager,
                      @NotNull final JwtKeyManager keyManager,
                      @NotNull final SBuildServer buildServer,
                      @NotNull final OidcIssuerUrlProvider issuerUrlProvider,
                      @NotNull final HttpClient httpClient,
                      @NotNull final CSRFFilter csrfFilter,
                      @NotNull final AddressResolver addressResolver) {
        this.keyManager = keyManager;
        this.buildServer = buildServer;
        this.issuerUrlProvider = issuerUrlProvider;
        this.httpClient = httpClient;
        this.csrfFilter = csrfFilter;
        this.addressResolver = addressResolver;
        controllerManager.registerController(PATH, this);
        LOG.info("JWT plugin: JwtTestController registered at " + PATH);
    }

    /** Called by Spring when the plugin is unloaded. Closes the HttpClient to release its selector thread. */
    public void destroy() {
        try {
            httpClient.close();
        } catch (final Exception e) {
            LOG.log(Level.WARNING, "JWT plugin: error closing HttpClient", e);
        }
        LOG.info("JWT plugin: JwtTestController HTTP client closed");
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
        if (user == null || !user.isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS)) {
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
                final var result = stepJwt(request, user); // [message, tokenRef]
                final var json = new JSONObject();
                json.put("ok", true);
                json.put("message", result[0]);
                json.put("tokenRef", result[1]);
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
            writeJson(response, false, "An internal error occurred — check the TeamCity server log for details");
        }
        return null;
    }

    private String[] stepJwt(final HttpServletRequest request, final SUser user) throws Exception {
        final var rootUrl = issuerUrlProvider.getIssuerUrl();
        if (!OidcUrlUtils.isHttpsUrl(rootUrl)) {
            throw new TestStepException("Issuer URL is not HTTPS — OIDC endpoints won't be reachable");
        }
        var algorithm = request.getParameter("algorithm");
        if (algorithm == null || algorithm.isBlank()) algorithm = "RS256";
        // Security: TTL is hard-capped at 1 minute regardless of the build feature configuration.
        // The exchange step (stepExchange) POSTs this token to an operator-supplied external URL.
        // If that URL is attacker-controlled, a valid signed JWT is delivered to them. Mitigations:
        //   1. Only admins with CHANGE_SERVER_SETTINGS can invoke this endpoint (enforced in doHandle).
        //   2. Private/link-local addresses are blocked at the network level (checkNotPrivateAddress).
        //   3. This 1-minute TTL caps the window in which a stolen token could be replayed — even
        //      if it reaches an attacker, it expires before most automated abuse is practical.
        // Requiring a non-empty audience does NOT help: an attacker simply supplies one.
        final var ttl = 1;
        var audience = request.getParameter("audience");
        if (audience == null || audience.isBlank()) audience = rootUrl;

        final var buildTypeId = request.getParameter("buildTypeId");
        if (buildTypeId == null || buildTypeId.isBlank()) {
            throw new TestStepException("Missing required parameter: buildTypeId");
        }
        // The subject the token is scoped to, plus a label distinguishing a build
        // configuration's concrete token from a template's representative one.
        final var resolved = resolveSubject(buildTypeId, user);

        final var now = new Date();
        final var claims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .subject(resolved.subject())
                .issuer(rootUrl)
                .audience(List.of(audience))
                .issueTime(now)
                .notBeforeTime(now)
                .expirationTime(new Date(now.getTime() + ttl * 60_000L))
                .build();

        final var jwt = keyManager.sign(claims, algorithm);
        final var serialized = jwt.serialize();
        final var tokenRef = UUID.randomUUID().toString();
        // Store the signed JWT in the HTTP session rather than returning it to the browser,
        // so the raw bearer credential never travels over the wire to the client.
        // The browser receives only this UUID reference; subsequent steps look it up and
        // remove it on read (consume-once).
        //
        // Multi-node HA note: HttpSession is node-local in TeamCity. This works correctly
        // because TC's HA setup already requires sticky sessions at the load balancer
        // (NodeResponsibility.CAN_PROCESS_USER_DATA_MODIFICATION_REQUESTS). All three
        // sequential test-connection POSTs from the same browser tab are guaranteed to land
        // on the same node. If a node switch somehow occurred mid-flow, the user would see
        // "No active test token — please click 'Test Connection' again" and could retry.
        request.getSession().setAttribute(SESSION_TOKEN_PREFIX + tokenRef, serialized);
        final var message = resolved.label() + " (sub: " + resolved.subject()
                + ", alg: " + algorithm + ", ttl: " + ttl + "m)";
        return new String[]{message, tokenRef};
    }

    /** The subject a test token is scoped to, and the label describing how it was derived. */
    private record ResolvedSubject(@NotNull String subject, @NotNull String label) {
    }

    /**
     * Resolves the {@code sub} claim for a test token from the edit dialog's id parameter. A build
     * configuration ("buildType:&lt;externalId&gt;", or a bare external id) yields a concrete
     * subject. A template ("template:&lt;externalId&gt;") has no concrete build type, so the subject
     * uses a {@code <build_type_id>} placeholder — the token is still signed so the discovery and
     * JWKS steps can exercise the server's OIDC endpoints.
     */
    private ResolvedSubject resolveSubject(@NotNull final String buildTypeId, @NotNull final SUser user)
            throws TestStepException {
        final var projectManager = buildServer.getProjectManager();
        if (buildTypeId.startsWith("template:")) {
            final var externalId = buildTypeId.substring("template:".length());
            final var template = projectManager.findBuildTypeTemplateByExternalId(externalId);
            if (template == null) {
                throw new TestStepException("Template not found: " + buildTypeId);
            }
            final var projectId = template.getProject().getProjectId();
            requireEditProject(user, projectId);
            return new ResolvedSubject(
                    "project:" + projectId + ":build_type:<build_type_id>",
                    "Representative JWT issued for template");
        }
        // TC passes the id param as "buildType:<externalId>" — strip the prefix if present.
        final var externalId = buildTypeId.startsWith("buildType:")
                ? buildTypeId.substring("buildType:".length())
                : buildTypeId;
        final var buildType = projectManager.findBuildTypeByExternalId(externalId);
        if (buildType == null) {
            throw new TestStepException("Build type not found: " + buildTypeId);
        }
        requireEditProject(user, buildType.getProjectId());
        return new ResolvedSubject(
                "project:" + buildType.getProjectId() + ":build_type:" + buildType.getInternalId(),
                "JWT issued");
    }

    /**
     * Mitigation 4: the user must have project-level EDIT_PROJECT for the token's project,
     * preventing a server-settings admin from issuing test JWTs for projects they can't edit.
     */
    private void requireEditProject(@NotNull final SUser user, @NotNull final String projectId)
            throws TestStepException {
        if (!user.isPermissionGrantedForProject(projectId, Permission.EDIT_PROJECT)) {
            throw new TestStepException("Access denied for project: " + projectId);
        }
    }

    private String stepDiscovery() throws Exception {
        final var rootUrl = issuerUrlProvider.getIssuerUrl();
        if (!OidcUrlUtils.isHttpsUrl(rootUrl)) {
            throw new TestStepException("Issuer URL is not HTTPS — OIDC endpoints won't be reachable");
        }
        final var url = buildUrl(rootUrl, "/.well-known/openid-configuration");
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
        final var rootUrl = issuerUrlProvider.getIssuerUrl();
        if (!OidcUrlUtils.isHttpsUrl(rootUrl)) {
            throw new TestStepException("Issuer URL is not HTTPS — OIDC endpoints won't be reachable");
        }
        final var tokenRef = request.getParameter("tokenRef");
        final var token = tokenRef != null
                ? (String) request.getSession().getAttribute(SESSION_TOKEN_PREFIX + tokenRef) : null;
        if (token == null) {
            throw new TestStepException("No active test token — please click 'Test Connection' again");
        }
        request.getSession().removeAttribute(SESSION_TOKEN_PREFIX + tokenRef);
        final var url = buildUrl(rootUrl, "/.well-known/jwks.json");
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
        var serviceUrl = request.getParameter("serviceUrl");
        final var audience = request.getParameter("audience");
        if (serviceUrl == null || serviceUrl.isBlank()) {
            throw new TestStepException("Missing required parameter: serviceUrl");
        }
        serviceUrl = serviceUrl.stripTrailing().replaceAll("/+$", "");
        if (!OidcUrlUtils.isHttpsUrl(serviceUrl)) {
            throw new TestStepException("serviceUrl must use HTTPS");
        }
        checkNotPrivateAddress(serviceUrl);
        final var tokenRef = request.getParameter("tokenRef");
        final var token = tokenRef != null
                ? (String) request.getSession().getAttribute(SESSION_TOKEN_PREFIX + tokenRef) : null;
        if (token == null) {
            throw new TestStepException("No active test token — please click 'Test Connection' again");
        }
        request.getSession().removeAttribute(SESSION_TOKEN_PREFIX + tokenRef);

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
        final var exchangeResp = SecondaryNodeSecurityManager.runSafeNetworkOperation(
                () -> httpClient.send(exchangeReq, HttpResponse.BodyHandlers.ofString()));
        final var status = exchangeResp.statusCode();
        if (status < 200 || status >= 300) {
            final var bodySnippet = exchangeResp.body().length() > 200
                    ? exchangeResp.body().substring(0, 200) : exchangeResp.body();
            throw new TestStepException("Exchange failed (HTTP " + status + "): " + bodySnippet);
        }
        return "Exchange succeeded (HTTP " + status + ")";
    }

    /**
     * System property that, when set to {@code true}, disables the private-address check in
     * {@link #checkNotPrivateAddress}. Intended for local development/manual testing where the
     * target service (e.g. Octopus Deploy) runs in a Docker network alongside TeamCity.
     * <strong>Never set this in production.</strong>
     */
    static final String ALLOW_PRIVATE_EXCHANGE_PROPERTY = "teamcity.oidc.allowPrivateExchangeUrls";

    /**
     * Resolves {@code url}'s hostname and rejects it if any resolved address is a loopback,
     * link-local, or RFC-1918 / site-local address. Prevents the exchange test step from being
     * used as an SSRF probe against internal infrastructure.
     * <p>
     * The check is skipped when the system property {@value #ALLOW_PRIVATE_EXCHANGE_PROPERTY}
     * is {@code true} — useful for local testing with Docker-hosted services.
     */
    private void checkNotPrivateAddress(final String url) throws TestStepException {
        if (Boolean.getBoolean(ALLOW_PRIVATE_EXCHANGE_PROPERTY)) {
            return;
        }
        final var host = URI.create(url).getHost();
        final InetAddress[] addresses;
        try {
            addresses = SecondaryNodeSecurityManager.runSafeNetworkOperation(() -> addressResolver.resolve(host));
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

    /**
     * Builds a URL by decomposing {@code rootUrl} into its URI components and
     * appending {@code path}. This ignores any query string or fragment on the root URL, which
     * plain string concatenation would not — e.g. {@code "https://tc.example.com?v=1" + "/..."}.
     */
    private static String buildUrl(final String rootUrl, final String path) {
        final var base = URI.create(rootUrl);
        return base.getScheme() + "://" + base.getAuthority() + base.getPath() + path;
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
            // runSafeNetworkOperation lifts the outbound-connection block a secondary node's
            // SecurityManager imposes; on the main node (and in tests) it just runs the operation.
            return SecondaryNodeSecurityManager.runSafeNetworkOperation(
                    () -> httpClient.send(req, HttpResponse.BodyHandlers.ofString()));
        } catch (final IOException e) {
            throw new TestStepException("Could not reach " + url + " — "
                    + e.getClass().getSimpleName() + ": " + e.getMessage());
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
