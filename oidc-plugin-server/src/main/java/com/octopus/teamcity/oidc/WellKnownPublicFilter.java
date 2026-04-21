package com.octopus.teamcity.oidc;

import com.nimbusds.jose.jwk.JWKSet;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.web.DelegatingFilter;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.jetbrains.annotations.NotNull;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

public class WellKnownPublicFilter implements Filter {
    private static final Logger LOG = Logger.getLogger(WellKnownPublicFilter.class.getName());

    static final String JWKS_PATH = "/.well-known/jwks.json";
    static final String OIDC_DISCOVERY_PATH = "/.well-known/openid-configuration";
    static final String AUTHORIZE_PATH = "/oidc/authorize";

    static final long JWKS_MAX_AGE_SECONDS = 60L;
    static final long JWKS_STALE_WHILE_REVALIDATE_SECONDS = 60L;

    private final JwtKeyManager keyManager;
    private final SBuildServer buildServer;

    public WellKnownPublicFilter(@NotNull final JwtKeyManager keyManager,
                                 @NotNull final SBuildServer buildServer) {
        this.keyManager = keyManager;
        this.buildServer = buildServer;
        DelegatingFilter.registerDelegate(this);
        LOG.info("JWT plugin: WellKnownPublicFilter registered in DelegatingFilter chain");
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {
        final var req = (HttpServletRequest) request;
        final var resp = (HttpServletResponse) response;

        var path = req.getRequestURI();
        final var contextPath = req.getContextPath();
        if (!contextPath.isEmpty() && path.startsWith(contextPath)) {
            path = path.substring(contextPath.length());
        }

        if (JWKS_PATH.equals(path)) {
            if (!keyManager.isReady()) {
                serviceUnavailable(resp);
                return;
            }
            resp.setContentType("application/json;charset=UTF-8");
            resp.setHeader("Access-Control-Allow-Origin", "*");
            resp.setHeader("Cache-Control", "max-age=" + JWKS_MAX_AGE_SECONDS
                    + ", stale-while-revalidate=" + JWKS_STALE_WHILE_REVALIDATE_SECONDS);
            final var publicKeys = keyManager.getPublicKeys();
            final var jwks = new JWKSet(publicKeys != null ? publicKeys : List.of());
            LOG.info("JWT plugin: serving JWKS (" + jwks.getKeys().size() + " key(s)) from WellKnownPublicFilter");
            resp.getWriter().write(jwks.toString());
            return;
        }

        if (OIDC_DISCOVERY_PATH.equals(path)) {
            if (!keyManager.isReady()) {
                serviceUnavailable(resp);
                return;
            }
            resp.setContentType("application/json;charset=UTF-8");
            resp.setHeader("Access-Control-Allow-Origin", "*");
            resp.setHeader("Cache-Control", "max-age=" + JWKS_MAX_AGE_SECONDS
                    + ", stale-while-revalidate=" + JWKS_STALE_WHILE_REVALIDATE_SECONDS);
            final var issuer = JwtKeyManager.normalizeRootUrl(buildServer.getRootUrl());
            LOG.fine("JWT plugin: serving OIDC discovery from WellKnownPublicFilter, issuer=" + issuer);

            final var doc = getJsonObject(issuer);

            resp.getWriter().write(doc.toJSONString());
            return;
        }

        if (AUTHORIZE_PATH.equals(path)) {
            resp.setContentType("application/json;charset=UTF-8");
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            resp.getWriter().write("{\"error\":\"unsupported_response_type\"," +
                    "\"error_description\":\"This TeamCity OIDC provider issues tokens for workload identity only and does not support interactive authorisation flows.\"}");
            return;
        }

        chain.doFilter(request, response);
    }

    private static JSONObject getJsonObject(final String issuer) {
        final var algs = new JSONArray();
        algs.add("RS256");
        algs.add("ES256");

        final var responseTypes = new JSONArray();
        responseTypes.add("id_token");

        final var subjectTypes = new JSONArray();
        subjectTypes.add("public");

        final var claims = new JSONArray();
        Collections.addAll(claims, "sub", "iss", "aud", "iat", "nbf", "exp",
                "branch", "build_type_external_id", "project_external_id",
                "triggered_by", "triggered_by_id", "build_number");

        final var doc = new JSONObject();
        doc.put("issuer", issuer);
        // authorization_endpoint is required by the OIDC Discovery spec even for non-interactive
        // providers. The endpoint returns unsupported_response_type for all requests.
        doc.put("authorization_endpoint", issuer + AUTHORIZE_PATH);
        doc.put("jwks_uri", issuer + JWKS_PATH);
        doc.put("id_token_signing_alg_values_supported", algs);
        doc.put("response_types_supported", responseTypes);
        doc.put("subject_types_supported", subjectTypes);
        doc.put("claims_supported", claims);
        return doc;
    }

    private static void serviceUnavailable(final HttpServletResponse resp) throws IOException {
        resp.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        resp.setContentType("application/json;charset=UTF-8");
        resp.setHeader("Access-Control-Allow-Origin", "*");
        resp.getWriter().write("{\"error\":\"server_starting\","
                + "\"error_description\":\"OIDC provider is not yet available — server startup in progress.\"}");
    }

    @Override
    public void init(final FilterConfig filterConfig) {}

    @Override
    public void destroy() {}
}
