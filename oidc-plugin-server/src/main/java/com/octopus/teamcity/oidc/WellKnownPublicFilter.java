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
import java.util.logging.Logger;

public class WellKnownPublicFilter implements Filter {
    private static final Logger LOG = Logger.getLogger(WellKnownPublicFilter.class.getName());

    static final String JWKS_PATH = "/.well-known/jwks.json";
    static final String OIDC_DISCOVERY_PATH = "/.well-known/openid-configuration";

    private final JwtKeyManager keyManager;
    private final SBuildServer buildServer;

    public WellKnownPublicFilter(@NotNull JwtKeyManager keyManager,
                                 @NotNull SBuildServer buildServer) {
        this.keyManager = keyManager;
        this.buildServer = buildServer;
        DelegatingFilter.registerDelegate(this);
        LOG.info("JWT plugin: WellKnownPublicFilter registered in DelegatingFilter chain");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;

        String path = req.getRequestURI();
        String contextPath = req.getContextPath();
        if (!contextPath.isEmpty() && path.startsWith(contextPath)) {
            path = path.substring(contextPath.length());
        }

        if (JWKS_PATH.equals(path)) {
            resp.setContentType("application/json;charset=UTF-8");
            resp.setHeader("Cache-Control", "max-age=300");
            JWKSet jwks = new JWKSet(keyManager.getPublicKeys());
            LOG.info("JWT plugin: serving JWKS (" + jwks.getKeys().size() + " key(s)) from WellKnownPublicFilter");
            resp.getWriter().write(jwks.toString());
            return;
        }

        if (OIDC_DISCOVERY_PATH.equals(path)) {
            resp.setContentType("application/json;charset=UTF-8");
            resp.setHeader("Cache-Control", "max-age=300");
            String issuer = JwtKeyManager.normalizeRootUrl(buildServer.getRootUrl());
            LOG.info("JWT plugin: serving OIDC discovery from WellKnownPublicFilter, issuer=" + issuer);

            JSONArray algs = new JSONArray();
            algs.add("RS256");
            algs.add("ES256");

            JSONArray responseTypes = new JSONArray();
            responseTypes.add("id_token");

            JSONArray subjectTypes = new JSONArray();
            subjectTypes.add("public");

            JSONArray claims = new JSONArray();
            for (String c : new String[]{"sub", "iss", "aud", "iat", "nbf", "exp",
                    "branch", "build_type_external_id", "project_external_id",
                    "triggered_by", "triggered_by_id", "build_number"}) {
                claims.add(c);
            }

            JSONObject doc = new JSONObject();
            doc.put("issuer", issuer);
            // authorization_endpoint is required by the OIDC Discovery spec even for non-interactive
            // providers. This provider does not support interactive flows; the endpoint returns 404.
            doc.put("authorization_endpoint", issuer + "/oidc/authorize");
            doc.put("jwks_uri", issuer + JWKS_PATH);
            doc.put("id_token_signing_alg_values_supported", algs);
            doc.put("response_types_supported", responseTypes);
            doc.put("subject_types_supported", subjectTypes);
            doc.put("claims_supported", claims);

            resp.getWriter().write(doc.toJSONString());
            return;
        }

        chain.doFilter(request, response);
    }

    @Override
    public void init(FilterConfig filterConfig) {}

    @Override
    public void destroy() {}
}
