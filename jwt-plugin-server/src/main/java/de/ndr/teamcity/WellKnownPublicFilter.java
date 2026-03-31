package de.ndr.teamcity;

import com.nimbusds.jose.jwk.JWKSet;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.web.DelegatingFilter;
import org.jetbrains.annotations.NotNull;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Handles {@code GET /.well-known/jwks.json} and {@code GET /.well-known/openid-configuration}
 * publicly (no authentication required) by registering directly into TC's {@link DelegatingFilter}
 * chain, which runs on {@code /*} before servlet dispatch.
 *
 * <p>TC's {@code buildServer} servlet is only mapped to specific URL patterns; it does not cover
 * {@code /.well-known/*} paths directly. Registering here lets cloud providers fetch the JWKS and
 * OIDC discovery document without credentials.</p>
 */
public class WellKnownPublicFilter implements Filter {

    private final JwtBuildFeature jwtBuildFeature;
    private final SBuildServer buildServer;

    public WellKnownPublicFilter(@NotNull JwtBuildFeature jwtBuildFeature,
                                 @NotNull SBuildServer buildServer) {
        this.jwtBuildFeature = jwtBuildFeature;
        this.buildServer = buildServer;
        DelegatingFilter.registerDelegate(this);
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

        if (JwksController.PATH.equals(path)) {
            resp.setContentType("application/json;charset=UTF-8");
            resp.setHeader("Cache-Control", "max-age=300");
            JWKSet jwks = new JWKSet(jwtBuildFeature.getPublicKeys());
            resp.getWriter().write(jwks.toString());
            return;
        }

        if (OidcDiscoveryController.PATH.equals(path)) {
            resp.setContentType("application/json;charset=UTF-8");
            resp.setHeader("Cache-Control", "max-age=300");
            String issuer = buildServer.getRootUrl();
            resp.getWriter().write(
                    "{\"issuer\":\"" + issuer + "\","
                    + "\"jwks_uri\":\"" + issuer + JwksController.PATH + "\","
                    + "\"id_token_signing_alg_values_supported\":[\"RS256\",\"ES256\"],"
                    + "\"response_types_supported\":[\"id_token\"],"
                    + "\"subject_types_supported\":[\"public\"],"
                    + "\"claims_supported\":[\"sub\",\"iss\",\"aud\",\"iat\",\"nbf\",\"exp\","
                    + "\"branch\",\"build_type_external_id\",\"project_external_id\","
                    + "\"triggered_by\",\"triggered_by_id\",\"build_number\"]}"
            );
            return;
        }

        chain.doFilter(request, response);
    }

    @Override
    public void init(FilterConfig filterConfig) {}

    @Override
    public void destroy() {}
}
