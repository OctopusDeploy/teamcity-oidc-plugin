package com.octopus.teamcity.oidc;

import jetbrains.buildServer.serverSide.ServerPaths;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Integration tests: verify that the OIDC discovery document produced by
 * WellKnownPublicFilter is compliant with the OpenID Connect Discovery 1.0 spec
 * and contains the fields required by cloud provider OIDC federation setups.
  * Reference: <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">...</a>
 */
@ExtendWith(MockitoExtension.class)
public class OidcDiscoveryComplianceTest {

    @Mock ServerPaths serverPaths;
    @Mock jetbrains.buildServer.serverSide.SBuildServer buildServer;

    @TempDir File tempDir;

    private JSONObject discoveryDocument;

    @BeforeEach
    void fetchDiscoveryDocument() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");
        final var keyManager = TestJwtKeyManagerFactory.create(serverPaths);
        final var filter = new WellKnownPublicFilter(keyManager, buildServer);

        final var request = mock(HttpServletRequest.class);
        final var response = mock(HttpServletResponse.class);
        final var chain = mock(FilterChain.class);
        final var writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.OIDC_DISCOVERY_PATH);
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, chain);

        discoveryDocument = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(writer.toString());
    }

    // --- Required fields (OIDC Discovery spec section 3) ---

    @Test
    public void issuerIsPresent() {
        assertThat(discoveryDocument.containsKey("issuer")).isTrue();
        assertThat((String) discoveryDocument.get("issuer")).isEqualTo("https://teamcity.example.com");
    }

    @Test
    public void issuerDoesNotHaveTrailingSlash() {
        // Cloud providers (GCP, AWS) compare issuer exactly — a trailing slash causes validation failure
        assertThat((String) discoveryDocument.get("issuer")).doesNotEndWith("/");
    }

    @Test
    public void jwksUriIsPresent() {
        assertThat(discoveryDocument.containsKey("jwks_uri")).isTrue();
        assertThat((String) discoveryDocument.get("jwks_uri"))
                .isEqualTo("https://teamcity.example.com/.well-known/jwks.json");
    }

    @Test
    public void responseTypesSupportedIsPresent() {
        // Required by spec
        assertThat(discoveryDocument.containsKey("response_types_supported")).isTrue();
        final var types = toStringList((JSONArray) discoveryDocument.get("response_types_supported"));
        assertThat(types).contains("id_token");
    }

    @Test
    public void subjectTypesSupportedIsPresent() {
        // Required by spec
        assertThat(discoveryDocument.containsKey("subject_types_supported")).isTrue();
        final var types = toStringList((JSONArray) discoveryDocument.get("subject_types_supported"));
        assertThat(types).contains("public");
    }

    @Test
    public void idTokenSigningAlgValuesSupportedIsPresent() {
        // Required by spec
        assertThat(discoveryDocument.containsKey("id_token_signing_alg_values_supported")).isTrue();
    }

    // --- Algorithm advertisement ---

    @Test
    public void advertisesRS256() {
        final var algs = toStringList(
                (JSONArray) discoveryDocument.get("id_token_signing_alg_values_supported"));
        assertThat(algs).contains("RS256");
    }

    @Test
    public void advertisesES256() {
        // Critical: cloud providers reject ES256 tokens if ES256 isn't advertised here
        final var algs = toStringList(
                (JSONArray) discoveryDocument.get("id_token_signing_alg_values_supported"));
        assertThat(algs).contains("ES256");
    }

    // --- Recommended fields ---

    @Test
    public void claimsSupportedIsPresent() {
        // Recommended by spec; some cloud provider setup wizards require it
        assertThat(discoveryDocument.containsKey("claims_supported")).isTrue();
    }

    @Test
    public void claimsSupportedIncludesStandardClaims() {
        final var claims = toStringList((JSONArray) discoveryDocument.get("claims_supported"));
        assertThat(claims).contains("sub", "iss", "aud", "iat", "exp");
    }

    @Test
    public void claimsSupportedIncludesCustomBuildClaims() {
        final var claims = toStringList((JSONArray) discoveryDocument.get("claims_supported"));
        assertThat(claims).contains("branch", "build_type_external_id", "project_external_id",
                "triggered_by", "build_number");
    }

    // --- Wire format ---

    @Test
    public void responseBodyIsValidJson() {
        // Verified implicitly by @BeforeEach parse — if it throws, setup fails
        assertThat(discoveryDocument).isNotNull();
    }

    @Test
    public void jwksUriUsesHttps() {
        // Cloud providers reject non-HTTPS JWKS URIs
        assertThat((String) discoveryDocument.get("jwks_uri")).startsWith("https://");
    }

    @Test
    public void jwksUriSuffix() {
        assertThat((String) discoveryDocument.get("jwks_uri"))
                .endsWith(WellKnownPublicFilter.JWKS_PATH);
    }

    // --- helper ---

    private List<String> toStringList(final JSONArray array) {
        final List<String> result = new ArrayList<>();
        array.forEach(e -> result.add((String) e));
        return result;
    }
}
