package de.ndr.teamcity;

import com.nimbusds.jose.shaded.gson.JsonArray;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;
import jetbrains.buildServer.serverSide.ServerPaths;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
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
 *
 * Reference: https://openid.net/specs/openid-connect-discovery-1_0.html
 */
@ExtendWith(MockitoExtension.class)
public class OidcDiscoveryComplianceTest {

    @Mock ServerPaths serverPaths;
    @Mock PluginDescriptor pluginDescriptor;
    @Mock jetbrains.buildServer.serverSide.SBuildServer buildServer;

    @TempDir File tempDir;

    private JsonObject discoveryDocument;

    @BeforeEach
    void fetchDiscoveryDocument() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");
        JwtBuildFeature feature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);
        WellKnownPublicFilter filter = new WellKnownPublicFilter(feature, buildServer);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));
        when(request.getRequestURI()).thenReturn(WellKnownPublicFilter.OIDC_DISCOVERY_PATH);
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, chain);

        discoveryDocument = JsonParser.parseString(writer.toString()).getAsJsonObject();
    }

    // --- Required fields (OIDC Discovery spec section 3) ---

    @Test
    public void issuerIsPresent() {
        assertThat(discoveryDocument.has("issuer")).isTrue();
        assertThat(discoveryDocument.get("issuer").getAsString()).isEqualTo("https://teamcity.example.com");
    }

    @Test
    public void issuerDoesNotHaveTrailingSlash() {
        // Cloud providers (GCP, AWS) compare issuer exactly — a trailing slash causes validation failure
        assertThat(discoveryDocument.get("issuer").getAsString()).doesNotEndWith("/");
    }

    @Test
    public void jwksUriIsPresent() {
        assertThat(discoveryDocument.has("jwks_uri")).isTrue();
        assertThat(discoveryDocument.get("jwks_uri").getAsString())
                .isEqualTo("https://teamcity.example.com/.well-known/jwks.json");
    }

    @Test
    public void responseTypesSupportedIsPresent() {
        // Required by spec
        assertThat(discoveryDocument.has("response_types_supported")).isTrue();
        List<String> types = toStringList(discoveryDocument.get("response_types_supported").getAsJsonArray());
        assertThat(types).contains("id_token");
    }

    @Test
    public void subjectTypesSupportedIsPresent() {
        // Required by spec
        assertThat(discoveryDocument.has("subject_types_supported")).isTrue();
        List<String> types = toStringList(discoveryDocument.get("subject_types_supported").getAsJsonArray());
        assertThat(types).contains("public");
    }

    @Test
    public void idTokenSigningAlgValuesSupportedIsPresent() {
        // Required by spec
        assertThat(discoveryDocument.has("id_token_signing_alg_values_supported")).isTrue();
    }

    // --- Algorithm advertisement ---

    @Test
    public void advertisesRS256() {
        List<String> algs = toStringList(
                discoveryDocument.get("id_token_signing_alg_values_supported").getAsJsonArray());
        assertThat(algs).contains("RS256");
    }

    @Test
    public void advertisesES256() {
        // Critical: cloud providers reject ES256 tokens if ES256 isn't advertised here
        List<String> algs = toStringList(
                discoveryDocument.get("id_token_signing_alg_values_supported").getAsJsonArray());
        assertThat(algs).contains("ES256");
    }

    // --- Recommended fields ---

    @Test
    public void claimsSupportedIsPresent() {
        // Recommended by spec; some cloud provider setup wizards require it
        assertThat(discoveryDocument.has("claims_supported")).isTrue();
    }

    @Test
    public void claimsSupportedIncludesStandardClaims() {
        List<String> claims = toStringList(discoveryDocument.get("claims_supported").getAsJsonArray());
        assertThat(claims).contains("sub", "iss", "aud", "iat", "exp");
    }

    @Test
    public void claimsSupportedIncludesCustomBuildClaims() {
        List<String> claims = toStringList(discoveryDocument.get("claims_supported").getAsJsonArray());
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
        assertThat(discoveryDocument.get("jwks_uri").getAsString()).startsWith("https://");
    }

    @Test
    public void jwksUriSuffix() {
        assertThat(discoveryDocument.get("jwks_uri").getAsString())
                .endsWith(WellKnownPublicFilter.JWKS_PATH);
    }

    // --- helper ---

    private List<String> toStringList(JsonArray array) {
        List<String> result = new ArrayList<>();
        array.forEach(e -> result.add(e.getAsString()));
        return result;
    }
}
