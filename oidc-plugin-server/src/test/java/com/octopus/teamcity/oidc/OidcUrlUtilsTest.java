package com.octopus.teamcity.oidc;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class OidcUrlUtilsTest {

    @Test
    public void isHttpsUrlReturnsTrueForHttps() {
        assertThat(OidcUrlUtils.isHttpsUrl("https://example.com")).isTrue();
    }

    @Test
    public void isHttpsUrlReturnsFalseForHttp() {
        assertThat(OidcUrlUtils.isHttpsUrl("http://example.com")).isFalse();
    }

    @Test
    public void isHttpsUrlReturnsFalseForNull() {
        //noinspection ConstantValue
        assertThat(OidcUrlUtils.isHttpsUrl(null)).isFalse();
    }

    @Test
    public void isHttpsUrlReturnsFalseForSchemeOnlyNoHost() {
        assertThat(OidcUrlUtils.isHttpsUrl("https://")).isFalse();
    }

    @Test
    public void isHttpsUrlReturnsFalseForEmptyPathHost() {
        assertThat(OidcUrlUtils.isHttpsUrl("https:///path")).isFalse();
    }

    @Test
    public void isHttpsUrlReturnsFalseForMalformedUrl() {
        assertThat(OidcUrlUtils.isHttpsUrl("not a url")).isFalse();
    }

    @Test
    public void normalizeRootUrlStripsTrailingSlash() {
        assertThat(OidcUrlUtils.normalizeRootUrl("https://example.com/")).isEqualTo("https://example.com");
    }

    @Test
    public void normalizeRootUrlStripsMultipleTrailingSlashes() {
        assertThat(OidcUrlUtils.normalizeRootUrl("https://example.com///")).isEqualTo("https://example.com");
    }

    @Test
    public void normalizeRootUrlLeavesCleanUrlUnchanged() {
        assertThat(OidcUrlUtils.normalizeRootUrl("https://example.com")).isEqualTo("https://example.com");
    }

    @Test
    public void normalizeRootUrlReturnsNullForNull() {
        //noinspection ConstantValue
        assertThat(OidcUrlUtils.normalizeRootUrl(null)).isNull();
    }
}
