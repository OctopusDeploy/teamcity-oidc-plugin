package com.octopus.teamcity.oidc;

import org.jetbrains.annotations.Nullable;

public final class OidcUrlUtils {

    private OidcUrlUtils() {}

    public static boolean isHttpsUrl(@Nullable final String url) {
        if (url == null) return false;
        try {
            final var uri = new java.net.URI(url);
            return "https".equals(uri.getScheme())
                    && uri.getHost() != null && !uri.getHost().isEmpty();
        } catch (final java.net.URISyntaxException e) {
            return false;
        }
    }

    /** Strips trailing slashes from a root URL. Cloud providers compare issuer by exact string. */
    public static String normalizeRootUrl(@Nullable final String url) {
        if (url == null) return null;
        return url.replaceAll("/+$", "");
    }
}
