package com.octopus.teamcity.oidc;

import org.jetbrains.annotations.NotNull;

import java.util.Map;

/**
 * Removes connection-inherited fields from a feature's saved params so config keeps only genuine
 * per-feature values. {@code audience}, {@code algorithm}, and {@code subject_dimensions} are
 * connection-authoritative and always removed; {@code ttl_minutes} is removed only when blank or
 * equal to the connection's TTL (a differing value persists as an override). {@code connection_id}
 * and {@code token_variable_name} are kept.
 */
public final class ConnectionInlineFieldCleaner {

    private ConnectionInlineFieldCleaner() {
    }

    public static void stripInheritedFields(@NotNull final Map<String, String> params,
                                            @NotNull final OidcConnection connection) {
        params.remove("audience");
        params.remove("algorithm");
        params.remove("subject_dimensions");

        final var rawTtl = params.getOrDefault("ttl_minutes", "").trim();
        if (rawTtl.isBlank()) {
            params.remove("ttl_minutes");
            return;
        }
        try {
            if (Integer.parseInt(rawTtl) == connection.settings().ttlMinutes()) {
                params.remove("ttl_minutes");
            }
        } catch (final NumberFormatException ignored) {
            // Unparseable: keep it, don't silently drop what the admin typed; runtime inherits the connection TTL.
        }
    }
}
