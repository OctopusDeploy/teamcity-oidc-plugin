package com.octopus.teamcity.oidc;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

public class ConnectionInlineFieldCleanerTest {

    private static OidcConnection connectionWithTtl(final int ttl) {
        return new OidcConnection("conn-id", "proj", "Display",
                new IssuanceSettings("api://conn", ttl, "ES256", Set.of("branch")), "conn.token");
    }

    @Test
    public void removesAuthoritativeFields() {
        final var params = new HashMap<>(Map.of(
                "connection_id", "conn-id",
                "audience", "api://feature",
                "algorithm", "RS256",
                "subject_dimensions", "trigger_type",
                "token_variable_name", "my.token"));

        ConnectionInlineFieldCleaner.stripInheritedFields(params, connectionWithTtl(60));

        assertThat(params).doesNotContainKeys("audience", "algorithm", "subject_dimensions");
        assertThat(params).containsEntry("connection_id", "conn-id");
        assertThat(params).containsEntry("token_variable_name", "my.token");
    }

    @Test
    public void removesTtlWhenEqualToConnection() {
        final var params = new HashMap<>(Map.of("connection_id", "conn-id", "ttl_minutes", "60"));
        ConnectionInlineFieldCleaner.stripInheritedFields(params, connectionWithTtl(60));
        assertThat(params).doesNotContainKey("ttl_minutes");
    }

    @Test
    public void removesTtlWhenBlank() {
        final var params = new HashMap<>(Map.of("connection_id", "conn-id", "ttl_minutes", "  "));
        ConnectionInlineFieldCleaner.stripInheritedFields(params, connectionWithTtl(60));
        assertThat(params).doesNotContainKey("ttl_minutes");
    }

    @Test
    public void keepsTtlWhenItDiffersFromConnection() {
        final var params = new HashMap<>(Map.of("connection_id", "conn-id", "ttl_minutes", "10"));
        ConnectionInlineFieldCleaner.stripInheritedFields(params, connectionWithTtl(60));
        assertThat(params).containsEntry("ttl_minutes", "10");
    }

    @Test
    public void keepsMalformedTtl() {
        // Non-blank and unparseable: leave it so it is not silently dropped; the runtime
        // inherits the connection's TTL for malformed values.
        final var params = new HashMap<>(Map.of("connection_id", "conn-id", "ttl_minutes", "abc"));
        ConnectionInlineFieldCleaner.stripInheritedFields(params, connectionWithTtl(60));
        assertThat(params).containsEntry("ttl_minutes", "abc");
    }
}
