package com.octopus.teamcity.oidc.it;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;

/**
 * Tiny JSON-parsing helper shared across the integration tests. Wraps the checked
 * {@link net.minidev.json.parser.ParseException} in an unchecked one so call sites stay terse.
 */
final class Json {

    private Json() {
    }

    static JSONObject parse(final String body) {
        try {
            return (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(body);
        } catch (final net.minidev.json.parser.ParseException e) {
            throw new IllegalStateException("Failed to parse JSON: " + body, e);
        }
    }
}
