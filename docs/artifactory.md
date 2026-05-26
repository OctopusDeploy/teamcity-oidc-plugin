# JFrog Artifactory Integration

TeamCity can authenticate to JFrog Artifactory using its [OIDC integration](https://jfrog.com/help/r/jfrog-platform-administration-documentation/openid-connect-integration). Builds exchange the `jwt.token` for a short-lived Artifactory access token without storing any Artifactory credentials in TeamCity.

The flow is:

1. The OIDC Identity Token build feature mints a JWT in the build.
2. The build calls Artifactory's token exchange endpoint, passing the JWT.
3. Artifactory verifies the JWT against TeamCity's JWKS, matches it to an identity mapping, and returns a scoped access token.
4. The build uses the access token to `docker login` and push.

Your TeamCity server must be reachable from Artifactory at `<issuer>/.well-known/openid-configuration` and `<issuer>/.well-known/jwks.json` — Artifactory fetches the JWKS to verify token signatures.

## Setup

### 1. Create an OIDC integration in Artifactory

In the JFrog Platform UI, go to **Administration → General Management → Manage Integrations → OpenID Connect → New Integration**.

- **Provider name:** a stable identifier (e.g. `teamcity`). You will reference this in the token exchange call.
- **Provider type:** Generic OpenID Connect
- **Provider URL:** your TeamCity root URL (e.g. `https://teamcity.example.com`), or the value of **Override issuer URL** if one is configured under Administration → OIDC / JWT. No trailing slash.
- **Audience:** a stable string of your choice (e.g. `jfrog-artifactory`). You will enter the same value in the build feature.

You will add an identity mapping in step 3; the identity mapping references the subject scope provided in the next step.

### 2. Add the OIDC Identity Token build feature configuration in TeamCity

In the TeamCity UI, add the OIDC Identity Token build feature to a build configuration.

Configure it with the following values:

- **Audience:** the same value you entered for the integration (e.g. `jfrog-artifactory`)
- **Algorithm:** RS256 (default)
- **Token lifetime:** 5–10 minutes is plenty of time as this is used once to mint the Artifactory token.
- **Subject scoping:** leave both off to start, so `sub` is the minimal `project:<id>:build_type:<id>` form. Opt in to `branch` later if you want to restrict to specific branches. See [Restricting access further](#restricting-access-further).

The configuration will give a `resulting sub claim` value that should be used as the subject value in the identity mapping.

### 3. Add an identity mapping in Artifactory

Identity mappings restrict which tokens this integration will accept and define the permissions the resulting access token receives. On the integration you created in the Artifactory UI, click **Add Identity Mapping**.

- **Name:** a descriptive label (e.g. `teamcity-myapp-backend`)
- **Priority:** `1` (lower numbers are evaluated first; put tighter rules ahead of broader ones)
- **Claims (JSON):**

  ```json
  {
    "iss": "https://teamcity.example.com",
    "aud": "jfrog-artifactory",
    "sub": "project:project7:build_type:bt42"
  }
  ```

  Replace `iss` with your actual issuer URL and `sub` with `project:<project_internal_id>:build_type:<build_type_internal_id>` for the build you want to trust. The internal IDs are visible in the build type URL (`.../buildType/bt42`) and are immutable across renames. JFrog supports `*` wildcards in claim values, so `"sub": "project:project7:build_type:*"` trusts any build type in that project.

- **Token scope:** `applied-permissions/groups` is the recommended scope — select a group that has push rights to the target Docker repository. Avoid `applied-permissions/admin`.
- **Token expiry:** match your typical build duration (e.g. `1800` seconds).

Add one identity mapping per build type that needs access, or a single mapping with a wildcard `sub` if a whole project should share permissions.

## Using the token in build steps

Exchange the JWT for an Artifactory access token, then use it with `docker login`:

```bash
#!/usr/bin/env bash
set -euo pipefail

JFROG_URL="https://mycompany.jfrog.io"
DOCKER_REGISTRY="mycompany.jfrog.io"
DOCKER_REPO="docker-local"
IMAGE="myapp:%build.number%"

# Exchange the TeamCity JWT for a short-lived Artifactory access token
ACCESS_TOKEN=$(curl -fsS -X POST \
  "${JFROG_URL}/access/api/v1/oidc/token" \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\": \"urn:ietf:params:oauth:grant-type:token-exchange\",
    \"subject_token_type\": \"urn:ietf:params:oauth:token-type:id_token\",
    \"subject_token\": \"%jwt.token%\",
    \"provider_name\": \"teamcity\"
  }" | jq -r .access_token)

# The Docker login username is the subject of the issued Artifactory token.
# Decode the JWT payload to read it without hard-coding the mapped username.
DOCKER_USER_FULL=$(echo "${ACCESS_TOKEN}" | cut -d. -f2 | base64 -d 2>/dev/null | jq -r .sub)
# trim Docker user string to just the username
DOCKER_USER="${DOCKER_USER_FULL##*users/}"

echo "${ACCESS_TOKEN}" | docker login "${DOCKER_REGISTRY}" \
  --username "${DOCKER_USER}" \
  --password-stdin

docker build -t "${DOCKER_REGISTRY}/${DOCKER_REPO}/${IMAGE}" .
docker push "${DOCKER_REGISTRY}/${DOCKER_REPO}/${IMAGE}"
```

Notes:

- `provider_name` in the POST body must match the OIDC integration name in JFrog exactly.
- The TeamCity JWT only needs to be valid at the point of the exchange call, so a 5–10 minute TTL is plenty even for long builds. The returned Artifactory access token has its own expiry (set on the identity mapping).
- `%jwt.token%` is a masked parameter, so its value is redacted in build logs.
- `DOCKER_REGISTRY` can be either path-style (`mycompany.jfrog.io`) or repo-subdomain style (`mycompany-docker-local.jfrog.io`), depending on how your JFrog Platform is set up.

### Using the JFrog CLI

If you prefer the JFrog CLI, it handles the token exchange and Docker authentication for you. After installing `jf` on the agent:

```bash
jf c add teamcity \
  --url "${JFROG_URL}" \
  --access-token "${ACCESS_TOKEN}" \
  --interactive=false

jf docker push "${DOCKER_REGISTRY}/${DOCKER_REPO}/${IMAGE}" --build-name=myapp --build-number=%build.number%
```

## Restricting access further

To restrict by branch or trigger type, opt in to those dimensions in the build feature's **Subject scoping** configuration. The plugin will then append them to the `sub` claim, which lets you match them in the identity mapping. For example, to restrict pushes to builds of `main` triggered by a real user (with both `branch` and `trigger_type` enabled):

```json
{
  "iss": "https://teamcity.example.com",
  "aud": "jfrog-artifactory",
  "sub": "project:project7:build_type:bt42:branch:refs/heads/main:trigger_type:user"
}
```

To match any branch under `refs/heads/` but still require a user trigger, use a wildcard:

```json
{
  "sub": "project:project7:build_type:bt42:branch:refs/heads/*:trigger_type:user"
}
```

See the [Subject claim](configuration.md#subject-claim) section of the Configuration Reference for the full grammar and the values each dimension can take.

## "Try Exchange" does not work with Artifactory

The build feature editor's **Try Exchange** button targets [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693)-conforming OIDC token endpoints. It will fail against Artifactory for two separate reasons:

1. **The button discovers before it exchanges.** It only asks for a base "Service URL" and then probes `<serviceUrl>/.well-known/openid-configuration` to locate the token endpoint. Artifactory is an OIDC consumer, not an issuer, so it doesn't publish a discovery document — the probe 404s and the exchange step is never reached.
2. **The request shape differs from RFC 8693.** Even if discovery were skipped, the exchange call itself would still fail:

   | | RFC 8693 (what the button sends) | JFrog `/access/api/v1/oidc/token` |
   |---|---|---|
   | Content-Type | `application/x-www-form-urlencoded` ([RFC 6749 §3.2](https://datatracker.ietf.org/doc/html/rfc6749#section-3.2)) | `application/json` |
   | `subject_token_type` | `urn:ietf:params:oauth:token-type:jwt` | `urn:ietf:params:oauth:token-type:id_token` |
   | Provider selection | Single token endpoint per issuer | Requires a `provider_name` field naming the configured integration |

Verify the integration with a real build step using the `curl` example above instead.

## Troubleshooting

- `curl -fsS https://teamcity.example.com/.well-known/openid-configuration` should return JSON from a host that can reach Artifactory. If JFrog cannot fetch this or the JWKS, the token exchange fails with a signature-verification error.
- `invalid subject token issuer` from the exchange endpoint means the `iss` claim in the JWT does not match the **Provider URL** on the integration. Check for trailing slashes and `http` vs `https` mismatches.
- `no identity mapping found` means the JWT verified but no mapping matched. Decode the token at jwt.io and compare every claim against the mapping JSON; the comparison is exact apart from `*` wildcards.
- If `docker push` returns `unauthorized` despite a successful login, check the group selected on the identity mapping — it must have **Deploy/Cache** permission on the target Docker repository.
