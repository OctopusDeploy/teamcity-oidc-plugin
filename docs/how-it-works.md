# How It Works

The plugin hooks into TeamCity's build lifecycle and exposes standard OIDC endpoints. No changes to your build agent or network infrastructure are required.

## JWT issuance

Just before a build is dispatched to an agent, TeamCity calls every registered `BuildStartContextProcessor`. The plugin checks whether the build has an OIDC Identity Token feature configured and, if so, signs a JWT and injects it as the masked parameter `jwt.token`.

```mermaid
sequenceDiagram
    participant TC as TeamCity
    participant Plugin as JwtBuildStartContext
    participant KM as JwtKeyManager

    TC->>Plugin: updateParameters(buildStartContext)
    Plugin->>Plugin: find JWT build features on this build
    alt JWT build feature is configured
        Plugin->>Plugin: read ttl_minutes, algorithm, audience, claims
        Plugin->>Plugin: check root URL is HTTPS
        Plugin->>Plugin: assemble JWT claims<br/>(sub=buildTypeExternalId, iss=rootUrl, aud, iat, exp, …)
        Plugin->>KM: sign(claims, algorithm)
        KM-->>Plugin: SignedJWT
        Plugin->>TC: addSharedParameter("jwt.token", token)
    else no JWT build feature
        Plugin-->>TC: (no-op)
    end
```

## Token verification by relying parties (e.g. cloud providers)

A build step sends `%jwt.token%` to the cloud provider (e.g. as a header or request body). The provider verifies it using the standard OIDC discovery protocol — no prior configuration of public keys is needed.

```mermaid
sequenceDiagram
    participant Build as Build step
    participant CP as Cloud Provider
    participant TC as TeamCity

    Build->>CP: send %jwt.token%
    CP->>TC: GET /.well-known/openid-configuration
    TC-->>CP: {issuer, jwks_uri, …}
    CP->>TC: GET /.well-known/jwks.json
    TC-->>CP: {keys: [current + retired public keys]}
    Note over CP: Parse JWT header → look up key by kid<br/>Verify signature, then validate iss, aud, exp
    alt token valid
        CP-->>Build: access granted
    else token invalid / expired
        CP-->>Build: 401 Unauthorized
    end
```

The JWKS endpoint always includes one generation of retired keys alongside the current keys. Tokens issued just before a rotation continue to verify for the remainder of their TTL.

## OIDC endpoints

The plugin serves two public endpoints (no authentication required):

| Endpoint | Description |
|---|---|
| `GET /.well-known/openid-configuration` | OIDC discovery document |
| `GET /.well-known/jwks.json` | Public key set for signature verification |

The issuer is your TeamCity root URL (e.g. `https://teamcity.example.com`).

Both endpoints return `503 Service Unavailable` during server startup while keys are being loaded.

## Test Connection

![Test Connection](images/screenshot-test-connection.png)

The build feature configuration page includes a **Test Connection** button that runs a four-step verification from the server (not the browser):

1. Issues a test JWT using the current configuration
2. Verifies the OIDC discovery endpoint is reachable and the issuer matches
3. Fetches the JWKS and verifies the token signature
4. Optionally attempts an OIDC token exchange against a target service URL

The raw JWT is stored in the server-side HTTP session and never sent to the browser — only a UUID reference (`tokenRef`) travels between steps. Each step consumes the token reference once and removes it from the session.

```mermaid
sequenceDiagram
    actor Admin
    participant Browser
    participant TC as JwtTestController
    participant OIDC as TeamCity OIDC Endpoints
    participant Svc as External Service

    Admin->>Browser: click "Test Connection"

    Browser->>TC: POST step=jwt
    Note over TC: Issue 1-min JWT<br/>Store in session keyed by tokenRef UUID<br/>JWT never sent to browser
    TC-->>Browser: {ok, tokenRef}

    Browser->>TC: POST step=discovery
    TC->>OIDC: GET /.well-known/openid-configuration
    OIDC-->>TC: discovery document
    Note over TC: Validates issuer == TC root URL
    TC-->>Browser: {ok, "Discovery endpoint OK"}

    Browser->>TC: POST step=jwks&tokenRef=…
    Note over TC: Retrieves JWT from session (consume-once, then removed)
    TC->>OIDC: GET /.well-known/jwks.json
    OIDC-->>TC: JWKS
    Note over TC: Matches JWT kid → verifies signature
    TC-->>Browser: {ok, "JWKS OK — signature verified"}

    opt Service URL provided
        Browser->>TC: POST step=exchange&tokenRef=…
        Note over TC: Retrieves JWT from session (consume-once)<br/>Blocks private/loopback addresses (SSRF mitigation)
        TC->>Svc: GET <serviceUrl>/.well-known/openid-configuration
        Svc-->>TC: {token_endpoint}
        TC->>Svc: POST token_endpoint (RFC 8693 token exchange)
        Svc-->>TC: 200 OK
        TC-->>Browser: {ok, "Exchange succeeded"}
    end
```

> **Permissions:** The test endpoint requires `CHANGE_SERVER_SETTINGS` globally, plus `EDIT_PROJECT` for the specific project. On multi-node HA deployments, sticky sessions must be configured at the load balancer — the session holding the JWT is node-local.
