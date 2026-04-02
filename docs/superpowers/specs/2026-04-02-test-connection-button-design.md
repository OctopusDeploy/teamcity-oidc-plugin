# Test Connection Button — Design Spec

## Goal

Add a "Test Connection" button to the JWT build feature edit page. When clicked, it opens a modal that progressively verifies the full OIDC stack: JWT issuance, discovery endpoint, JWKS signature verification, and optionally a cloud token exchange.

---

## Scope

- Issue a dry-run JWT using the current (unsaved) form values
- Verify `/.well-known/openid-configuration` is reachable and valid
- Verify `/.well-known/jwks.json` is reachable and that the JWT signature verifies against it
- Optionally: test a token exchange against a cloud service (entered at test time, not saved)

---

## Components

### 1. `JwtTestController`

New `SimpleController` registered at `POST /admin/jwtTest.html`.

**Auth:** Requires `MANAGE_SERVER_INSTALLATION` permission (same check as `KeyRotationController`). Returns HTTP 403 with `{"ok": false, "message": "Access denied"}` if not admin.

**Request params (all steps):**
- `step` — one of `jwt`, `discovery`, `jwks`, `exchange`

**Additional params by step:**
- `jwt`: `algorithm` (RS256/ES256), `ttl_minutes`, `audience`
- `jwks`: `token` (the JWT string from the `jwt` step)
- `exchange`: `token`, `serviceUrl`, `audience` (reused from the form — doubles as the ExternalId for Octopus)

**Response:** `application/json`
```json
{"ok": true, "message": "JWT issued (kid: abc123, alg: RS256, ttl: 10m)"}
{"ok": false, "message": "Could not reach /.well-known/jwks.json — ConnectException"}
```

**Step behaviour:**

| Step | Logic | Success message |
|------|-------|----------------|
| `jwt` | Issue a signed JWT using `JwtBuildFeature.getRsaKey()`/`getEcKey()`. Uses a synthetic subject (`test`), issuer from `buildServer.getRootUrl()`, and the supplied TTL/audience. Fails fast if rootUrl is not HTTPS. | `JWT issued (kid: {kid}, alg: {alg}, ttl: {ttl}m)` |
| `discovery` | HTTP GET `{rootUrl}/.well-known/openid-configuration`. Parses response as JSON, checks `issuer` field matches rootUrl. 5-second connect/read timeout. | `Discovery endpoint OK (issuer matches)` |
| `jwks` | HTTP GET `{rootUrl}/.well-known/jwks.json`. Parses as `JWKSet`. Finds key by `kid` from token header. Verifies token signature. | `JWKS OK — signature verified` |
| `exchange` | Fetch the token endpoint by GETting `{serviceUrl}/.well-known/openid-configuration` and reading its `token_endpoint` field. Then POST to that endpoint with `Content-Type: application/json` body: `{"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","audience":"{audience}","subject_token":"{token}","subject_token_type":"urn:ietf:params:oauth:token-type:jwt"}`. The `audience` value comes from the form (= Octopus ExternalId). Reports HTTP status and first 200 chars of response body. | `Exchange succeeded (HTTP 200)` |

**Error cases:**
- Root URL not HTTPS → `step=jwt` fails: `"Root URL is not HTTPS — OIDC endpoints won't be reachable"`
- Network failure on discovery/JWKS → friendly message including the exception type and rootUrl
- `kid` not found in JWKS → `"Key ID not found in JWKS (kid: {kid})"`
- Signature verification fails → `"Signature verification failed"`
- Exchange non-2xx → `"Exchange failed (HTTP {status}): {first 200 chars of body}"`

### 2. JSP + JS (`editJwtBuildFeature.jsp`)

**Button:** A "Test Connection" button added below the existing form fields.

**Modal:** A hidden `<div>` overlaying the form, containing:
- 3 result rows (jwt, discovery, jwks), each initially showing `○ Pending`
- An exchange section below a divider: a text input labelled **"Service URL"** (e.g. `https://octopus.example.com`) and a "Try Exchange" button (disabled until step 3 passes)
- A "Close" button always visible

**JS flow:**
1. Click "Test Connection" → show modal, reset all rows to `○ Pending`
2. Read current form field values for `algorithm`, `ttl_minutes`, `audience`
3. POST `step=jwt` with form values → update row 1 with result
4. If ok: POST `step=discovery` → update row 2
5. If ok: POST `step=jwks` with `token=<jwt>` → update row 3; enable exchange input
6. If user enters a Service URL and clicks "Try Exchange": POST `step=exchange` with `token`, `serviceUrl`, and `audience` (from form) → update row 4

Each row updates immediately when its response arrives. On failure, subsequent rows remain greyed out. The JWT string is held in a JS local variable between steps — it is not stored server-side.

### 3. Spring XML

One new bean in `build-server-plugin-jwt-plugin.xml`:

```xml
<bean id="jwtTestController" class="de.ndr.teamcity.JwtTestController"/>
```

The plugin XML uses `default-autowire="constructor"`, so TC will inject `JwtBuildFeature` and `SBuildServer` automatically.

---

## What Is Not Stored

The Service URL and the test JWT are transient — they exist only in the browser session during the test. Nothing is written to disk or the TC database.

---

## Testing

Unit tests for `JwtTestController`:
- `step=jwt` with RS256 returns a valid signed JWT
- `step=jwt` with ES256 returns a valid signed JWT
- `step=jwt` with non-HTTPS rootUrl returns `ok: false`
- `step=discovery` with a mock HTTP server returning valid discovery JSON returns `ok: true`
- `step=discovery` with wrong issuer returns `ok: false`
- `step=jwks` with a valid token verifies successfully
- `step=jwks` with a tampered token returns `ok: false`
- `step=exchange` with a mock server serving discovery + token endpoint returning 200 returns `ok: true`
- `step=exchange` with a mock token endpoint returning 401 returns `ok: false` with status in message
- `step=exchange` with a mock discovery doc missing `token_endpoint` returns `ok: false`
- Non-admin request returns HTTP 403

No JS/browser tests — the JS is thin glue; the logic lives in the controller.
