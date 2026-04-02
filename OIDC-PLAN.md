# TeamCity OIDC Provider — Implementation Plan

Goal: Evolve the JWT plugin POC into a fully-fledged OIDC provider so TeamCity builds can
authenticate to cloud services (GCP, AWS, Azure) without static credentials.

---

## Current State

The POC generates RS256-signed JWTs and injects them as `env.JWT` at build start.
It has a functional core but is not production-safe and is incomplete as an OIDC provider.

---

## Bug Fixes (must fix before anything else)

- [x] **NPE on automated triggers** — `build.getTriggeredBy().getUser()` is null for VCS/schedule/
      dependency triggers. Fix: null-guard `triggered_by_id` claim.
- [x] **Branch claim is a `Branch` object** — `build.getBranch()` returns a `Branch`, not a `String`.
      Fix: use `build.getBranch().getName()` (null-guarded). This is critical for cloud IAM policy
      matching (e.g. `attribute.branch == "refs/heads/main"`).
- [x] **Unsafe HTTPS coercion** — `.replaceFirst("http://", "https://")` can corrupt the issuer URL.
      Fix: use the configured root URL as-is; require it to be HTTPS, fail fast with a clear error
      if not.

---

## Security Hardening

- [x] **Private key plaintext on disk** — `key.json` stores the full RSA private key unencrypted.
      Options (in order of preference):
      - Integrate with a secrets manager (Vault, AWS Secrets Manager, GCP KMS)
      - Store in a PKCS12 Java KeyStore with a strong password
      - At minimum: restrict file to owner-read/write only (`chmod 600` equivalent via
        `Files.setPosixFilePermissions`)
- [x] **JWT visible in build parameters** — `addSharedParameter("env.JWT", ...)` exposes the token
      in the TeamCity UI and potentially build logs. Investigate masked parameter type or alternative
      injection mechanism.
- [x] **Token TTL** — Configurable per build feature instance via `ttl_minutes` parameter.
      Default: 10 minutes.
- [x] **File permissions on key.json** — Enforce `chmod 600` immediately after write.
- [x] **Remove unused `jjwt` dependency** — Only Nimbus is used; jjwt is dead weight.

---

## OIDC Provider Implementation

For tokens to work as proper OIDC tokens, the server must implement the OIDC discovery protocol.

- [x] **OIDC Discovery endpoint** — Serve `GET /.well-known/openid-configuration` (or a
      TeamCity-rooted equivalent) returning a discovery document:
      ```json
      {
        "issuer": "https://<teamcity-host>",
        "jwks_uri": "https://<teamcity-host>/.well-known/jwks.json",
        "id_token_signing_alg_values_supported": ["RS256"],
        "response_types_supported": ["id_token"],
        "subject_types_supported": ["public"],
        "claims_supported": ["sub", "iss", "aud", "iat", "exp", "branch", ...]
      }
      ```
- [x] **Public JWKS endpoint** — Serve `GET /.well-known/jwks.json` publicly (no auth required),
      returning the current public key(s). Cloud providers poll this URL to validate token
      signatures.
- [x] **Key rotation support** — During rotation, serve both old and new public keys in the JWKS
      for an overlap window (e.g. 24 hours). Use key thumbprint as `kid` instead of fixed
      `"teamcity"` string.

---

## Key Management

- [x] **Key ID from thumbprint** — Replace fixed `kid = "teamcity"` with
      `RSAKey.computeThumbprint()` so the `kid` is stable and derived from key material.
- [x] **Key rotation mechanism** — Admin action to generate a new key, with overlap period where
      both keys are present in JWKS. Old key retired after configurable window.
- [ ] **Key rotation schedule** — Optional: automatic rotation on a configurable interval.

---

## Claims & Token Quality

- [ ] **Add `jti` claim** — Unique per-token identifier (build ID + random nonce) to support replay
      detection and future revocation.
- [x] **Configurable audience** — Allow the `aud` claim to be set per build feature instance
      (cloud providers often require a specific audience value).
- [x] **Configurable claims** — Let build feature config select which claims to include
      (branch, project, triggered_by, etc.) to minimise token surface.
- [x] **Algorithm choice** — Consider supporting ES256 (ECDSA P-256) as an alternative to RS256;
      better performance and smaller tokens, widely supported by cloud providers.

---

## Build Feature UX

- [x] **Configurable TTL** — Input field for token lifetime (default: 10 minutes).
- [x] **Configurable audience** — Input field for `aud` claim value.
- [x] **Validation on save** — Check that the TeamCity root URL is HTTPS before allowing the
      feature to be enabled.
- [ ] **Test connection button** — Add a "Test" button to the build feature config page that
      triggers a dry-run JWT issuance and verifies the OIDC discovery/JWKS endpoints are
      reachable, so operators can confirm the setup works before running a real build.

---

## Cloud Provider Integration Guides

- [ ] Document Azure Workload Identity setup
- [ ] Document AWS IAM OIDC provider setup
- [ ] Document TerraformCloud Workload Identity Federation setup
- [ ] Document Octopus Workload Identity Federation setup
- [ ] make it easy for people to discover how to do this - general info on the build feature page? links to docs on the build feature page? 

---

## Build & Toolchain

- [ ] **Rename package namespace** — Change `de.ndr.teamcity` to `com.octopus.teamcity` (or
      appropriate subdomain) throughout all source files and the Spring bean XML config.
- [x] **Update Java version** — Upgraded to Java 21. Replaced `mockito-inline` with
      `mockito-core` (inline mocking is now built in). Added `--add-opens java.base/java.lang`
      and `-Dnet.bytebuddy.experimental=true` to Surefire to handle ByteBuddy/Java 21
      compatibility with the TeamCity test-support jar.
- [ ] Add dependabot

---

## Code Review Findings (2026-03-30)

### Critical

- [x] **Discovery document omits ES256** — `/.well-known/openid-configuration` always advertises
      only `["RS256"]`; cloud providers reject ES256-signed tokens even though the EC public key is
      in the JWKS. Fix: advertise both `["RS256", "ES256"]`.
- [x] **`rotateKey()` is not atomic** — four sequential file writes then four sequential field
      updates. A crash mid-way leaves disk and memory in inconsistent states. Fix: generate both
      new keys first, write all four files, then update all four fields; wrap field updates in a
      `synchronized` block (or use an `AtomicReference` to an immutable key-material record).

### Important

- [x] **Claims splitting ignores whitespace** — `"branch, build_number"` silently drops
      `build_number`. Fix: `split("\\s*,\\s*")`.
- [x] **No admin trigger for key rotation** — `rotateKey()` exists and is tested but there is no
      HTTP endpoint or UI through which an operator can call it. Added `POST /admin/jwtKeyRotate.html`.
- [x] **Torn state during rotation** — four separate `volatile` writes are not collectively atomic;
      a concurrent JWKS request can see a mixed key state. Fix: `AtomicReference` to an immutable
      `KeyMaterial` record, or `synchronized` on `rotateKey()` and `getPublicKeys()`.
- [x] **Constructor swallows startup errors** — checked exceptions thrown during key loading are
      wrapped by Spring in `BeanCreationException` with the root cause buried. Fix: catch and
      rethrow as `RuntimeException` with a clear message pointing to the plugin data directory.
- [x] **Discovery controller uses Nimbus's internal shaded Gson** — not a public API; may break on
      any Nimbus upgrade. Fix: build the JSON string manually or add an explicit Gson dependency.

### Minor

- [x] **`getKeyDirectory()` calls `mkdirs()` on every invocation** — compute and create the
      directory once at construction time.
- [x] **JSP uses `${param.foo}` instead of `propertiesBean.properties['foo']`** — loses values on
      TeamCity validation re-renders.
- [x] **JWKS and discovery responses have no cache headers** — add `Cache-Control: max-age=300`
      to avoid stale responses post-rotation.
- [x] **`claims_supported` missing from discovery document** — OIDC spec recommends it; some
      cloud provider setup wizards display or use it.

---

## Code Review Findings (2026-04-02)

### Important

- [x] **Duplicate serving logic** — `WellKnownPublicFilter` short-circuits TC's dispatcher so
      `OidcDiscoveryController` and `JwksController` are never reached for `/.well-known/*` paths.
      The OIDC discovery JSON is duplicated in two places and can drift. Fix: either serve both
      endpoints entirely from the filter and remove the Spring controllers, or make the filter
      delegate to the Spring dispatcher for these paths.
- [x] **`OidcDiscoveryController` takes `JwtBuildFeature` but never uses it** — appears to be
      implicit DI ordering. Document the reason or replace with `@DependsOn` in the Spring XML.
- [x] **JSON responses built by string concatenation** — `buildServer.getRootUrl()` and
      `e.getMessage()` are embedded directly into JSON strings in `OidcDiscoveryController`,
      `WellKnownPublicFilter`, and `KeyRotationController`. A malformed root URL or exception
      message with quotes/backslashes will produce invalid JSON. Fix: use Nimbus's bundled
      `net.minidev.json.JSONObject` (already on classpath) or any JSON serializer.
- [x] **Empty `claims` param silently disables all custom claims** — if the claims field is saved
      as an empty string (not absent), `"".split(",")` produces `[""]` and no claims are included.
      Fix: treat blank as equivalent to null — `(claimsParam == null || claimsParam.isBlank())`.
- [x] **`updateParameters()` should not throw** — `BuildStartContextProcessor` throwing an
      uncaught `RuntimeException` has undefined behavior in TC (build may hang or fail with a
      confusing internal error). The HTTPS guard should log a warning and return rather than throw.
- [x] **Integration tests use `octopusdeploy:latest`** — non-deterministic; a new Octopus release
      can silently break the OIDC token exchange test. Pin to a specific version tag.

### Minor

- [ ] **`getKeyDirectory()` is an unnecessary indirection** — the private method just returns the
      `keyDirectory` field; all callers can access it directly.
- [ ] **Logging a 50-char JWT prefix at INFO adds little value** — the prefix is always base64
      header bytes; you can't distinguish tokens from it. Log the `kid` header value instead,
      which is human-meaningful and non-sensitive.
- [x] **Duplicate `ParseException` import in `JwtBuildStartContextTest`** — `java.text.ParseException`
      appears in both the import list and as a fully-qualified name in `throws` clauses. Redundant
      and noisy; remove the fully-qualified occurrences.

---

## Deferred / Out of Scope for Now

- Token revocation list (no standard mechanism; rely on short TTL instead)
- Per-project key isolation (increases operational complexity significantly)
- Dynamic client registration

---

## Reference

- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [RFC 7517 — JSON Web Key (JWK)](https://www.rfc-editor.org/rfc/rfc7517)
- [RFC 7519 — JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519)
- [GCP Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
- [AWS IAM OIDC Identity Providers](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)