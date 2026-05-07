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
- [x] **Key rotation schedule** — Optional: automatic rotation on a configurable interval.

---

## Claims & Token Quality

- [x] **Add `jti` claim** — Unique per-token identifier (build ID + random nonce) to support replay
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
- [x] **Test connection button** — Add a "Test" button to the build feature config page that:
  - triggers a dry-run JWT issuance
  - verifies the OIDC discovery/JWKS endpoints are reachable
  - optionally asks for a service id and url (or similar) so that it can go and try and exchange jwt for a token
  - Note: exchange step sends `Content-Type: application/json` (required by Octopus); standard OAuth servers (AWS, Azure, GCP) expect `application/x-www-form-urlencoded` per RFC 8693 — may need per-provider handling in future

---

## Cloud Provider Integration Guides

- [x] Document Azure Workload Identity setup
- [x] Document AWS IAM OIDC provider setup
- [x] Document TerraformCloud Workload Identity Federation setup
- [x] Document Octopus Workload Identity Federation setup
- [ ] make it easy for people to discover how to do this - general info on the build feature page? links to docs on the build feature page? 

## architecture diagrams

- [ ] Flows
- [ ] what other digrams make sense?

---

## Build & Toolchain

- [x] **Rename package namespace** — Change `de.ndr.teamcity` to `com.octopus.teamcity` (or
      appropriate subdomain) throughout all source files and the Spring bean XML config.
- [x] **Update Java version** — Upgraded to Java 21. Replaced `mockito-inline` with
      `mockito-core` (inline mocking is now built in). Added `--add-opens java.base/java.lang`
      and `-Dnet.bytebuddy.experimental=true` to Surefire to handle ByteBuddy/Java 21
      compatibility with the TeamCity test-support jar.
- [x] Add dependabot

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

- [x] **`getKeyDirectory()` is an unnecessary indirection** — the private method just returns the
      `keyDirectory` field; all callers can access it directly.
- [x] **Logging a 50-char JWT prefix at INFO adds little value** — the prefix is always base64
      header bytes; you can't distinguish tokens from it. Log the `kid` header value instead,
      which is human-meaningful and non-sensitive.
- [x] **Duplicate `ParseException` import in `JwtBuildStartContextTest`** — `java.text.ParseException`
      appears in both the import list and as a fully-qualified name in `throws` clauses. Redundant
      and noisy; remove the fully-qualified occurrences.

---

## Security Review Findings (2026-04-04)

### Critical

- [x] **Private keys are only obfuscated, not encrypted** — `EncryptUtil.scramble` uses 3DES with
      a 24-byte key **hardcoded in the TC binary and identical across all TeamCity installations**
      (source-visible in `common-api`). Anyone who has the TC SDK source can decrypt the files.
      The POSIX 0600 permissions are the real protection — the scramble adds nothing against a
      targeted attack. There is no TC-native server-specific persistent encryption key available in
      the SDK (`RSACipher` uses ephemeral in-memory keys lost on restart). Options:
      - **PKCS12 KeyStore + password via environment variable** — real cryptography (PBKDF2 +
        AES-256) with the password injected by the OS service manager (e.g. systemd
        `EnvironmentFile`) so the key material and the password never share the same filesystem
        path. A leaked backup or file-read vulnerability no longer yields the private key.
        Note: if the password is stored in a file next to the keystore this is no better than the
        current hardcoded-key 3DES.
      - **KMS** (Vault, AWS KMS, GCP KMS) — strongest option but operationally complex.
      - **Remove scramble, rely on POSIX 0600 only** — simpler and equally secure in practice;
        makes the actual threat model explicit rather than implying false security.
      - **At minimum**: document that POSIX 0600 is the sole meaningful protection and that the
        scramble provides no additional security, so operators understand the threat model.

### High

- [x] **SSRF in `exchange` test step** — `serviceUrl` is accepted from the HTTP request and used
      to issue an outbound HTTP GET. HTTPS is now required (partially fixed), but there is no
      allowlist and no IMDS/link-local blocking — any internal HTTPS host is still reachable.
      Fixed: DNS resolved at request time; loopback, RFC-1918, and link-local addresses are blocked
      via `InetAddress.isLoopbackAddress/isSiteLocalAddress/isLinkLocalAddress`. An allowlist is
      not implemented (no fixed set of cloud provider IPs to enumerate).
- [x] **No CSRF protection on key rotation** — `POST /admin/jwtKeyRotate.html` performs no
      server-side CSRF token validation. A page visited by a logged-in admin can silently rotate
      keys. `JwtTestController` has the same gap (JSP sends the header but server never validates
      it). Fixed: `CSRFFilter.validateRequest()` called in both controllers before auth check.
- [x] **Algorithm parameter is unconstrained** — `JwtKeyManager.sign()` accepts any string and
      silently falls back to RS256 for anything other than `"ES256"`. Fix: validate that `algorithm`
      is one of the two supported values and reject anything else with a clear error.

### Medium

- [x] **No upper bound on JWT TTL** — `PropertiesProcessor` only requires a positive integer; a
      TTL of one year passes validation. `JwtBuildStartContext` applies no clamping (unlike
      `JwtTestController` which clamps to 1440). Fix: add a reasonable maximum (e.g. 1440 minutes)
      to the properties processor.
- [x] **Token replay is possible until expiry** — `jti` is generated but never tracked server-side.
      A captured token can be replayed freely until it expires. Inherent to stateless JWTs; fixing
      it requires a distributed revocation store (e.g. Redis set of seen `jti` values) which is
      out of scope for this plugin. TTL is now clamped 1–1440 minutes (default 10), limiting the
      replay window. *Risk accepted.*
- [x] **`triggered_by` claim leaks internal TC descriptor strings** — `triggeredBy.getAsString()`
      is an unstable internal format that has historically included user display names, schedule
      expressions, and VCS rule descriptions. Consider omitting or sanitising this claim. *Not a concern.*
- [x] **`serviceUrl` accepts HTTP; live JWT transmitted in plaintext** — no scheme restriction
      combined with the credential exfiltration risk above. Fix: require HTTPS for `serviceUrl`.
- [x] **`stepDiscovery` and `stepJwks` fetch without checking scheme** — `isHttpsUrl()` is not
      called before the internal HTTP fetches in the test steps.

### Low

- [x] **`exchange` step sends a live signed JWT to an operator-supplied URL** — a malicious or
      compromised admin could supply a URL they control and receive a valid token. Mitigations
      applied: private/link-local addresses blocked (SSRF fix); test token TTL hard-capped at
      1 minute regardless of build feature config. Remaining exploitability: requires
      `MANAGE_SERVER_INSTALLATION`, the attacker must also know a valid audience and have an
      existing cloud provider trust relationship configured. Requiring a non-empty audience does
      not help — the attacker simply supplies one. Remaining option: use a `sub`/`jti` prefix that
      no real cloud IAM policy would match (e.g. `test:` prefix on subject). *Risk accepted — the
      exchange step's purpose is to validate the OIDC configuration end-to-end; a prefixed subject
      would defeat that. Attacker already requires superadmin privileges.*
- [x] **Exception messages returned verbatim to the client** — `e.getMessage()` in
      `JwtTestController` may expose file paths or internal topology (`KeyRotationController` is
      already fixed — returns generic "Key rotation failed."). Fix: log server-side; return a
      generic message to the client from `JwtTestController` too.
- [x] **JWKS JSP guard is at page level, not JSP level** — `CHANGE_SERVER_SETTINGS` is checked
      in `JwtBuildFeatureAdminPage.isAvailable()` but not in the JSP itself.
- [x] **Post-rotation JWKS cache lag** — `Cache-Control: max-age=300` means intermediate caches
      may serve stale JWKS for 5 minutes after rotation; newly issued tokens will fail verification.
      Consider lowering to 60 seconds or adding `stale-while-revalidate`.
      (Now `max-age=60, stale-while-revalidate=60`; residual `stale-while-revalidate` risk tracked
      in Security Review 2026-04-18.)

### Info

- [x] **No automatic key rotation schedule** — keys are rotated only manually; indefinite key reuse
      increases blast radius of a compromise. (See existing "Key rotation schedule" item above.)
- [x] **Only one generation of retired keys preserved** — tokens spanning two rotations fail
      verification. Acceptable given short TTLs; documented in README.
- [x] **`triggered_by_id` is a numeric TC user ID** — TC user IDs are not reused after deletion,
      so this is a stable identity. Finding closed as not a concern.
- [x] **Discovery document omits `authorization_endpoint`** — may cause strict OIDC validators to
      reject the document; this provider is non-interactive so the field is not meaningful, but
      some validators require it.
- [x] **RSA key size is 2048 bits** — acceptable per NIST until 2030 but below the 3072+ now
      recommended for new long-lived signing keys. Low priority given the manual rotation path.
- [x] **Test-issued JWTs omit `nbf`** — production tokens include `nbf`; test tokens don't.
      Results from the test step may not accurately reflect production token behaviour at strict
      relying parties.

---

## Code Review Findings (2026-04-18)

### Important

- [x] **`JwtTestController` not declared in Spring XML** — `build-server-plugin-jwt-plugin.xml` lists
      every other bean but not `jwtTestController`. TeamCity instantiates only declared beans, so
      `@Autowired` is never invoked and the endpoint `/admin/jwtTest.html` is never registered.
      The "Test Connection" button in the build feature UI calls a non-existent endpoint.
      Fix: add `<bean id="jwtTestController" class="...JwtTestController"/>`. When doing so, note
      that `stepJwt` issues a real signed JWT for any named build type with no project-level
      authorization check — acceptable at `MANAGE_SERVER_INSTALLATION` but a risk if the permission
      is later lowered to match `CHANGE_SERVER_SETTINGS` (see Permission inconsistency item below).
- [x] **`rotateKey()` lost-update race under concurrent invocations** — The `AtomicReference` prevents
      torn reads but not lost updates. If the scheduler and an admin request call `rotateKey()`
      concurrently, both read the same `current` snapshot, both write files, and the second
      `keys.set()` installs a `KeyMaterial` whose retired slots point to the original keys — not to
      the keys the first caller just generated. Any JWT signed between the two `set()` calls becomes
      unverifiable. Fix: `synchronized` on `rotateKey()`, or a `compareAndSet` loop.
- [x] **`rotateKey()` file writes are not crash-safe** — Four sequential `saveKeyToFile()` calls write
      retired-rsa, retired-ec, new-rsa, new-ec in order. A crash or `IOException` mid-sequence
      leaves the key directory in a state where both the active and retired slots contain the same
      key pair, or RSA and EC keys are from different rotation generations. Fix: write new keys to
      temp files, rename atomically (or write a "rotation in progress" sentinel and handle it on
      startup).
- [x] **`JwtTestController.stepJwt()` does not normalise the root URL** — `buildServer.getRootUrl()`
      is used directly as the JWT issuer and in the `stepDiscovery` comparison, but
      `WellKnownPublicFilter` uses `normalizeRootUrl()` (strips trailing slash) when producing the
      discovery document issuer. If the TC root URL has a trailing slash, the test flow reports a
      spurious "issuer mismatch" error. Fix: call `JwtKeyManager.normalizeRootUrl()` at lines 125
      and 167 of `JwtTestController`.
- [x] **`WellKnownPublicFilter` logs at INFO on every JWKS request** — Cloud providers poll the
      JWKS endpoint frequently. With `max-age=60`, each cache miss per consumer hits the server
      every 60 seconds. INFO-level logging for every such request will flood the TeamCity server
      log. Change to `LOG.fine(...)`.
- [x] **Live signed JWT returned to the browser in the test flow** — `stepJwt` returns the full
      serialized token in the JSON response (`r1.token`) and the JSP stores it in a JavaScript
      variable (`_jwtToken`). The token is a genuine bearer credential with a real signature and
      real `sub`/`iss`/`aud` claims. Any XSS on the TeamCity domain, a malicious browser extension,
      or an intercepting proxy can steal it. Fix: either return only a token fingerprint (header +
      kid) for the UI display, or ensure the `stepJwks` step verifies via a server-side reference
      rather than by re-submitting the raw token. **Fixed in #76** — JWT stored in HTTP session
      under a UUID key; only the GUID reference (`tokenRef`) is sent to the browser. Session
      attribute is removed immediately after use (consume-once).
- [x] **`JwtBuildFeature.describeParameters()` appends audience without HTML escaping** — Not
      required: TeamCity already HTML-escapes the description string returned by
      `describeParameters()` before rendering it in the build configuration overview.
- [x] **Permission inconsistency: `JwtTestController` uses `MANAGE_SERVER_INSTALLATION` while
      `KeyRotationController` and `RotationSettingsController` use `CHANGE_SERVER_SETTINGS`** —
      Key rotation is arguably more sensitive than issuing a test token, yet the test controller
      requires the *highest* TC permission. An admin who can rotate keys cannot run the test flow.
      Align to `CHANGE_SERVER_SETTINGS` and ensure the build-type authZ note above is addressed.
- [x] **`RotationSettingsController.doHandle()` load→save gap loses concurrent `lastRotatedAt` update**
      — The controller calls `settingsManager.load()` and `settingsManager.save()` as two separate
      `synchronized` blocks. If `updateLastRotatedAt()` runs between them (triggered by a concurrent
      auto-rotation), the freshly written timestamp is immediately overwritten by the stale value
      the controller read in its `load()` call. Fix: add a `synchronized` block spanning both calls,
      or add a dedicated `saveEnabledAndSchedule(enabled, cron)` method to
      `RotationSettingsManager` that does the read-modify-write atomically.
- [x] **Joda-Time used in `JwtBuildStartContext` while the rest of the codebase uses `java.time`** —
      `new DateTime()`, `.toDate()`, `.plusMinutes()` (Joda) in `JwtBuildStartContext` is
      inconsistent with `Instant`, `LocalDateTime`, and `ZoneOffset.UTC` used everywhere else.
      Joda-Time has been in maintenance mode since 2014. Replace with `java.time.Instant` /
      `java.time.temporal.ChronoUnit`.
- [x] **Generic `Exception` catch in `JwtBuildParametersProvider`** — `catch (final Exception e)` in
      `getParameters()` and `getParametersAvailableOnAgent()` is overly broad; masks unexpected
      runtime failures that should propagate. Catch specific exception types instead.
- [x] **Unchecked JWK cast in `JwtKeyManager`** — `JWK.parse()` returns a generic `JWK`; the
      subsequent `.toRSAKey()` / `.toECKey()` calls throw `ClassCastException` if persisted key
      type doesn't match expectations. Add explicit type validation or handle the cast failure.
- [x] **Silent exception swallowing in `RotationSettingsManager.load()`** — JSON/Instant parse
      failures are logged at WARN and silently return defaults, hiding data corruption. At minimum
      surface a user-facing error or preserve a backup.
- [x] **TTL parsing swallows `NumberFormatException` without distinguishing config error** —
      `Integer.parseInt()` in `JwtBuildStartContext` is caught by the broad outer handler and logged
      at SEVERE, making configuration mistakes indistinguishable from genuine runtime failures.
      Parse defensively and log a descriptive config error at a lower level.

### Minor

- [x] **`KeyRotationScheduler` starts with `initialDelay=0`** — `checkAndRotateIfDue()` runs
      immediately on server startup. If the cron schedule is overdue (server was down across a
      rotation boundary), RSA 2048-bit key generation and four file writes happen in the startup
      critical path, delaying readiness. Additionally, combined with `stale-while-revalidate=60` on
      the JWKS endpoint, cloud providers may serve the old JWKS for up to 120 seconds post-startup;
      builds queued immediately after restart may have their tokens rejected during that window.
      Use a short initial delay (e.g., `1` minute) to let the server fully start first.
- [x] **`RotationSettings.defaults()` enables auto-rotation with `lastRotatedAt=null`** — On first
      install, `lastRotatedAt=null` is treated as epoch 0 in the scheduler; `cron.next(epoch_0)` is
      always in the past, so combined with `initialDelay=0`, the plugin rotates keys immediately on
      first startup — discarding the keys just generated in the constructor. Either set
      `lastRotatedAt` to `Instant.now()` in `defaults()` or start with `enabled=false`.
- [x] **`HttpClient` in `JwtTestController` is never closed** — `HttpClient` implements
      `AutoCloseable` since JDK 21. The instance created in the constructor holds an internal
      selector thread. If TeamCity hot-reloads the plugin without a JVM restart, the old thread
      leaks. **Fixed in #81** — `destroy()` closes the client; wired via `destroy-method` in
      the Spring XML.
- [x] **Test code imports Nimbus internal shaded Gson** — `WellKnownPublicFilterTest`,
      `KeyRotationTest`, and `OidcDiscoveryComplianceTest` import
      `com.nimbusds.jose.shaded.gson.JsonParser`. **Fixed in #82** — replaced with
      `net.minidev.json` throughout.
- [x] **`maven-compiler-plugin` declared as a `<dependency>` in the parent POM** — Build plugins
      belong in `<build>/<plugins>`, not in `<dependencies>`. **Fixed in #83** — removed from
      `<dependencies>`; it was already correctly declared in `<build><plugins>`.
- [x] **Hardcoded developer path `<teamcityDir>/Users/svs/TeamCity</teamcityDir>` in parent POM** —
      This path only exists on one machine; other developers and CI will silently use a wrong
      TeamCity installation. Externalise to a Maven property with a sensible default or document
      a required environment variable. *(PR #84)*
- [x] **`JwtBuildStartContext` re-throws exception with no added context** — `catch (Exception e)
      { throw e; }` adds no additional context or log entry; the stack trace alone is insufficient
      for diagnosing build failures. **Already fixed** — both catch blocks log at SEVERE with build
      ID and rethrow a generic message.
- [x] **URL construction by string concatenation in `JwtTestController`** — `rootUrl + "/.well-known/...")`
      is fragile if `rootUrl` ever carries a trailing slash or query string. **Fixed in #77** — URI
      decomposition via `wellKnownUrl()` helper; query strings on rootUrl are now safely discarded.
- [x] **Regex compiled on every build start** — `claimsParam.split("\\s*,\\s*")` in
      `JwtBuildStartContext` compiles a regex on every invocation. **Fixed in #78** — hoisted to
      `private static final Pattern CLAIMS_SPLIT`.
- [x] **Silent TTL default on parse failure in `JwtTestController`** — `NumberFormatException`
      silently returns TTL of 10; callers receive no indication their explicit value was ignored.
      **Moot** — `parseTtl` was dead code; `stepJwt` hardcodes TTL to 1 minute. Dead method
      removed.
- [x] **Undocumented default cron expression** — `DEFAULT_SCHEDULE = "0 0 3 1 */3 *"` in
      `RotationSettings` has no inline comment explaining the schedule (3 AM on the 1st of every
      3 months). **Fixed in #80** — added Javadoc comment.
- [x] **`cronSchedule` not validated on load** — `RotationSettingsManager` doesn't validate the
      cron expression when reading from JSON; an invalid value only fails later at runtime.
      **Fixed in #80** — validates with `CronExpression.parse()` on load; falls back to default
      with a warning if invalid.

### Suggestion

- [x] **No test coverage for `JwtBuildFeatureAdminPage.fillModel()`** — The method has meaningful
      logic: JWKS base64 encoding, cron-next computation, null `lastRotatedAt` handling, invalid
      cron handling. A misformatted date or a bad cron expression from `rotation-settings.json`
      would break the admin UI silently. Add a unit test covering the main branches. *(PR #85)*
- [x] **`normalizeRootUrl()` and `isHttpsUrl()` are misplaced on `JwtKeyManager`** — These are
      URL utility methods with nothing to do with key management. They are called by
      `JwtBuildStartContext`, `WellKnownPublicFilter`, `JwtTestController`, and `JwtBuildFeature`,
      creating coupling to the key manager. Extract to a small `OidcUrlUtils` class.

---

## Security Review Findings (2026-04-18)

### High

- [x] **Stored XSS in build feature UI — audience field not escaped** — `editJwtBuildFeature.jsp`
      renders the `audience` value without explicit XML escaping (unlike the `claims` field which
      uses `${fn:escapeXml(...)}`). Investigated: TeamCity's `props:textProperty` tag automatically
      HTML-escapes its `value` attribute before rendering, so no explicit escaping is required.
      Confirmed via live browser test with a `<script>alert(1)</script>` payload — no execution.
      Raw HTML contexts (plain `<input>`, `data-` attributes) are not auto-escaped and still use
      `fn:escapeXml()` explicitly.
- [x] **`rotation-settings.json` written without POSIX permissions** —
      `RotationSettingsManager.save()` uses `FileUtils.writeStringToFile()` with no subsequent
      `Files.setPosixFilePermissions()`, unlike the private keys in `JwtKeyManager`. Any process
      running as a different user on the same host can read the file. Apply `600` permissions
      consistently.

### Medium

- [x] **TTL upper-bound not enforced at JWT signing time** — `JwtBuildFeature.getParametersProcessor`
      rejects TTL > 1440 at UI-save time, but `JwtBuildStartContext.updateParameters` calls
      `Integer.parseInt(params.getOrDefault("ttl_minutes", "10"))` with no clamping. Build feature
      parameters can be manipulated via the TC REST API or through template inheritance, bypassing
      the UI validator. A value of, say, `525600` (one year) is accepted at signing time and
      produces a token valid for a year. Fix: clamp to 1–1440 inside `updateParameters` regardless
      of what the params map contains.
- [x] **`JOSEException` during signing rethrown as `RuntimeException` visible in build log** — If
      key signing fails (e.g., due to a corrupted key), `JwtBuildStartContext` wraps the
      `JOSEException` in a `RuntimeException` and rethrows it. TeamCity may include the exception
      message (which contains algorithm and key details) in the build log visible to the user who
      triggered the build. Fix: log at SEVERE server-side and surface a generic failure message to
      the build log.
- [x] **No validation that claims parameter values are from the allowed set** —
      `JwtBuildStartContext` splits the raw `claims` string and checks membership in
      `enabledClaims`, but never validates that values are from `ALL_CUSTOM_CLAIMS`. Direct XML
      edits to build config can inject arbitrary strings that silently produce no claims, with no
      user-visible error.

### Low

- [x] **No CORS headers on JWKS and discovery endpoints** — `WellKnownPublicFilter` does not emit
      `Access-Control-Allow-Origin: *`. Browser-based OIDC clients that perform dynamic discovery
      or key fetching will fail with CORS errors. This limits compatibility with browser-based
      relying parties. Fix: add `Access-Control-Allow-Origin: *` (these are public read-only
      endpoints with no authentication).
- [x] **Cron parse error message reflected verbatim to the client** — `RotationSettingsController`
      returns `"Invalid cron schedule: " + e.getMessage()` where `e` is from Spring's
      `CronExpression.parse()`. The parser's error messages can expose the Spring version and
      internal class names, assisting fingerprinting. **Accepted** — admin-only endpoint,
      low practical risk.
- [x] **`stale-while-revalidate` window may serve revoked keys post-rotation** —
      `Cache-Control: max-age=60, stale-while-revalidate=60` means caches can serve a stale JWKS
      for up to 60 additional seconds after expiry (120 s total worst-case). Tokens signed with
      a retired key will fail verification during this window. Consider `stale-if-error` instead
      of `stale-while-revalidate`, or reduce the window.
- [x] **`keyManager.getPublicKeys()` result passed to `new JWKSet()` without null check** —
      in `WellKnownPublicFilter`, if `getPublicKeys()` ever returns null, the `JWKSet` constructor
      will throw a `NullPointerException`. Add a defensive null/empty check.

### Info

- [x] **`isHttpsUrl()` uses `startsWith("https://")` without parsing the URL** — Accepts degenerate
      inputs such as `https://` (no host), `https:///path`, or `https://user:pass@host`. The root
      URL is admin-controlled so the risk is low, but a malformed URL would produce syntactically
      valid but semantically wrong `iss` and `jwks_uri` values. Consider validating with
      `URI.create()` and checking `getHost()` is non-null and non-empty.
- [x] **Discovery document issuer derived from `buildServer.getRootUrl()` at request time** — If an
      admin changes the TC root URL after JWTs have been issued, the discovery document's `issuer`
      changes immediately but outstanding JWTs still carry the old `iss`. Cloud providers comparing
      JWT `iss` to the discovery document will reject all in-flight tokens with no warning.
      Document this operational risk prominently. *Risk accepted — rare in practice and not easily
      solvable without persisting the issuer separately.*

---

## Notifications & Observability

- [x] **Slack notifications on deployment failures** — when the deployment fails in Octopus Deploy, send a slack notificaiton. *(PR #86)*

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