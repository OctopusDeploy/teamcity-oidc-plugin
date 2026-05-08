# Configuration Reference

## Build feature

Add the **OIDC Identity Token** build feature to a build configuration. Multiple instances are allowed if you need tokens for different audiences.

![Build feature configuration](images/screenshot-build-feature.png)

| Field | Description |
|---|---|
| Token lifetime | How long the JWT is valid (default 10 minutes). The upper bound is the **Max lifetime** configured under Administration → OIDC / JWT (defaults to 720 minutes / 12 hours). Set this to the minimum needed by your build steps. |
| Audience | Value for the `aud` claim. Cloud providers typically require a specific value (e.g. `api://AzureADTokenExchange` for Azure, the service account ID for Octopus Deploy). Defaults to the TeamCity root URL. |
| Signing algorithm | RS256 (RSA-2048, default), RS384 (RSA-3072), or ES256 (ECDSA P-256). |
| Claims to include | Select which optional claims to include. All are included by default. |

## Token claims

Reference the token in build steps as `%jwt.token%`. It is injected as a masked parameter, so its value is redacted in build logs.

### Standard claims

| Claim | Value |
|---|---|
| `sub` | Build type external ID (e.g. `MyProject_Build`) |
| `iss` | TeamCity root URL |
| `aud` | Configured audience (defaults to TeamCity root URL) |
| `iat` / `nbf` / `exp` | Issued at / not before / expiry (based on configured TTL) |
| `jti` | Unique token ID (`<buildId>-<uuid>`) |
| `build_type_external_id` | Build type external ID (same as `sub`) |
| `project_external_id` | Project external ID |

### Optional claims

| Claim | Description |
|---|---|
| `branch` | Branch name (e.g. `refs/heads/main`). Default-branch builds are reported as the VCS root's configured default branch ref, not TeamCity's `<default>` marker. Omitted from the token entirely when the build has no branch (typically because the build configuration has no VCS root attached). |
| `trigger_type` | How the build was triggered: `user`, `snapshotDependency`, the trigger's `type` parameter (e.g. `vcsTrigger`, `schedulingTrigger`), or `unknown` |

## Cloud provider setup guides

- [AWS](aws.md) — IAM OIDC federation, trust policy, using the token with the AWS CLI/SDK
- [Azure](azure.md) — workload identity federation, federated credentials, Azure PowerShell login
- [Octopus Deploy](octopus-deploy.md) — OIDC identity setup for Octopus Deploy

