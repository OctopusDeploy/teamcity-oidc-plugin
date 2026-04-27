# TeamCity OIDC Plugin

A TeamCity plugin that turns your TeamCity server into an OIDC identity provider, enabling workload identity federation with cloud services — no static credentials required.

When a build starts, the plugin issues a signed JWT and injects it as the masked build parameter `jwt.token`. Cloud providers (AWS, Azure, GCP, Octopus Deploy) verify the token against the plugin's public JWKS endpoint and grant access based on the claims it contains. No secrets need to be stored in TeamCity or on the build agent.

## Requirements

- TeamCity 2025.11+
- The TeamCity server root URL must be configured as `https://`

## Installation

Copy the plugin zip to `<TeamCity data directory>/plugins/` and restart TeamCity.

## Setup

1. Add the **OIDC Identity Token** build feature to a build configuration.
2. Configure the audience (`aud`) to match what your cloud provider expects.
3. In your cloud provider, create an OIDC identity that trusts your TeamCity server as the issuer, and configure conditions based on the claims in the token.
4. Reference the token in build steps as `%jwt.token%`.

## Screenshot

![OIDC Identity Token build feature](screenshot-build-features.png)

## Documentation

- [How It Works](docs/how-it-works.md) — JWT issuance lifecycle, OIDC token verification flow, Test Connection
- [Configuration Reference](docs/configuration.md) — build feature fields, token claims, Octopus Deploy integration
- [Key Management](docs/key-management.md) — key rotation, storage, and encryption at rest
- [Development](docs/development.md) — building the plugin, plugin architecture
