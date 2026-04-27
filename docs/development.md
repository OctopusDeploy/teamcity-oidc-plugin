# Development

## Building

```
mvn package -pl oidc-plugin-server -am -DskipTests
```

The plugin zip is written to `target/Octopus.TeamCity.OIDC.1.0-SNAPSHOT.zip`.

See [`CLAUDE.md`](../CLAUDE.md) for full local development instructions including manual testing with a live stack.

## Plugin architecture

### Startup sequence

The key manager cannot decrypt key files until TeamCity's `EncryptionManager` has initialised its encryption strategy, which happens during server startup — after all Spring beans have been constructed. This creates a two-phase startup:

1. **Spring construction** — all plugin beans are instantiated and register themselves with TeamCity extension points. The key manager holds `null` keys; OIDC endpoints return `503 Service Unavailable`.
2. **Server startup event** — TeamCity fires `serverStartup()` on all `BuildServerAdapter` listeners. The key manager loads keys from disk; OIDC endpoints begin serving responses.

```mermaid
sequenceDiagram
    participant Spring as Spring Container
    participant TC as TeamCity Server
    participant KM as JwtKeyManager
    participant Enc as EncryptionManager

    Note over Spring,Enc: Phase 1 — Spring context initialization
    Spring->>KM: new JwtKeyManager(serverPaths, encryption)
    Note over KM: keys = null (isReady() = false)<br/>Encryption strategy not yet active
    Spring->>TC: JwtKeyManagerServerLifecycle registers as BuildServerAdapter
    Spring->>TC: KeyRotationScheduler registers as BuildServerAdapter
    Spring->>TC: WellKnownPublicFilter.registerDelegate() — serves 503 until ready
    Spring->>TC: JwtBuildStartContext.registerExtension() as BuildStartContextProcessor

    Note over Spring,Enc: Phase 2 — TeamCity server startup complete<br/>EncryptionManager encryption strategy now active
    TC->>KM: serverStartup() → notifyTeamCityServerStartupCompleted()
    KM->>KM: cleanupOrphanedTempFiles()
    KM->>Enc: decrypt(key files)
    KM->>KM: loadKeys() — keys now non-null, isReady() = true
    TC->>TC: KeyRotationScheduler.serverStartup()<br/>starts hourly rotation check (1-min initial delay)
    Note over KM: OIDC endpoints now serve responses<br/>Builds can now receive jwt.token
```

> **Hot-deploy note:** When the plugin is deployed to a running server, `serverStartup()` never fires. `KeyRotationScheduler` handles this by checking `buildServer.isStarted()` in its constructor and starting the scheduler immediately if the server is already up. `JwtKeyManagerServerLifecycle` does not have equivalent handling — key loading must be triggered via the TeamCity plugin reload mechanism.
