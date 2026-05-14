# TeamCity OIDC Plugin — Developer Notes

## Java environment

jenv manages Java but does not set `JAVA_HOME` by default. Use the symlink path directly
(avoid `$(jenv javahome)` — the subcommand triggers a confirmation prompt):

```bash
JAVA_HOME=/Users/matt/.jenv/versions/21 mvn <goals>
```

## Building

Build the plugin zip from the **root module** (required before running integration tests).
Do NOT use `mvn clean` before `mvn verify` — it deletes the zip and the test will crash:

```bash
JAVA_HOME=/Users/matt/.jenv/versions/21 mvn package -DskipTests
```

Run unit tests only:

```bash
JAVA_HOME=/Users/matt/.jenv/versions/21 mvn test -pl oidc-plugin-server
```

## Manual testing with a live stack

Spins up TeamCity + Octopus + a Caddy TLS proxy via Testcontainers.
Always build the zip first (`mvn package -DskipTests` from root), then:

```bash
TESTCONTAINERS_RYUK_DISABLED=true \
JAVA_HOME=/Users/matt/.jenv/versions/21 \
mvn verify -pl integration-tests -Dit.test=OidcFlowIT#manualTestingPause -Dmanual \
  > /tmp/it-manual.log 2>&1 &
```

Wait for the "Stack is ready" banner in the log:

```bash
tail -f /tmp/it-manual.log
```

The banner prints the TeamCity URL, super user token, Octopus URL, and API key.

### Prerequisites

Add to `/etc/hosts` (once):

```
127.0.0.1  teamcity-tls  teamcity-public-tls  octopus-tls
```

### Logging in via Chrome MCP

TeamCity exposes two ports:
- **Caddy (HTTPS)** — `https://teamcity-tls:<caddy-port>` (self-signed cert, browser will warn)
- **TC direct (HTTP)** — `http://localhost:<tc-port>` — use this to avoid cert issues with Chrome MCP

Find the direct HTTP port:

```bash
docker ps --format "{{.Names}}: {{.Ports}}" | grep teamcity
```

Get the super user token from logs:

```bash
docker logs <teamcity-container-name> 2>&1 | grep "Super user authentication token"
```

Navigate in Chrome MCP:
1. Open `http://localhost:<tc-port>/login.html?super=1`
2. Enter the super user token (empty username)
3. Navigate to the build feature edit page via:
   - Admin → Projects → OidcTest → Edit (OidcTest Build) → Build Features → Edit

### Tearing down

```bash
docker ps --format "{{.Names}}" | grep "jwt-it-" | xargs docker rm -f
```

Also kill the background Maven process.

## Code style

**Java:** Always use `final var` for local variables.

**JavaScript:**
- Use `const` for variables that are not reassigned, `let` otherwise. Never use `var`.
- Prefer arrow functions (`(x) => ...`) over `function(x) { ... }` for callbacks and any code that doesn't need its own `this` binding.
- Prefer modern array methods: `arr.includes(x)` over `arr.indexOf(x) !== -1`; destructure where it reads cleaner (e.g. `([k, v]) => ...` instead of `(e) => e[0] + e[1]`).

## TeamCity's built-in escaping

TeamCity automatically HTML-escapes output in several rendering contexts:

- `BuildFeature.describeParameters()` return value
- `props:textProperty` tag `value` attribute

Do not add explicit escaping (e.g. `HtmlUtils.htmlEscape()`, `fn:escapeXml()`) on values
passed into these — it produces double-escaped output.

Raw HTML contexts (plain `<input>`, `<span>` content, `data-` attributes) are **not**
automatically escaped and still require `fn:escapeXml()` explicitly.

## Commits and Pull Requests

Do not use conventional commit prefixes (e.g. `fix:`, `feat:`, `chore:`) in commit messages or PR titles.

## Pull Request Descriptions

PR descriptions must always include:

- **Background**: The high level of why the change is needed — the user-facing problem or motivation
- **Details**: The details of the problem
- **Results**: What was changed and how it fixes the problem
- **Screenshots**: Include before/after screenshots where the change affects the UI. Screenshots must be uploaded by the human — Claude cannot upload binary files to GitHub. Take the screenshots (saving them to `/tmp/`), tell the human the file paths, and ask them to drag-and-drop the images into the PR description on GitHub.

Create PRs in draft, so that human review is required before saying they are ready.

## Do not commit

- `OIDC-PLAN.md`
- `build-and-run-tests.sh`
- `docs/superpowers/` (superpowers skill docs)
