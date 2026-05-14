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
- **Caddy (HTTPS)** — `https://teamcity-tls:<caddy-port>` (self-signed cert, browser will warn). The Caddy port is auto-allocated and changes on each restart.
- **TC direct (HTTP)** — `http://localhost:18111` in manual mode. The host port is pinned to `18111` so the URL is stable across container restarts (see `MANUAL_TC_HOST_PORT` in `OidcFlowIT`). Use this with Chrome MCP to skip the Caddy self-signed cert warning.

Outside manual mode the direct HTTP port is auto-allocated — find it with:

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

### Iterating on JSP / CSS changes against the running stack

In manual mode the TeamCity direct HTTP port is pinned to `18111` (so the URL stays
constant). The super-user token **regenerates on each restart** — re-fetch it from the
container logs after restarting:

```bash
docker logs <teamcity-container> 2>&1 | grep "Super user authentication token" | tail -1
```

**CSS changes** hot-reload. Push the file and hard-refresh the browser:

```bash
TC=$(docker ps --format "{{.Names}}" | grep teamcity | head -1)
docker cp oidc-plugin-server/src/main/resources/buildServerResources/jwt-admin.css \
  "$TC":/opt/teamcity/webapps/ROOT/plugins/teamcity-oidc-plugin/jwt-admin.css
```

**JSP changes require a TeamCity restart.** Pushing the JSP file alone is not enough —
Jasper caches the compiled JSP class in JVM memory and does not recheck the source mtime,
so subsequent requests keep serving the stale compiled class even after `docker cp` and
clearing `/opt/teamcity/work/Catalina/...`. Rebuild the zip, copy it into `datadir/plugins`,
and `docker restart` the container:

```bash
JAVA_HOME=/Users/matt/.jenv/versions/21 mvn package -DskipTests
TC=$(docker ps --format "{{.Names}}" | grep teamcity | head -1)
docker cp target/Octopus.TeamCity.OIDC.1.0-SNAPSHOT.zip \
  "$TC":/data/teamcity_server/datadir/plugins/Octopus.TeamCity.OIDC.1.0-SNAPSHOT.zip
docker restart "$TC"
```

Then wait for HTTP 200 on the new port:

```bash
until PORT=$(docker ps --format "{{.Names}}: {{.Ports}}" | grep teamcity | grep -oE "[0-9]+->8111" | grep -oE "^[0-9]+"); \
      [ -n "$PORT" ] && curl -s -o /dev/null -w "%{http_code}" "http://localhost:$PORT/login.html" 2>/dev/null | grep -q "200"; \
      do sleep 3; done; echo "READY $PORT"
```

## Code style

**Java:** Always use `final var` for local variables.

**JSP scriptlets** are the exception: TC's bundled Jasper compiles JSP scriptlets with Java 8 source level, which does not recognise `var`. Use explicit types (`final JwtBuildFeature.SampleClaims samples = ...`) in `<% ... %>` blocks. The `editJwtBuildFeature.jsp` file documents this exception inline.

**JavaScript:** Always use `const` for variables that are not reassigned, `let` otherwise. Never use `var`.

## Plugin JSPs and Spring

`WebApplicationContextUtils.getRequiredWebApplicationContext(application)` returns TeamCity's
**root** web application context, not the plugin's child Spring context — calling
`.getBean(MyPluginBean.class)` on it throws "No WebApplicationContext found" at runtime even
though the JSP compiles cleanly.

To expose a plugin bean to its JSP, add a static accessor on a class the plugin already
registers as a Spring bean (e.g. `JwtBuildFeature`), assign the bean to a `static volatile`
field in the constructor, and call the accessor from the JSP. See
`JwtBuildFeature.maxTokenLifetimeMinutes()` for the pattern.

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
