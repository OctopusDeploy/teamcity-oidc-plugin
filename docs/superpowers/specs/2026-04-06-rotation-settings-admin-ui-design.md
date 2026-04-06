# Key Rotation Settings Admin UI — Design

## Goal

Add a rotation settings section to the existing "JWT build feature" admin tab so operators can enable/disable automatic key rotation, configure the cron schedule, view current status, and trigger an immediate rotation — all without leaving the page.

## Architecture

### New: `RotationSettingsController`

- Path: `POST /admin/jwtRotationSettings.html`
- Guards: CSRF (`CSRFFilter.validateRequest()`), then `MANAGE_SERVER_INSTALLATION` permission — same pattern as `KeyRotationController`
- Reads `enabled` (boolean) and `cronSchedule` (string) from request parameters
- Validates `cronSchedule` with `CronExpression.parse()` — returns `{ok: false, message: "..."}` JSON on invalid expression
- Saves via `RotationSettingsManager`
- Returns `{ok: true, message: "Settings saved"}` JSON on success
- Registered in Spring XML with constructor autowiring

### Modified: `JwtBuildFeatureAdminPage`

- Inject `RotationSettingsManager` (new constructor parameter, autowired by Spring)
- In `fillModel()`:
  - Load `RotationSettings` via `settingsManager.load()`
  - Compute `nextDue`: if enabled and `lastRotatedAt != null`, call `CronExpression.parse(cronSchedule).next(lastRotatedAt.atZone(UTC).toLocalDateTime())`; format as `"yyyy-MM-dd HH:mm UTC"` or `null`
  - Add to model: `rotationEnabled` (boolean), `cronSchedule` (String), `lastRotatedAt` (formatted String or `"Never"`), `nextDue` (formatted String or `null`)

### Modified: `jwtBuildFeatureSettings.jsp`

New "Key Rotation" section above the existing JWKS block:

```
[ ✓ ] Enable automatic rotation
Schedule: [0 0 3 1 */3 *          ]  [Save]  [Rotate now]
Last rotated: 2026-04-01 03:00 UTC | Next due: 2026-07-01 03:00 UTC
<feedback area — hidden until action taken>
```

- **Save button**: AJAX `POST /admin/jwtRotationSettings.html` with `enabled` + `cronSchedule`; shows success or error inline
- **Rotate now button**: AJAX `POST /admin/jwtKeyRotate.html`; shows success or error inline; on success, refreshes the status line
- Both buttons send the TC CSRF token header (`X-TC-CSRF-Token`)
- Feedback area: one shared `<span>` per button, shown in green (ok) or red (error), cleared on next action

## Data Flow

```
JSP load  →  fillModel()  →  model attributes  →  JSP renders current state
Save click  →  AJAX POST /admin/jwtRotationSettings.html  →  validate + save  →  JSON  →  inline feedback
Rotate now  →  AJAX POST /admin/jwtKeyRotate.html  →  rotate  →  JSON  →  inline feedback + status refresh
```

Status refresh after "Rotate now": update last-rotated display client-side using the current timestamp (no full page reload needed).

## Validation

- Cron schedule: validated server-side with `CronExpression.parse()`; invalid expressions return `{ok: false, message: "Invalid cron: <reason>"}` displayed inline, nothing saved
- Enabled: boolean checkbox, no validation needed

## Error Handling

- Network error or non-200 response: display "Request failed" inline
- Invalid cron: display server error message inline
- Both cases leave existing settings unchanged

## Files

- **Create**: `oidc-plugin-server/src/main/java/com/octopus/teamcity/oidc/RotationSettingsController.java`
- **Create**: `oidc-plugin-server/src/test/java/com/octopus/teamcity/oidc/RotationSettingsControllerTest.java`
- **Modify**: `oidc-plugin-server/src/main/java/com/octopus/teamcity/oidc/JwtBuildFeatureAdminPage.java`
- **Modify**: `oidc-plugin-server/src/test/java/com/octopus/teamcity/oidc/JwtBuildFeatureAdminPageTest.java` (new file if not exists)
- **Modify**: `oidc-plugin-server/src/main/resources/buildServerResources/jwtBuildFeatureSettings.jsp`
- **Modify**: `oidc-plugin-server/src/main/resources/META-INF/build-server-plugin-jwt-plugin.xml`

## Testing

- `RotationSettingsControllerTest`: POST with valid settings saves and returns ok; invalid cron returns error; non-POST returns 405; CSRF failure returns without saving; non-admin returns 403
- `JwtBuildFeatureAdminPageTest`: `fillModel()` populates all four rotation model attributes; `nextDue` is null when disabled; `lastRotatedAt` is "Never" when null
- JSP: no unit test (TC JSP rendering not easily unit-testable); covered by manual smoke test
