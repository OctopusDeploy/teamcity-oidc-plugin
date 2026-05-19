<%@ include file="/include-internal.jsp"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<link rel="stylesheet" href="${pageContext.request.contextPath}/plugins/teamcity-oidc-plugin/jwt-admin.css"/>
<%@ page import="jetbrains.buildServer.serverSide.auth.Permission" %>
<%@ page import="jetbrains.buildServer.web.util.SessionUser" %>
<%@ page import="jetbrains.buildServer.users.SUser" %>
<%
    final SUser currentUser = SessionUser.getUser(request);
    if (currentUser == null || !currentUser.isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS)) {
        response.sendError(javax.servlet.http.HttpServletResponse.SC_FORBIDDEN);
        return;
    }
%>

<div class="jwt-admin">

  <p class="jwt-intro">
    Turns TeamCity into an OIDC provider. During each build, this plugin issues a short-lived,
    cryptographically signed JWT that cloud services can verify against the public keys below -
    so your builds can authenticate without storing long-lived credentials anywhere.
  </p>
  <p class="jwt-intro">
    To use it, add the <strong>OIDC / JWT</strong> build feature to a build configuration.
  </p>
  <p class="jwt-intro">
    Need help? See the setup guides for
    <a href="https://github.com/OctopusDeploy/teamcity-oidc-plugin/blob/main/docs/aws.md" target="_blank" rel="noopener">AWS</a>,
    <a href="https://github.com/OctopusDeploy/teamcity-oidc-plugin/blob/main/docs/azure.md" target="_blank" rel="noopener">Azure</a>, or
    <a href="https://github.com/OctopusDeploy/teamcity-oidc-plugin/blob/main/docs/octopus-deploy.md" target="_blank" rel="noopener">Octopus Deploy</a>.
  </p>

  <%-- ── Section 1: Issuer URL ── --%>
  <div class="jwt-sec">
    <div class="jwt-sec-title">Issuer URL</div>

    <div class="jwt-field-row">
      <div class="jwt-field-label"><label for="overrideIssuerUrl">Override URL</label></div>
      <div class="jwt-field-body">
        <div class="jwt-field-inline">
          <input class="jwt-inp jwt-inp-url" type="text" id="overrideIssuerUrl"
                 value="<c:out value="${overrideIssuerUrl}"/>" placeholder="https://ci.example.com"/>
          <button class="jwt-btn jwt-btn-primary" type="button" onclick="jwtSaveOidcSettings()">Save</button>
          <button class="jwt-btn jwt-btn-danger" type="button" onclick="jwtClearOidcSettings()">Reset to default</button>
        </div>
        <span class="jwt-hint">Leave blank to use the TeamCity root URL. Set this only if TeamCity is behind a reverse proxy and the public-facing URL differs from the root URL.</span>
        <span id="jwtOidcSettingsResult" style="display:none"></span>
      </div>
    </div>

    <div class="jwt-field-row">
      <div class="jwt-field-label">Effective URL</div>
      <div class="jwt-field-body">
        <code class="jwt-effective-url"><c:out value="${effectiveIssuerUrl}"/>/.well-known/openid-configuration</code>
      </div>
    </div>
  </div>

  <%-- ── Section 1b: Token defaults ── --%>
  <div class="jwt-sec">
    <div class="jwt-sec-title">Token defaults</div>

    <div class="jwt-field-row">
      <div class="jwt-field-label"><label for="maxTokenLifetimeMinutes">Max lifetime (minutes)</label></div>
      <div class="jwt-field-body">
        <div class="jwt-field-inline">
          <input class="jwt-inp" type="number" id="maxTokenLifetimeMinutes" min="1"
                 max="<c:out value="${maxTokenLifetimeAbsoluteMax}"/>" style="width:7em;"
                 value="<c:out value="${maxTokenLifetimeMinutes}"/>"/>
          <button class="jwt-btn jwt-btn-primary" type="button" onclick="jwtSaveMaxTokenLifetime()">Save</button>
        </div>
        <span class="jwt-hint">Upper bound on the per-build-feature <code>Token lifetime</code> setting. Default 720 (12h); absolute ceiling <c:out value="${maxTokenLifetimeAbsoluteMax}"/> (24h).</span>
        <span id="jwtMaxTtlResult" style="display:none"></span>
      </div>
    </div>
  </div>

  <%-- ── Section 2: Key Rotation ── --%>
  <div class="jwt-sec">
    <div class="jwt-sec-title">Key Rotation</div>

    <div class="jwt-field-row">
      <div class="jwt-field-label">Auto-rotation</div>
      <div class="jwt-field-body">
        <label class="jwt-checkbox-label">
          <input type="checkbox" id="rotationEnabled" <c:if test="${rotationEnabled}">checked</c:if>>
          Enable automatic rotation
        </label>
      </div>
    </div>

    <div class="jwt-field-row">
      <div class="jwt-field-label"><label for="cronSchedule">Schedule</label></div>
      <div class="jwt-field-body">
        <div class="jwt-field-inline">
          <input class="jwt-inp jwt-inp-cron" type="text" id="cronSchedule"
                 value="<c:out value="${cronSchedule}"/>"/>
          <button class="jwt-btn jwt-btn-primary" type="button" onclick="jwtSaveRotationSettings()">Save</button>
          <button class="jwt-btn" type="button" onclick="jwtRotateNow()">Rotate now</button>
        </div>
        <span class="jwt-hint">6-field cron (sec min hr day month weekday) - e.g. <code>0 0 3 * * SUN</code> = Sundays at 03:00 UTC</span>
        <span id="jwtSaveResult" style="display:none"></span>
        <span id="jwtRotateResult" style="display:none"></span>
        <span id="jwtRotateWarning" style="display:none"></span>
      </div>
    </div>

    <div class="jwt-field-row">
      <div class="jwt-field-label"></div>
      <div class="jwt-field-body">
        <span class="jwt-status-line">
          Last rotated: <span id="jwtLastRotatedDate"><c:out value="${lastRotatedAt}"/></span><span id="jwtWarmupAnnotation"><c:if test="${hasPending}"> (warming up - new key active at <c:out value="${pendingActivateAt}"/>)</c:if></span><c:if test="${not empty nextDue}"> &nbsp;&middot;&nbsp; Next due: <c:out value="${nextDue}"/></c:if>
        </span>
      </div>
    </div>
  </div>

  <%-- ── Section 3: JWKS ── --%>
  <div class="jwt-sec">
    <div class="jwt-sec-title">JWKS</div>

    <div class="jwt-field-row">
      <div class="jwt-field-label"><label for="jwksCacheLifetimeMinutes">Cache lifetime (minutes)</label></div>
      <div class="jwt-field-body">
        <div class="jwt-field-inline">
          <input class="jwt-inp" type="number" id="jwksCacheLifetimeMinutes"
                 min="<c:out value="${jwksCacheLifetimeMin}"/>"
                 max="<c:out value="${jwksCacheLifetimeMax}"/>"
                 style="width:7em;"
                 value="<c:out value="${jwksCacheLifetimeMinutes}"/>"/>
          <button class="jwt-btn jwt-btn-primary" type="button" onclick="jwtSaveJwksCacheLifetime()">Save</button>
        </div>
        <span class="jwt-hint">Sent as the <code>Cache-Control: max-age</code> on the JWKS and discovery endpoints (in seconds = minutes &times; 60), and is also the post-rotation warmup window: a newly-rotated key is published in JWKS immediately but does not sign tokens until this many minutes have passed. Default <c:out value="${jwksCacheLifetimeDefault}"/>; range <c:out value="${jwksCacheLifetimeMin}"/>&#8211;<c:out value="${jwksCacheLifetimeMax}"/>.</span>
        <span id="jwtJwksCacheResult" style="display:none"></span>
      </div>
    </div>

    <div class="jwt-jwks-toolbar">
      <span id="jwtKeyCount" class="jwt-key-count"></span>
      <a class="jwt-btn" id="jwtJwksDownload"
         href="data:application/json;charset=utf-8;base64,${jwksBase64}"
         download="jwks.json" style="display:none">&#x2B07; Download jwks.json</a>
    </div>
    <table class="jwt-key-table" id="jwtKeyTable" style="display:none">
      <thead>
        <tr>
          <th></th>
          <th>Key ID</th>
          <th>Algorithm</th>
          <th>Type</th>
          <th>Use</th>
          <th>Status</th>
          <th>Created</th>
        </tr>
      </thead>
      <tbody id="jwtKeyTableBody"></tbody>
    </table>
  </div>

</div>

<script>
  const jwtContextPath = '${pageContext.request.contextPath}';

  function jwtShowResult(elementId, state, message) {
    const el = document.getElementById(elementId);
    const prefix = state === 'ok' ? '\u2713 ' : state === 'warn' ? '\u26a0 ' : '\u2717 ';
    el.textContent = prefix + message;
    el.className = 'jwt-msg jwt-msg-' + state;
    el.style.display = 'inline-flex';
  }

  const jwtAdminPost = (url, body, onSuccess, onError) => {
    const csrfMeta = document.querySelector('meta[name="tc-csrf-token"]');
    const csrf = csrfMeta ? csrfMeta.getAttribute('content') : '';
    fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-TC-CSRF-Token': csrf
      },
      body: body
    })
    // The controllers return JSON for both success (2xx) and known-case errors
    // (400 validation, 409 warmup-in-progress) — pass the parsed body to
    // onSuccess regardless of status code so callers can render the structured
    // message. Only unexpected failures (network, non-JSON body e.g. 5xx HTML)
    // fall through to onError.
    .then(r => r.json().then(onSuccess, onError))
    .catch(onError);
  };

  const jwtSaveOidcSettings = () => {
    const url = document.getElementById('overrideIssuerUrl').value;
    jwtAdminPost(jwtContextPath + '/admin/jwtOidcSettings.html',
      'overrideIssuerUrl=' + encodeURIComponent(url),
      data => {
        jwtShowResult('jwtOidcSettingsResult', data.state, data.message);
        if (data.state !== 'error') {
          document.getElementById('overrideIssuerUrl').value = url.trim().replace(/\/+$/, '');
        }
      },
      () => jwtShowResult('jwtOidcSettingsResult', 'error', 'Request failed')
    );
  };

  const jwtClearOidcSettings = () => {
    document.getElementById('overrideIssuerUrl').value = '';
    jwtAdminPost(jwtContextPath + '/admin/jwtOidcSettings.html',
      'overrideIssuerUrl=',
      data => jwtShowResult('jwtOidcSettingsResult', data.state, data.message),
      () => jwtShowResult('jwtOidcSettingsResult', 'error', 'Request failed')
    );
  };

  const jwtSaveMaxTokenLifetime = () => {
    const value = document.getElementById('maxTokenLifetimeMinutes').value;
    jwtAdminPost(jwtContextPath + '/admin/jwtOidcSettings.html',
      'maxTokenLifetimeMinutes=' + encodeURIComponent(value),
      data => jwtShowResult('jwtMaxTtlResult', data.state, data.message),
      () => jwtShowResult('jwtMaxTtlResult', 'error', 'Request failed')
    );
  };

  const jwtSaveJwksCacheLifetime = () => {
    const value = document.getElementById('jwksCacheLifetimeMinutes').value;
    jwtAdminPost(jwtContextPath + '/admin/jwtOidcSettings.html',
      'jwksCacheLifetimeMinutes=' + encodeURIComponent(value),
      data => jwtShowResult('jwtJwksCacheResult', data.state, data.message),
      () => jwtShowResult('jwtJwksCacheResult', 'error', 'Request failed')
    );
  };

  const jwtSaveRotationSettings = () => {
    const enabled = document.getElementById('rotationEnabled').checked;
    const schedule = document.getElementById('cronSchedule').value;
    jwtAdminPost(jwtContextPath + '/admin/jwtRotationSettings.html',
      'enabled=' + enabled + '&cronSchedule=' + encodeURIComponent(schedule),
      data => jwtShowResult('jwtSaveResult', data.state, data.message),
      () => jwtShowResult('jwtSaveResult', 'error', 'Request failed')
    );
  };

  // Format an instant (Date or ISO-8601 string) as 'YYYY-MM-DD HH:MM UTC' to match
  // the server-side rendering (see JwtBuildFeatureAdminPage.FMT). Used wherever JS
  // updates a DOM element whose value the JSP would otherwise have rendered.
  const jwtFormatUtcMinute = instantOrIso => {
    const d = instantOrIso instanceof Date ? instantOrIso : new Date(instantOrIso);
    return d.getUTCFullYear() + '-' +
      String(d.getUTCMonth() + 1).padStart(2, '0') + '-' +
      String(d.getUTCDate()).padStart(2, '0') + ' ' +
      String(d.getUTCHours()).padStart(2, '0') + ':' +
      String(d.getUTCMinutes()).padStart(2, '0') + ' UTC';
  };

  const jwtRotateNow = () => {
    jwtAdminPost(jwtContextPath + '/admin/jwtKeyRotate.html', '',
      data => {
        if (data.status === 'rotated') {
          const activeAtFmt = data.activeAt ? jwtFormatUtcMinute(data.activeAt) : null;
          const msg = activeAtFmt
            ? 'Rotation started - new key will become active at ' + activeAtFmt
            : 'Keys rotated successfully';
          jwtShowResult('jwtRotateResult', 'ok', msg);
          if (data.warning) {
            jwtShowResult('jwtRotateWarning', 'warn', data.warning);
          } else {
            document.getElementById('jwtRotateWarning').style.display = 'none';
          }
          document.getElementById('jwtLastRotatedDate').textContent = jwtFormatUtcMinute(new Date());
          document.getElementById('jwtWarmupAnnotation').textContent = activeAtFmt
            ? ' (warming up - new key active at ' + activeAtFmt + ')'
            : '';
          jwtRefreshKeyTable();
        } else if (data.status === 'warmupInProgress') {
          // 409 path: a previous rotation's warmup is still in progress. Show the
          // structured message (which names the activation time) as a warning, not
          // a hard error — the rotation is recoverable by waiting.
          jwtShowResult('jwtRotateResult', 'warn', data.message);
          document.getElementById('jwtRotateWarning').style.display = 'none';
        } else {
          jwtShowResult('jwtRotateResult', 'error', data.message || 'Rotation failed');
          document.getElementById('jwtRotateWarning').style.display = 'none';
        }
      },
      () => jwtShowResult('jwtRotateResult', 'error', 'Request failed')
    );
  };

  const jwtEscape = str => String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

  function jwtHighlightJson(json) {
    // " is intentionally not escaped — the regex patterns below depend on literal " delimiters,
    // and JWK values (base64url, algorithm names) never contain " characters.
    const escaped = json
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
    return escaped
      .replace(/"([^"]+)"(\s*:)/g, '<span class="jwt-j-key">"$1"</span>$2')
      .replace(/:\s*"([^"]*)"/g, (m, v) => ': <span class="jwt-j-str">"' + v + '"</span>');
  }

  const jwtRenderKeys = keys => {
    document.getElementById('jwtKeyCount').textContent =
      keys.length + ' active key' + (keys.length !== 1 ? 's' : '');
    document.getElementById('jwtJwksDownload').style.display = '';
    document.getElementById('jwtKeyTable').style.display = '';

    const tbody = document.getElementById('jwtKeyTableBody');
    tbody.innerHTML = '';
    const seenAlgs = new Set();

    keys.forEach(key => {
      const alg = key.alg || key.kty || '?';
      const status = seenAlgs.has(alg) ? 'retiring' : 'current';
      seenAlgs.add(alg);
      const type = key.kty === 'EC'    ? 'EC ' + (key.crv || '?')
                 : key.alg === 'RS256' ? 'RSA-2048'
                 : key.alg === 'RS384' ? 'RSA-3072'
                 : key.kty || '?';

      const dataRow = document.createElement('tr');
      dataRow.className = 'jwt-data-row';
      const created = key.iat
        ? new Date(key.iat * 1000).toISOString().slice(0, 16).replace('T', ' ') + ' UTC'
        : '\u2014';
      dataRow.innerHTML =
        '<td class="jwt-expand-cell"><span class="jwt-expand-icon">&#9658;</span></td>' +
        '<td class="jwt-monospace">' + jwtEscape(key.kid || '') + '</td>' +
        '<td><span class="jwt-badge jwt-badge-alg">' + jwtEscape(key.alg || key.kty || '') + '</span></td>' +
        '<td>' + jwtEscape(type) + '</td>' +
        '<td>' + jwtEscape(key.use || 'sig') + '</td>' +
        '<td><span class="jwt-badge jwt-badge-' + status + '">' + status + '</span></td>' +
        '<td class="jwt-status-line">' + jwtEscape(created) + '</td>';

      const jsonRow = document.createElement('tr');
      jsonRow.className = 'jwt-json-row';
      jsonRow.style.display = 'none';
      const jsonCell = document.createElement('td');
      jsonCell.colSpan = 7;
      jsonCell.className = 'jwt-json-cell';
      const pre = document.createElement('pre');
      pre.className = 'jwt-json-inner';
      pre.innerHTML = jwtHighlightJson(JSON.stringify(key, null, 2));
      jsonCell.appendChild(pre);
      jsonRow.appendChild(jsonCell);

      const expandIcon = dataRow.querySelector('.jwt-expand-icon');
      dataRow.addEventListener('click', () => {
        const open = jsonRow.style.display !== 'none';
        jsonRow.style.display = open ? 'none' : '';
        expandIcon.classList.toggle('jwt-open', !open);
      });

      tbody.appendChild(dataRow);
      tbody.appendChild(jsonRow);
    });
  }

  const jwtRefreshKeyTable = () => {
    fetch(jwtContextPath + '/.well-known/jwks.json', { cache: 'no-store' })
      .then(r => r.json())
      .then(jwks => jwtRenderKeys(jwks.keys || []))
      .catch(() => {
        document.getElementById('jwtKeyCount').textContent = 'Could not refresh JWKS data';
      });
  };

  (() => {
    const raw = '${jwksBase64}';
    if (!raw) {
      document.getElementById('jwtKeyCount').textContent = 'Keys not yet available (server startup in progress)';
      return;
    }
    let jwks;
    try {
      jwks = JSON.parse(atob(raw));
    } catch (e) {
      document.getElementById('jwtKeyCount').textContent = 'Could not parse JWKS data';
      return;
    }
    jwtRenderKeys(jwks.keys || []);
  })();
</script>
