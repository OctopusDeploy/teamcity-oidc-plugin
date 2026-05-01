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
    Turns TeamCity into an OIDC provider. During each build, this plugin issue a short-lived,
    cryptographically signed JWT that cloud services can verify against the public keys below &mdash;
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
        <span class="jwt-hint">6-field cron (sec min hr day month weekday) &mdash; e.g. <code>0 0 3 * * SUN</code> = Sundays at 03:00 UTC</span>
        <span id="jwtSaveResult" style="display:none"></span>
        <span id="jwtRotateResult" style="display:none"></span>
        <span id="jwtRotateWarning" style="display:none"></span>
      </div>
    </div>

    <div class="jwt-field-row">
      <div class="jwt-field-label"></div>
      <div class="jwt-field-body">
        <span class="jwt-status-line">
          Last rotated: <span id="jwtLastRotatedDate"><c:out value="${lastRotatedAt}"/></span><c:if test="${not empty nextDue}"> &nbsp;&middot;&nbsp; Next due: <c:out value="${nextDue}"/></c:if>
        </span>
      </div>
    </div>
  </div>

  <%-- ── Section 3: JWKS ── --%>
  <div class="jwt-sec">
    <div class="jwt-sec-title">JWKS</div>

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

  function jwtAdminPost(url, body, onSuccess, onError) {
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
    .then(function(r) { if (!r.ok) { throw new Error('HTTP ' + r.status); } return r.json(); })
    .then(onSuccess)
    .catch(onError);
  }

  function jwtSaveOidcSettings() {
    const url = document.getElementById('overrideIssuerUrl').value;
    jwtAdminPost(jwtContextPath + '/admin/jwtOidcSettings.html',
      'overrideIssuerUrl=' + encodeURIComponent(url),
      function(data) {
        const state = data.state || (data.ok ? 'ok' : 'error');
        jwtShowResult('jwtOidcSettingsResult', state, data.message);
        if (data.ok) {
          document.getElementById('overrideIssuerUrl').value = url.trim().replace(/\/+$/, '');
        }
      },
      function() { jwtShowResult('jwtOidcSettingsResult', 'error', 'Request failed'); }
    );
  }

  function jwtClearOidcSettings() {
    document.getElementById('overrideIssuerUrl').value = '';
    jwtAdminPost(jwtContextPath + '/admin/jwtOidcSettings.html',
      'overrideIssuerUrl=',
      function(data) {
        const state = data.state || (data.ok ? 'ok' : 'error');
        jwtShowResult('jwtOidcSettingsResult', state, data.message);
      },
      function() { jwtShowResult('jwtOidcSettingsResult', 'error', 'Request failed'); }
    );
  }

  function jwtSaveRotationSettings() {
    const enabled = document.getElementById('rotationEnabled').checked;
    const schedule = document.getElementById('cronSchedule').value;
    jwtAdminPost(jwtContextPath + '/admin/jwtRotationSettings.html',
      'enabled=' + enabled + '&cronSchedule=' + encodeURIComponent(schedule),
      function(data) { jwtShowResult('jwtSaveResult', data.ok ? 'ok' : 'error', data.message); },
      function() { jwtShowResult('jwtSaveResult', 'error', 'Request failed'); }
    );
  }

  function jwtRotateNow() {
    jwtAdminPost(jwtContextPath + '/admin/jwtKeyRotate.html', '',
      function(data) {
        const ok = data.status === 'rotated';
        jwtShowResult('jwtRotateResult', ok ? 'ok' : 'error', ok ? 'Keys rotated successfully' : (data.message || 'Rotation failed'));
        if (ok && data.warning) {
          jwtShowResult('jwtRotateWarning', 'warn', data.warning);
        } else {
          document.getElementById('jwtRotateWarning').style.display = 'none';
        }
        if (ok) {
          const now = new Date();
          const formatted = now.getUTCFullYear() + '-' +
            String(now.getUTCMonth() + 1).padStart(2, '0') + '-' +
            String(now.getUTCDate()).padStart(2, '0') + ' ' +
            String(now.getUTCHours()).padStart(2, '0') + ':' +
            String(now.getUTCMinutes()).padStart(2, '0') + ' UTC';
          document.getElementById('jwtLastRotatedDate').textContent = formatted;
          jwtRefreshKeyTable();
        }
      },
      function() { jwtShowResult('jwtRotateResult', 'error', 'Request failed'); }
    );
  }

  function jwtEscape(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function jwtHighlightJson(json) {
    // " is intentionally not escaped — the regex patterns below depend on literal " delimiters,
    // and JWK values (base64url, algorithm names) never contain " characters.
    const escaped = json
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
    return escaped
      .replace(/"([^"]+)"(\s*:)/g, '<span class="jwt-j-key">"$1"</span>$2')
      .replace(/:\s*"([^"]*)"/g, function(m, v) {
        return ': <span class="jwt-j-str">"' + v + '"</span>';
      });
  }

  function jwtRenderKeys(keys) {
    document.getElementById('jwtKeyCount').textContent =
      keys.length + ' active key' + (keys.length !== 1 ? 's' : '');
    document.getElementById('jwtJwksDownload').style.display = '';
    document.getElementById('jwtKeyTable').style.display = '';

    const tbody = document.getElementById('jwtKeyTableBody');
    tbody.innerHTML = '';
    const seenAlgs = new Set();

    keys.forEach(function(key) {
      const alg = key.alg || key.kty || '?';
      const status = seenAlgs.has(alg) ? 'retiring' : 'current';
      seenAlgs.add(alg);
      const type = key.kty === 'EC'    ? 'EC ' + (key.crv || '?')
                 : key.alg === 'RS256' ? 'RSA-2048'
                 : key.alg === 'RS384' ? 'RSA-3072'
                 : key.kty || '?';

      const dataRow = document.createElement('tr');
      dataRow.className = 'jwt-data-row';
      dataRow.innerHTML =
        '<td class="jwt-expand-cell"><span class="jwt-expand-icon">&#9658;</span></td>' +
        '<td class="jwt-monospace">' + jwtEscape(key.kid || '') + '</td>' +
        '<td><span class="jwt-badge jwt-badge-alg">' + jwtEscape(key.alg || key.kty || '') + '</span></td>' +
        '<td>' + jwtEscape(type) + '</td>' +
        '<td>' + jwtEscape(key.use || 'sig') + '</td>' +
        '<td><span class="jwt-badge jwt-badge-' + status + '">' + status + '</span></td>';

      const jsonRow = document.createElement('tr');
      jsonRow.className = 'jwt-json-row';
      jsonRow.style.display = 'none';
      const jsonCell = document.createElement('td');
      jsonCell.colSpan = 6;
      jsonCell.className = 'jwt-json-cell';
      const pre = document.createElement('pre');
      pre.className = 'jwt-json-inner';
      pre.innerHTML = jwtHighlightJson(JSON.stringify(key, null, 2));
      jsonCell.appendChild(pre);
      jsonRow.appendChild(jsonCell);

      const expandIcon = dataRow.querySelector('.jwt-expand-icon');
      dataRow.addEventListener('click', function() {
        const open = jsonRow.style.display !== 'none';
        jsonRow.style.display = open ? 'none' : '';
        expandIcon.classList.toggle('jwt-open', !open);
      });

      tbody.appendChild(dataRow);
      tbody.appendChild(jsonRow);
    });
  }

  function jwtRefreshKeyTable() {
    fetch(jwtContextPath + '/.well-known/jwks.json')
      .then(function(r) { return r.json(); })
      .then(function(jwks) { jwtRenderKeys(jwks.keys || []); })
      .catch(function() {
        document.getElementById('jwtKeyCount').textContent = 'Could not refresh JWKS data';
      });
  }

  (function() {
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
