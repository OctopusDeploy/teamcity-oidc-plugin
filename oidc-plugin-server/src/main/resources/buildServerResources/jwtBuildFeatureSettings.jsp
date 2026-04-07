<%@ include file="/include-internal.jsp"%>
<%@ taglib prefix="props" tagdir="/WEB-INF/tags/props" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page import="jetbrains.buildServer.serverSide.auth.Permission" %>
<%@ page import="jetbrains.buildServer.web.util.SessionUser" %>
<%
    var currentUser = SessionUser.getUser(request);
    if (currentUser == null || !currentUser.isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS)) {
        response.sendError(javax.servlet.http.HttpServletResponse.SC_FORBIDDEN);
        return;
    }
%>

<h2>Key Rotation</h2>

<table>
  <tr>
    <td>
      <label>
        <input type="checkbox" id="rotationEnabled" <c:if test="${rotationEnabled}">checked</c:if>>
        Enable automatic rotation
      </label>
    </td>
  </tr>
  <tr>
    <td>
      <label for="cronSchedule">Cron schedule (6-field: second minute hour day month weekday):</label><br/>
      <input type="text" id="cronSchedule" size="25" value="<c:out value="${cronSchedule}"/>"/>
      &nbsp;
      <input type="button" value="Save" onclick="jwtSaveRotationSettings()"/>
      &nbsp;
      <input type="button" value="Rotate now" onclick="jwtRotateNow()"/>
    </td>
  </tr>
  <tr>
    <td>
      <span id="jwtLastRotated" style="color:#555;font-size:0.9em">
        Last rotated: <c:out value="${lastRotatedAt}"/>
        <c:if test="${not empty nextDue}">
          &nbsp;|&nbsp; Next due: <c:out value="${nextDue}"/>
        </c:if>
      </span>
    </td>
  </tr>
  <tr>
    <td>
      <span id="jwtSaveResult" style="display:none"></span>
      &nbsp;
      <span id="jwtRotateResult" style="display:none"></span>
    </td>
  </tr>
</table>

<script>
  function jwtSaveRotationSettings() {
    var enabled = document.getElementById('rotationEnabled').checked;
    var schedule = document.getElementById('cronSchedule').value;
    jwtAdminPost('/admin/jwtRotationSettings.html',
      'enabled=' + enabled + '&cronSchedule=' + encodeURIComponent(schedule),
      function(data) { jwtShowResult('jwtSaveResult', data.ok, data.message); },
      function() { jwtShowResult('jwtSaveResult', false, 'Request failed'); }
    );
  }

  function jwtRotateNow() {
    jwtAdminPost('/admin/jwtKeyRotate.html', '',
      function(data) {
        var ok = data.status === 'rotated';
        var msg = ok ? 'Keys rotated successfully' : (data.message || 'Rotation failed');
        jwtShowResult('jwtRotateResult', ok, msg);
        if (ok) {
          var now = new Date();
          var formatted = now.getUTCFullYear() + '-' +
            String(now.getUTCMonth() + 1).padStart(2, '0') + '-' +
            String(now.getUTCDate()).padStart(2, '0') + ' ' +
            String(now.getUTCHours()).padStart(2, '0') + ':' +
            String(now.getUTCMinutes()).padStart(2, '0') + ' UTC';
          document.querySelector('#jwtLastRotated').textContent = 'Last rotated: ' + formatted;
        }
      },
      function() { jwtShowResult('jwtRotateResult', false, 'Request failed'); }
    );
  }

  function jwtAdminPost(url, body, onSuccess, onError) {
    fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-TC-CSRF-Token': BS.CSRF.token
      },
      body: body
    })
    .then(function(r) { return r.json(); })
    .then(onSuccess)
    .catch(onError);
  }

  function jwtShowResult(elementId, ok, message) {
    var el = document.getElementById(elementId);
    el.textContent = message;
    el.style.color = ok ? 'green' : 'red';
    el.style.display = 'inline';
  }
</script>

<h2>JWKS</h2>
<pre><c:out value="${jwks}"/></pre>
<a href="data:application/json;charset=utf-8;base64,${jwksBase64}" download="jwks.json">download</a>
