<%@ include file="/include-internal.jsp"%>
<%@ taglib prefix="props" tagdir="/WEB-INF/tags/props" %>
<%@ taglib prefix="l" tagdir="/WEB-INF/tags/layout" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<l:settingsGroup title="JWT Build Feature">
    <tr>
        <th><label for="ttl_minutes">Token lifetime (minutes):</label></th>
        <td>
            <props:textProperty name="ttl_minutes" value="${empty propertiesBean.properties['ttl_minutes'] ? '10' : propertiesBean.properties['ttl_minutes']}" style="width:5em;"/>
            <span class="smallNote">How long the JWT is valid for. Default: 10 minutes.</span>
            <span class="error" id="error_ttl_minutes"></span>
        </td>
    </tr>
    <tr>
        <th><label for="audience">Audience (<code>aud</code>):</label></th>
        <td>
            <props:textProperty name="audience" value="${propertiesBean.properties['audience']}" style="width:30em;"/>
            <span class="smallNote">Value for the <code>aud</code> claim. Leave blank to use the TeamCity server URL. Cloud providers often require a specific value here (e.g. <code>api://AzureADTokenExchange</code>).</span>
            <span class="error" id="error_audience"></span>
        </td>
    </tr>
    <tr>
        <th><label for="algorithm">Signing algorithm:</label></th>
        <td>
            <props:selectProperty name="algorithm">
                <props:option value="RS256" selected="${empty propertiesBean.properties['algorithm'] || propertiesBean.properties['algorithm'] == 'RS256'}">RS256 (RSA, default)</props:option>
                <props:option value="ES256" selected="${propertiesBean.properties['algorithm'] == 'ES256'}">ES256 (ECDSA P-256)</props:option>
            </props:selectProperty>
            <span class="smallNote">ES256 produces smaller tokens and is widely supported by cloud providers.</span>
        </td>
    </tr>
    <tr>
        <th><label for="claims">Claims to include:</label></th>
        <td>
            <props:textProperty name="claims" value="${propertiesBean.properties['claims']}" style="width:40em;"/>
            <span class="smallNote">Comma-separated list of claims to include in the token. Leave blank to include all.
                Available: <code>branch</code>, <code>build_type_external_id</code>, <code>project_external_id</code>,
                <code>triggered_by</code>, <code>triggered_by_id</code>, <code>build_number</code>.</span>
            <span class="error" id="error_claims"></span>
        </td>
    </tr>
    <tr>
        <th></th>
        <td>
            <button type="button" onclick="jwtTestOpen()">Test Connection</button>
            <span class="smallNote">Verify JWT issuance and OIDC endpoints using the current settings above.</span>
        </td>
    </tr>
</l:settingsGroup>

<%-- Test Connection modal --%>
<div id="jwtTestModal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.6);z-index:10000;align-items:center;justify-content:center;">
    <div style="background:#2b2b2b;border:1px solid #555;border-radius:6px;padding:20px;min-width:480px;max-width:600px;font-size:13px;font-family:monospace;">
        <div style="font-weight:bold;color:#ccc;margin-bottom:14px;font-size:14px;">Test Connection</div>
        <div id="jwtRow0" style="margin-bottom:6px;color:#888;">○ JWT issuance</div>
        <div id="jwtRow1" style="margin-bottom:6px;color:#888;">○ OIDC discovery endpoint</div>
        <div id="jwtRow2" style="margin-bottom:6px;color:#888;">○ JWKS signature verification</div>
        <hr style="border:none;border-top:1px solid #444;margin:12px 0;"/>
        <div style="color:#aaa;margin-bottom:6px;">Optional: test token exchange</div>
        <div style="display:flex;gap:8px;align-items:center;">
            <input id="jwtServiceUrl" type="text" placeholder="https://octopus.example.com"
                   style="flex:1;background:#1e1e1e;border:1px solid #555;color:#ccc;padding:4px 6px;border-radius:3px;"
                   disabled/>
            <button type="button" id="jwtExchangeBtn" onclick="jwtTestExchange()" disabled
                    style="white-space:nowrap;">Try Exchange</button>
        </div>
        <div id="jwtRow3" style="margin-top:6px;min-height:18px;color:#888;"></div>
        <div style="text-align:right;margin-top:14px;">
            <button type="button" onclick="jwtTestClose()">Close</button>
        </div>
    </div>
</div>

<script type="text/javascript">
    var _jwtToken = null;
    var _jwtTestUrl = '${pageContext.request.contextPath}/admin/jwtTest.html';

    function jwtTestOpen() {
        _jwtToken = null;
        ['jwtRow0','jwtRow1','jwtRow2','jwtRow3'].forEach(function(id) {
            var el = document.getElementById(id);
            el.textContent = id === 'jwtRow3' ? '' : '○ Pending';
            el.style.color = '#888';
        });
        document.getElementById('jwtServiceUrl').disabled = true;
        document.getElementById('jwtServiceUrl').value = '';
        document.getElementById('jwtExchangeBtn').disabled = true;
        document.getElementById('jwtTestModal').style.display = 'flex';
        jwtTestRunChecks();
    }

    function jwtTestClose() {
        document.getElementById('jwtTestModal').style.display = 'none';
    }

    function jwtSetRow(id, ok, message) {
        var el = document.getElementById(id);
        el.textContent = (ok ? '✓ ' : '✗ ') + message;
        el.style.color = ok ? '#7ec87e' : '#e06c75';
    }

    function jwtPost(params) {
        var body = Object.entries(params)
            .map(function(e) { return encodeURIComponent(e[0]) + '=' + encodeURIComponent(e[1]); })
            .join('&');
        return fetch(_jwtTestUrl, {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: body
        }).then(function(r) { return r.json(); });
    }

    async function jwtTestRunChecks() {
        var algorithm = document.getElementById('algorithm').value;
        var ttl = document.getElementById('ttl_minutes').value || '10';
        var audience = document.getElementById('audience').value;

        document.getElementById('jwtRow0').textContent = '⏳ Issuing JWT...';
        var r1 = await jwtPost({step:'jwt', algorithm:algorithm, ttl_minutes:ttl, audience:audience});
        jwtSetRow('jwtRow0', r1.ok, r1.message);
        if (!r1.ok) return;
        _jwtToken = r1.token;

        document.getElementById('jwtRow1').textContent = '⏳ Checking discovery endpoint...';
        var r2 = await jwtPost({step:'discovery'});
        jwtSetRow('jwtRow1', r2.ok, r2.message);
        if (!r2.ok) return;

        document.getElementById('jwtRow2').textContent = '⏳ Verifying JWKS signature...';
        var r3 = await jwtPost({step:'jwks', token:_jwtToken});
        jwtSetRow('jwtRow2', r3.ok, r3.message);
        if (!r3.ok) return;

        document.getElementById('jwtServiceUrl').disabled = false;
        document.getElementById('jwtExchangeBtn').disabled = false;
    }

    async function jwtTestExchange() {
        var serviceUrl = document.getElementById('jwtServiceUrl').value.trim();
        if (!serviceUrl) return;
        var audience = document.getElementById('audience').value;
        document.getElementById('jwtExchangeBtn').disabled = true;
        document.getElementById('jwtRow3').textContent = '⏳ Trying exchange...';
        document.getElementById('jwtRow3').style.color = '#888';
        var r = await jwtPost({step:'exchange', token:_jwtToken, serviceUrl:serviceUrl, audience:audience});
        jwtSetRow('jwtRow3', r.ok, r.message);
        document.getElementById('jwtExchangeBtn').disabled = false;
    }
</script>
