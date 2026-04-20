<%@ include file="/include-internal.jsp"%>
<%@ taglib prefix="props" tagdir="/WEB-INF/tags/props" %>
<%@ taglib prefix="l" tagdir="/WEB-INF/tags/layout" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<jsp:useBean id="buildForm" type="jetbrains.buildServer.controllers.admin.projects.EditableBuildTypeSettingsForm" scope="request"/>

<l:settingsGroup title="">
    <tr>
        <td colspan="2"><span class="error" id="error_root_url"></span></td>
    </tr>
    <tr>
        <th><label for="ttl_minutes">Token lifetime (minutes):</label></th>
        <td>
            <props:textProperty name="ttl_minutes" value="${empty propertiesBean.properties['ttl_minutes'] ? '10' : fn:escapeXml(propertiesBean.properties['ttl_minutes'])}" style="width:5em;"/>
            <span class="smallNote">How long the JWT is valid for. Default: 10 minutes.</span>
            <span class="error" id="error_ttl_minutes"></span>
        </td>
    </tr>
    <tr>
        <th><label for="audience">Audience (<code>aud</code>):</label></th>
        <td>
            <props:textProperty name="audience" value="${fn:escapeXml(propertiesBean.properties['audience'])}" style="width:30em;"/>
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
        <th><label>Claims to include:</label></th>
        <td>
            <%-- Hidden field holds the comma-separated value that TC saves; JS keeps it in sync --%>
            <input type="hidden" id="claims" name="claims" value="${fn:escapeXml(propertiesBean.properties['claims'])}"/>
            <table style="border-collapse:collapse;">
                <tr>
                    <td style="padding:2px 8px 2px 0;"><label><input type="checkbox" class="jwt-claim-cb" value="branch"/> branch</label></td>
                    <td></td>
                </tr>
                <tr>
                    <td style="padding:2px 8px 2px 0;"><label><input type="checkbox" class="jwt-claim-cb" value="build_type_external_id"/> build_type_external_id</label></td>
                    <td><span class="smallNote"><code>${fn:escapeXml(buildForm.externalId)}</code></span></td>
                </tr>
                <tr>
                    <td style="padding:2px 8px 2px 0;"><label><input type="checkbox" class="jwt-claim-cb" value="project_external_id"/> project_external_id</label></td>
                    <td><span class="smallNote"><code>${fn:escapeXml(buildForm.project.externalId)}</code></span></td>
                </tr>
                <tr>
                    <td style="padding:2px 8px 2px 0;"><label><input type="checkbox" class="jwt-claim-cb" value="triggered_by"/> triggered_by</label></td>
                    <td></td>
                </tr>
                <tr>
                    <td style="padding:2px 8px 2px 0;"><label><input type="checkbox" class="jwt-claim-cb" value="triggered_by_id"/> triggered_by_id</label></td>
                    <td></td>
                </tr>
                <tr>
                    <td style="padding:2px 8px 2px 0;"><label><input type="checkbox" class="jwt-claim-cb" value="build_number"/> build_number</label></td>
                    <td></td>
                </tr>
            </table>
            <span class="smallNote">Uncheck claims to exclude them from the token.</span>
            <span class="error" id="error_claims"></span>
        </td>
    </tr>
</l:settingsGroup>

<%-- Hidden holder; JS moves its contents into TC's editBuildFeatureAdditionalButtons on DOM ready --%>
<%-- data-build-type-id carries the build type ID safely without inline JS injection --%>
<span id="jwtTestConnectionBtnHolder" style="display:none;" data-build-type-id="${fn:escapeXml(param.id)}">
    <input type="button" value="Test Connection" class="btn btn_primary submitButton"
           onclick="event.stopPropagation(); window.jwtTestOpen();" />
</span>

<%-- Test Connection modal --%>
<div id="jwtTestModal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.6);z-index:10000;align-items:center;justify-content:center;">
    <div style="background:#2b2b2b;border:1px solid #555;border-radius:6px;padding:20px;min-width:480px;max-width:600px;font-size:13px;font-family:monospace;">
        <div style="font-weight:bold;color:#ccc;margin-bottom:14px;font-size:14px;">Test Connection</div>
        <div id="jwtRow0" style="margin-bottom:6px;color:#888;">&#x25CB; JWT issuance</div>
        <div id="jwtRow1" style="margin-bottom:6px;color:#888;">&#x25CB; OIDC discovery endpoint</div>
        <div id="jwtRow2" style="margin-bottom:6px;color:#888;">&#x25CB; JWKS signature verification</div>
        <hr style="border:none;border-top:1px solid #444;margin:12px 0;"/>
        <div style="color:#aaa;margin-bottom:6px;">Test token exchange</div>
        <div style="display:flex;gap:8px;align-items:center;">
            <input id="jwtServiceUrl" type="text" placeholder="https://octopus.example.com"
                   style="flex:1;background:#1e1e1e;border:1px solid #555;color:#ccc;padding:4px 6px;border-radius:3px;"
                   disabled/>
            <button type="button" id="jwtExchangeBtn" class="btn" onclick="window.jwtTestExchange()" disabled
                    style="white-space:nowrap;">Try Exchange</button>
        </div>
        <div id="jwtRow3" style="margin-top:6px;min-height:18px;color:#888;"></div>
        <div style="text-align:right;margin-top:14px;">
            <button type="button" class="btn" onclick="window.jwtTestClose()">Close</button>
        </div>
    </div>
</div>

<script type="text/javascript">
    let _jwtToken = null;
    const _jwtTestUrl = '${pageContext.request.contextPath}/admin/jwtTest.html';

    window.jwtTestOpen = function() {
        _jwtToken = null;
        ['jwtRow0','jwtRow1','jwtRow2','jwtRow3'].forEach(function(id) {
            const el = document.getElementById(id);
            el.textContent = id === 'jwtRow3' ? '' : '○ Pending';
            el.style.color = '#888';
        });
        document.getElementById('jwtServiceUrl').disabled = true;
        document.getElementById('jwtServiceUrl').value = '';
        document.getElementById('jwtExchangeBtn').disabled = true;
        document.getElementById('jwtTestModal').style.display = 'flex';
        jwtTestRunChecks();
    }

    window.jwtTestClose = function() {
        document.getElementById('jwtTestModal').style.display = 'none';
    }

    window.jwtSetRow = function(id, ok, message) {
        const el = document.getElementById(id);
        el.textContent = (ok ? '✓ ' : '✗ ') + message;
        el.style.color = ok ? '#7ec87e' : '#e06c75';
    }

    window.jwtPost = function(params) {
        const body = Object.entries(params)
            .map(function(e) { return encodeURIComponent(e[0]) + '=' + encodeURIComponent(e[1]); })
            .join('&');
        const csrfMeta = document.querySelector('meta[name="tc-csrf-token"]');
        const csrf = csrfMeta ? csrfMeta.getAttribute('content') : '';
        return fetch(_jwtTestUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-TC-CSRF-Token': csrf
            },
            body: body
        }).then(function(r) { return r.json(); });
    }

    window.jwtTestRunChecks = async function() {
        const algorithm = document.getElementById('algorithm').value;
        const ttl = document.getElementById('ttl_minutes').value || '10';
        const audience = document.getElementById('audience').value;
        const buildTypeId = document.getElementById('jwtTestConnectionBtnHolder').dataset.buildTypeId || '';

        document.getElementById('jwtRow0').textContent = '⏳ Issuing JWT...';
        const r1 = await jwtPost({step:'jwt', algorithm:algorithm, ttl_minutes:ttl, audience:audience, buildTypeId:buildTypeId});
        jwtSetRow('jwtRow0', r1.ok, r1.message);
        if (!r1.ok) return;
        _jwtToken = r1.token;

        document.getElementById('jwtRow1').textContent = '⏳ Checking discovery endpoint...';
        const r2 = await jwtPost({step:'discovery'});
        jwtSetRow('jwtRow1', r2.ok, r2.message);
        if (!r2.ok) return;

        document.getElementById('jwtRow2').textContent = '⏳ Verifying JWKS signature...';
        const r3 = await jwtPost({step:'jwks', token:_jwtToken});
        jwtSetRow('jwtRow2', r3.ok, r3.message);
        if (!r3.ok) return;

        document.getElementById('jwtServiceUrl').disabled = false;
        document.getElementById('jwtExchangeBtn').disabled = false;
    }

    window.jwtTestExchange = async function() {
        const serviceUrl = document.getElementById('jwtServiceUrl').value.trim();
        if (!serviceUrl) return;
        const audience = document.getElementById('audience').value;
        document.getElementById('jwtExchangeBtn').disabled = true;
        document.getElementById('jwtRow3').textContent = '⏳ Trying exchange...';
        document.getElementById('jwtRow3').style.color = '#888';
        const r = await jwtPost({step:'exchange', token:_jwtToken, serviceUrl:serviceUrl, audience:audience});
        jwtSetRow('jwtRow3', r.ok, r.message);
        document.getElementById('jwtExchangeBtn').disabled = false;
    }

    $j(document).ready(function() {
        const placeholder = $j('span#editBuildFeatureAdditionalButtons');
        if (placeholder.length) {
            placeholder.empty();
            placeholder.append($j('span#jwtTestConnectionBtnHolder').children());
        }

        // Initialise claim checkboxes from stored comma-separated value.
        // Blank = all claims enabled, so tick all boxes when the field is empty.
        const ALL_CLAIMS = ['branch','build_type_external_id','project_external_id',
                          'triggered_by','triggered_by_id','build_number'];
        const stored = $j('#claims').val().trim();
        const enabled = stored === '' ? ALL_CLAIMS : stored.split(/\s*,\s*/);
        $j('.jwt-claim-cb').each(function() {
            $j(this).prop('checked', enabled.indexOf($j(this).val()) !== -1);
        });

        // Sync hidden field on every checkbox change.
        // All checked → store blank (= "all"); partial → store comma-separated list.
        $j('.jwt-claim-cb').on('change', function() {
            const checked = $j('.jwt-claim-cb:checked').map(function() { return $j(this).val(); }).get();
            $j('#claims').val(checked.length === ALL_CLAIMS.length ? '' : checked.join(','));
        });
    });
</script>
