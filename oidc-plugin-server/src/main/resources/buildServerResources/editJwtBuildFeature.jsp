<%@ page contentType="text/html;charset=UTF-8" pageEncoding="UTF-8" %>
<%@ include file="/include-internal.jsp"%>
<%@ taglib prefix="props" tagdir="/WEB-INF/tags/props" %>
<%@ taglib prefix="l" tagdir="/WEB-INF/tags/layout" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<%@ page import="com.octopus.teamcity.oidc.JwtBuildFeature" %>
<%@ page import="com.octopus.teamcity.oidc.OidcConnection" %>
<%@ page import="jetbrains.buildServer.serverSide.auth.Permission" %>
<%@ page import="jetbrains.buildServer.users.SUser" %>
<%@ page import="jetbrains.buildServer.web.util.SessionUser" %>
<%
    pageContext.setAttribute("jwtRootUrlNeedsHttps", !JwtBuildFeature.isRootUrlHttps());

    final JwtBuildFeature.SampleClaims jwtSamples = JwtBuildFeature.sampleClaimsFor(request.getParameter("id"));
    pageContext.setAttribute("sampleBranch", jwtSamples.branch());
    pageContext.setAttribute("sampleTriggerType", jwtSamples.triggerType());
    pageContext.setAttribute("sampleHasVcsRoot", jwtSamples.hasVcsRoot());
    pageContext.setAttribute("projectInternalId", jwtSamples.projectInternalId());
    pageContext.setAttribute("projectExternalId", jwtSamples.projectExternalId());
    pageContext.setAttribute("buildTypeInternalId", jwtSamples.buildTypeInternalId());

    // OidcSettingsManager lives in the plugin's child Spring context, not TC's root web
    // context, so WebApplicationContextUtils can't see it. Use the static accessor instead.
    pageContext.setAttribute("maxTokenLifetimeMinutes", JwtBuildFeature.maxTokenLifetimeMinutes());
    pageContext.setAttribute("jwtIssuerUrl", JwtBuildFeature.issuerUrl());

    final SUser editJwtCurrentUser = SessionUser.getUser(request);
    pageContext.setAttribute("currentUserCanConfigureMax",
            editJwtCurrentUser != null && editJwtCurrentUser.isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS));

    // Build a map-based view of each connection so the JSP's ${c.id} expressions can read
    // them. Property-style access like ${c.id} on a Map is a key lookup and works in
    // all Jasper versions; calling a record accessor (${c.id()}) needs method-invocation
    // support that TC's bundled Jasper may not provide at Java 8 source level.
    final java.util.List<OidcConnection> jwtConnectionsRaw =
            JwtBuildFeature.availableConnectionsFor(request.getParameter("id"));
    final java.util.List<java.util.Map<String, String>> jwtConnections = new java.util.ArrayList<>();
    for (final OidcConnection conn : jwtConnectionsRaw) {
        final java.util.Map<String, String> view = new java.util.HashMap<>();
        view.put("id", conn.id());
        view.put("displayName", conn.displayName());
        view.put("audience", conn.settings().audience());
        view.put("ttl", String.valueOf(conn.settings().ttlMinutes()));
        view.put("algorithm", conn.settings().signingAlgorithm());
        view.put("subjectDimensions", String.join(",", conn.settings().subjectDimensions()));
        view.put("tokenVariableName", conn.tokenVariableName());
        jwtConnections.add(view);
    }
    pageContext.setAttribute("jwtConnections", jwtConnections);
%>
<link rel="stylesheet" href="${pageContext.request.contextPath}/plugins/teamcity-oidc-plugin/jwt-admin.css"/>
<jsp:useBean id="buildForm" type="jetbrains.buildServer.controllers.admin.projects.EditableBuildTypeSettingsForm" scope="request"/>

<l:settingsGroup title="">
    <%-- Id of the feature being edited, so the validator can skip it in the duplicate-name
         check (blank when adding). --%>
    <props:hiddenProperty name="self_feature_id" value="${param.featureId}"/>
    <c:if test="${jwtRootUrlNeedsHttps}">
        <tr id="row_root_url">
            <td colspan="2"><span class="error" id="error_root_url">The TeamCity server root URL must use HTTPS for OIDC token issuance. Update it in Administration &#x2192; Global Settings.</span></td>
        </tr>
    </c:if>
    <tr id="row_connection_id">
        <th><label for="connection_id">Connection:</label></th>
        <td>
            <c:choose>
                <c:when test="${empty jwtConnections}">
                    <span class="smallNote">No connections configured for this project. Create one via the project's <a href="${pageContext.request.contextPath}/admin/editProject.html?projectId=${fn:escapeXml(projectExternalId)}&amp;tab=oauthConnections">Connections</a> page.</span>
                </c:when>
                <c:otherwise>
                    <props:selectProperty name="connection_id">
                        <props:option value="">(none)</props:option>
                        <c:forEach var="c" items="${jwtConnections}">
                            <props:option value="${fn:escapeXml(c.id)}"
                                          selected="${propertiesBean.properties['connection_id'] == c.id}">
                                <c:out value="${c.displayName}"/>
                            </props:option>
                        </c:forEach>
                    </props:selectProperty>
                    <span class="smallNote">Create and edit credentials via the project's <a href="${pageContext.request.contextPath}/admin/editProject.html?projectId=${fn:escapeXml(projectExternalId)}&amp;tab=oauthConnections">Connections</a> page.</span>
                </c:otherwise>
            </c:choose>
            <span class="error" id="error_connection_id"></span>
        </td>
    </tr>
    <tr>
        <th><label for="token_variable_name">Variable name:</label></th>
        <td>
            <props:textProperty name="token_variable_name" value="${propertiesBean.properties['token_variable_name']}" style="width:30em;"/>
            <span class="smallNote jwt-field-note">Where the token is written. Blank inherits (connection, else <code>jwt.token</code>).</span>
            <span class="error" id="error_token_variable_name"></span>
        </td>
    </tr>

    <tr>
        <th><label>Issuer (<code>iss</code>):</label></th>
        <td>
            <input type="text" id="jwtIssuerUrl" readonly value="${fn:escapeXml(jwtIssuerUrl)}" style="width:30em;"/>
            <span class="smallNote jwt-field-note">The OIDC issuer URL (<c:choose><c:when test="${currentUserCanConfigureMax}"><a href="${pageContext.request.contextPath}/admin/admin.html?item=jwtPlugin">configurable</a></c:when><c:otherwise>configurable by admins</c:otherwise></c:choose>).</span>
        </td>
    </tr>

    <tr>
        <th><label for="ttl_minutes">Token lifetime (minutes):</label></th>
        <td>
            <props:textProperty name="ttl_minutes" value="${empty propertiesBean.properties['ttl_minutes'] ? '10' : propertiesBean.properties['ttl_minutes']}" style="width:5em;"/>
            <span class="smallNote">How long the JWT is valid for.<br/>Default: 10 minutes; max: <c:out value="${maxTokenLifetimeMinutes}"/> minutes (<c:choose><c:when test="${currentUserCanConfigureMax}"><a href="${pageContext.request.contextPath}/admin/admin.html?item=jwtPlugin">configurable</a></c:when><c:otherwise>configurable by admins</c:otherwise></c:choose>).</span>
            <span class="error" id="error_ttl_minutes"></span>
        </td>
    </tr>
    <tr>
        <th><label for="audience">Audience (<code>aud</code>):</label></th>
        <td>
            <props:textProperty name="audience" value="${propertiesBean.properties['audience']}" style="width:30em;"/>
            <span class="smallNote jwt-field-note">Value for the <code>aud</code> claim. Leave blank to use the TeamCity server URL. Cloud providers often require a specific value here (e.g. <code>api://AzureADTokenExchange</code> for Entra ID).</span>
            <span class="error" id="error_audience"></span>
        </td>
    </tr>
    <tr>
        <th><label for="algorithm">Signing algorithm:</label></th>
        <td>
            <props:selectProperty name="algorithm">
                <props:option value="RS256" selected="${empty propertiesBean.properties['algorithm'] || propertiesBean.properties['algorithm'] == 'RS256'}">RS256 (RSA-2048, default)</props:option>
                <props:option value="RS384" selected="${propertiesBean.properties['algorithm'] == 'RS384'}">RS384 (RSA-3072)</props:option>
                <props:option value="ES256" selected="${propertiesBean.properties['algorithm'] == 'ES256'}">ES256 (ECDSA P-256)</props:option>
            </props:selectProperty>
            <span class="smallNote">ES256 produces smaller tokens and is widely supported by cloud providers. RS384 uses a 3072-bit RSA key.</span>
        </td>
    </tr>
    <tr>
        <th><label>Subject scoping:</label></th>
        <td>
            <%-- Hidden field holds the comma-separated value that TC saves; JS keeps it in sync --%>
            <props:hiddenProperty name="subject_dimensions" id="subject_dimensions"/>
            <span class="smallNote">
                Choose which dimensions appear in <code>sub</code>; claims are emitted separately in the token regardless.
            </span>
            <%-- Sample values for the live preview, exposed via HTML data-* so JS can read them
                 without needing to inline-escape into a script literal. --%>
            <div id="jwtSubjectPreviewData" style="display:none;"
                 data-project-id="${fn:escapeXml(projectInternalId)}"
                 data-build-type-id="${fn:escapeXml(buildTypeInternalId)}"
                 data-sample-branch="${fn:escapeXml(sampleBranch)}"
                 data-sample-trigger-type="${fn:escapeXml(sampleTriggerType)}"></div>
            <ul class="jwt-subject-dimensions">
                <li><label title="Always included - required to identify the source project"><input type="checkbox" checked disabled/> project</label></li>
                <li><label title="Always included - required to identify the source build configuration"><input type="checkbox" checked disabled/> build_type</label></li>
                <c:if test="${sampleHasVcsRoot}">
                <li><label><input type="checkbox" class="jwt-subject-dimension-cb" value="branch"/> branch</label></li>
                </c:if>
                <li>
                    <label><input type="checkbox" class="jwt-subject-dimension-cb" value="trigger_type"/> trigger_type</label>
                    <span class="smallNote jwt-subject-dimensions-tooltip"
                          title="Possible values: user, snapshotDependency, vcsTrigger, schedulingTrigger, retryBuildTrigger, buildDependencyTrigger, finishBuildTrigger, perforceShelveTrigger, unknown">[?]</span>
                </li>
            </ul>
            <div class="jwt-subject-preview">
                <label for="jwtSubjectPreview">Resulting <code>sub</code> claim:</label>
                <input id="jwtSubjectPreview" type="text" readonly/>
            </div>
            <span class="error" id="error_subject_dimensions"></span>
        </td>
    </tr>
    <tr>
        <th>Setup guides:</th>
        <td>
            <span class="smallNote">
                <a href="https://github.com/OctopusDeploy/teamcity-oidc-plugin/blob/main/docs/aws.md" target="_blank" rel="noopener">AWS</a> &middot;
                <a href="https://github.com/OctopusDeploy/teamcity-oidc-plugin/blob/main/docs/azure.md" target="_blank" rel="noopener">Azure</a> &middot;
                <a href="https://github.com/OctopusDeploy/teamcity-oidc-plugin/blob/main/docs/artifactory.md" target="_blank" rel="noopener">JFrog Artifactory</a> &middot;
                <a href="https://github.com/OctopusDeploy/teamcity-oidc-plugin/blob/main/docs/octopus-deploy.md" target="_blank" rel="noopener">Octopus Deploy</a>
            </span>
        </td>
    </tr>
</l:settingsGroup>

<%-- Connection metadata for JS — emitted as data-* attributes to avoid inline script injection --%>
<div id="jwtConnectionsData" style="display:none;">
    <c:forEach var="c" items="${jwtConnections}">
        <span class="jwt-connection-entry"
              data-id="${fn:escapeXml(c.id)}"
              data-display-name="${fn:escapeXml(c.displayName)}"
              data-audience="${fn:escapeXml(c.audience)}"
              data-ttl="${fn:escapeXml(c.ttl)}"
              data-algorithm="${fn:escapeXml(c.algorithm)}"
              data-subject-dimensions="${fn:escapeXml(c.subjectDimensions)}"
              data-token-variable-name="${fn:escapeXml(c.tokenVariableName)}"></span>
    </c:forEach>
</div>

<%-- Hidden holder; JS moves its contents into TC's editBuildFeatureAdditionalButtons on DOM ready --%>
<%-- data-build-type-id carries the build type ID safely without inline JS injection --%>
<span id="jwtTestConnectionBtnHolder" style="display:none;" data-build-type-id="${fn:escapeXml(param.id)}">
    <input type="button" value="Test Connection" class="btn btn_primary"
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
    let _jwtTokenRef = null;
    const _jwtTestUrl = '${pageContext.request.contextPath}/admin/jwtTest.html';

    window.jwtTestOpen = () => {
        _jwtTokenRef = null;
        ['jwtRow0','jwtRow1','jwtRow2','jwtRow3'].forEach(id => {
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

    window.jwtTestClose = () => {
        document.getElementById('jwtTestModal').style.display = 'none';
    }

    window.jwtSetRow = (id, ok, message) => {
        const el = document.getElementById(id);
        el.textContent = (ok ? '\u2713 ' : '\u2717 ') + message;
        el.style.color = ok ? '#7ec87e' : '#e06c75';
    }

    window.jwtPost = (params) => {
        const body = Object.entries(params)
            .map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v))
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
        }).then(r => r.json());
    }

    // jwtTestRunChecks and jwtTestExchange are defined inside $j(document).ready()
    // so they can access connectionData. They are assigned to window.* for the inline
    // onclick handlers on the modal buttons.

    (() => {
        // Hide the empty groupingTitle row the l:settingsGroup tag always renders
        document.querySelectorAll('tr.groupingTitle').forEach(tr => {
            if (!tr.textContent.trim()) tr.style.display = 'none';
        });
    })();

    $j(document).ready(() => {
        const placeholder = $j('span#editBuildFeatureAdditionalButtons');
        if (placeholder.length) {
            placeholder.empty();
            placeholder.append($j('span#jwtTestConnectionBtnHolder').children());
        }

        // Initialise checkboxes from the stored subject-scoping value.
        // Blank = no optional dimensions (the default for a fresh feature); the resulting
        // `sub` is just project:<id>:build_type:<id>. Comma-separated names enable the
        // listed dimensions.
        const stored = $j('#subject_dimensions').val().trim();
        const enabled = stored === '' ? [] : stored.split(/\s*,\s*/);
        $j('.jwt-subject-dimension-cb').each((_, el) => {
            $j(el).prop('checked', enabled.includes(el.value));
        });

        // Live preview of the resulting sub claim. Uses real sample values from the
        // last finished build when available, falling back to <name> placeholders
        // so the shape of the composed sub is always visible.
        const previewData = $j('#jwtSubjectPreviewData');
        // On a template there is no concrete project/build type, so fall back to the
        // <project_id>/<build_type_id> placeholders to keep the composed sub's shape visible.
        const projectId = previewData.attr('data-project-id') || '<project_id>';
        const buildTypeId = previewData.attr('data-build-type-id') || '<build_type_id>';
        const sampleBranch = previewData.attr('data-sample-branch') || '<branch>';
        const sampleTriggerType = previewData.attr('data-sample-trigger-type') || '<trigger_type>';

        function updatePreview() {
            let sub = 'project:' + projectId + ':build_type:' + buildTypeId;
            if ($j('.jwt-subject-dimension-cb[value="branch"]').is(':checked')) {
                sub += ':branch:' + sampleBranch;
            }
            if ($j('.jwt-subject-dimension-cb[value="trigger_type"]').is(':checked')) {
                sub += ':trigger_type:' + sampleTriggerType;
            }
            $j('#jwtSubjectPreview').val(sub);
        }

        // Sync hidden field and preview on every checkbox change.
        // None checked → blank; some/all checked → comma-separated list.
        $j('.jwt-subject-dimension-cb').on('change', () => {
            const checked = $j('.jwt-subject-dimension-cb:checked').map((_, el) => el.value).get();
            $j('#subject_dimensions').val(checked.join(','));
            updatePreview();
        });

        updatePreview();

        // Read connection metadata once from the data-* attributes emitted by the JSP.
        const connectionData = {};
        $j('#jwtConnectionsData .jwt-connection-entry').each((_, el) => {
            const $e = $j(el);
            connectionData[$e.attr('data-id')] = {
                displayName: $e.attr('data-display-name'),
                audience: $e.attr('data-audience'),
                ttl: $e.attr('data-ttl'),
                algorithm: $e.attr('data-algorithm'),
                subjectDimensions: $e.attr('data-subject-dimensions'),
                tokenVariableName: $e.attr('data-token-variable-name')
            };
        });

        // Helper: resolve algorithm/ttl/audience from the selected connection (if any),
        // falling back to the inline form fields when no connection is selected.
        const resolveTestParams = () => {
            const selectedConn = document.getElementById('connection_id') ? document.getElementById('connection_id').value : '';
            const fromConn = selectedConn && connectionData[selectedConn];
            return {
                algorithm: fromConn ? fromConn.algorithm : document.getElementById('algorithm').value,
                ttl: fromConn ? fromConn.ttl : (document.getElementById('ttl_minutes').value || '10'),
                audience: fromConn ? fromConn.audience : document.getElementById('audience').value
            };
        };

        window.jwtTestRunChecks = async () => {
            const {algorithm, ttl, audience} = resolveTestParams();
            const buildTypeId = document.getElementById('jwtTestConnectionBtnHolder').dataset.buildTypeId || '';

            document.getElementById('jwtRow0').textContent = '⏳ Issuing JWT...';
            const r1 = await jwtPost({step:'jwt', algorithm:algorithm, ttl_minutes:ttl, audience:audience, buildTypeId:buildTypeId});
            jwtSetRow('jwtRow0', r1.ok, r1.message);
            if (!r1.ok) return;
            _jwtTokenRef = r1.tokenRef;

            document.getElementById('jwtRow1').textContent = '⏳ Checking discovery endpoint...';
            const r2 = await jwtPost({step:'discovery'});
            jwtSetRow('jwtRow1', r2.ok, r2.message);
            if (!r2.ok) return;

            document.getElementById('jwtRow2').textContent = '⏳ Verifying JWKS signature...';
            const r3 = await jwtPost({step:'jwks', tokenRef:_jwtTokenRef});
            jwtSetRow('jwtRow2', r3.ok, r3.message);
            if (!r3.ok) return;

            document.getElementById('jwtServiceUrl').disabled = false;
            document.getElementById('jwtExchangeBtn').disabled = false;
        };

        window.jwtTestExchange = async () => {
            const serviceUrl = document.getElementById('jwtServiceUrl').value.trim();
            if (!serviceUrl) return;
            const {algorithm, ttl, audience} = resolveTestParams();
            const buildTypeId = document.getElementById('jwtTestConnectionBtnHolder').dataset.buildTypeId || '';
            document.getElementById('jwtExchangeBtn').disabled = true;
            document.getElementById('jwtRow3').textContent = '⏳ Issuing fresh JWT for exchange...';
            document.getElementById('jwtRow3').style.color = '#888';
            // Issue a fresh token each time — the 1-minute TTL may have expired since
            // the initial Test Connection checks ran.
            const r1 = await jwtPost({step:'jwt', algorithm:algorithm, ttl_minutes:ttl, audience:audience, buildTypeId:buildTypeId});
            if (!r1.ok) {
                jwtSetRow('jwtRow3', false, 'Could not issue JWT: ' + r1.message);
                document.getElementById('jwtExchangeBtn').disabled = false;
                return;
            }
            const r = await jwtPost({step:'exchange', tokenRef:r1.tokenRef, serviceUrl:serviceUrl, audience:audience});
            jwtSetRow('jwtRow3', r.ok, r.message);
            document.getElementById('jwtExchangeBtn').disabled = false;
        };

        // When a connection is selected, overlay the inline form fields with the
        // connection's values and lock them. When the user deselects the connection,
        // restore the previously-saved inline values from the per-input cache.
        const cacheInline = ($el, value) => {
            if ($el.data('inlineCached') === undefined) {
                $el.data('inlineCached', value);
            }
        };
        const restoreInline = ($el) => {
            if ($el.data('inlineCached') !== undefined) {
                $el.val($el.data('inlineCached'));
                $el.removeData('inlineCached');
            }
        };

        const refreshConnectionUI = () => {
            const selected = $j('#connection_id').val();
            const selectedConnection = selected && connectionData[selected];

            const $varName = $j('#token_variable_name');
            $varName.attr('placeholder', selectedConnection
                ? (selectedConnection.tokenVariableName || 'jwt.token')
                : 'jwt.token');

            const $ttl = $j('#ttl_minutes');
            const $aud = $j('#audience');
            const $alg = $j('#algorithm');
            const $subj = $j('#subject_dimensions');
            const subjectCheckboxes = $j('.jwt-subject-dimension-cb');

            if (selectedConnection) {
                cacheInline($aud, $aud.val());
                cacheInline($alg, $alg.val());
                cacheInline($subj, $subj.val());

                // TTL is an override, not connection-authoritative: editable, with the connection's TTL as the "inherit" placeholder.
                $ttl.attr('placeholder', selectedConnection.ttl).prop('readonly', false).removeClass('jwt-locked');
                $aud.val(selectedConnection.audience).prop('readonly', true).addClass('jwt-locked');
                $alg.val(selectedConnection.algorithm).prop('disabled', true).addClass('jwt-locked');
                $subj.val(selectedConnection.subjectDimensions || '');
                const subjectDimensions = (selectedConnection.subjectDimensions || '').split(',').filter(s => s.length > 0);
                subjectCheckboxes.each((_, el) => {
                    el.checked = subjectDimensions.indexOf(el.value) !== -1;
                    el.disabled = true;
                });
            } else {
                restoreInline($aud);
                restoreInline($alg);
                restoreInline($subj);
                $ttl.attr('placeholder', '10').prop('readonly', false).removeClass('jwt-locked');
                $aud.prop('readonly', false).removeClass('jwt-locked');
                $alg.prop('disabled', false).removeClass('jwt-locked');
                const subjectDimensions = $subj.val().split(',').filter(s => s.length > 0);
                subjectCheckboxes.each((_, el) => {
                    el.checked = subjectDimensions.indexOf(el.value) !== -1;
                    el.disabled = false;
                });
            }
            updatePreview();
        };

        $j('#connection_id').on('change', refreshConnectionUI);
        refreshConnectionUI();
    });
</script>
