<%@ page contentType="text/html;charset=UTF-8" pageEncoding="UTF-8" %>
<%@ include file="/include-internal.jsp"%>
<%@ taglib prefix="props" tagdir="/WEB-INF/tags/props" %>
<%@ taglib prefix="l" tagdir="/WEB-INF/tags/layout" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<%@ page import="com.octopus.teamcity.oidc.JwtBuildFeature" %>
<%
    pageContext.setAttribute("maxTokenLifetimeMinutes", JwtBuildFeature.maxTokenLifetimeMinutes());
%>
<link rel="stylesheet" href="${pageContext.request.contextPath}/plugins/teamcity-oidc-plugin/jwt-admin.css"/>

<tr>
    <th><nobr><label for="displayName">Display name: <l:star/></label></nobr></th>
    <td>
        <props:textProperty name="displayName" value="${propertiesBean.properties['displayName']}" style="width:30em;"/>
        <span class="smallNote">Label shown in the build feature dropdown and the connections list.</span>
        <span class="error" id="error_displayName"></span>
    </td>
</tr>
<tr>
    <th><nobr><label for="ttl_minutes">Token lifetime (minutes):</label></nobr></th>
    <td>
        <props:textProperty name="ttl_minutes" style="width:5em;"/>
        <span class="smallNote">How long the JWT is valid for.<br/>Default: 10 minutes; max: <c:out value="${maxTokenLifetimeMinutes}"/> minutes.</span>
        <span class="error" id="error_ttl_minutes"></span>
    </td>
</tr>
<tr>
    <th><nobr><label for="audience">Audience (<code>aud</code>):</label></nobr></th>
    <td>
        <props:textProperty name="audience" style="width:30em;"/>
        <span class="smallNote">Value for the <code>aud</code> claim. Leave blank to use the TeamCity server URL. Cloud providers often require a specific value here (e.g. <code>api://AzureADTokenExchange</code> for Entra ID).</span>
        <span class="error" id="error_audience"></span>
    </td>
</tr>
<tr>
    <th><nobr><label for="algorithm">Signing algorithm:</label></nobr></th>
    <td>
        <props:selectProperty name="algorithm">
            <props:option value="RS256">RS256 (RSA-2048, default)</props:option>
            <props:option value="RS384">RS384 (RSA-3072)</props:option>
            <props:option value="ES256">ES256 (ECDSA P-256)</props:option>
        </props:selectProperty>
        <span class="smallNote">ES256 produces smaller tokens and is widely supported by cloud providers. RS384 uses a 3072-bit RSA key.</span>
    </td>
</tr>
<tr>
    <th><nobr><label>Subject scoping:</label></nobr></th>
    <td>
        <%-- Hidden field holds the comma-separated value that TC saves; JS keeps it in sync --%>
        <props:hiddenProperty name="subject_dimensions" id="subject_dimensions"/>
        <span class="smallNote">
            Choose which dimensions appear in <code>sub</code>; claims are emitted separately in the token regardless.
        </span>
        <ul class="jwt-subject-dimensions">
            <li><label title="Always included - required to identify the source project"><input type="checkbox" checked disabled/> project</label></li>
            <li><label title="Always included - required to identify the source build configuration"><input type="checkbox" checked disabled/> build_type</label></li>
            <li><label><input type="checkbox" class="oidc-conn-dimension-cb" value="branch"/> branch</label></li>
            <li>
                <label><input type="checkbox" class="oidc-conn-dimension-cb" value="trigger_type"/> trigger_type</label>
                <span class="smallNote jwt-subject-dimensions-tooltip"
                      title="Possible values: user, snapshotDependency, vcsTrigger, schedulingTrigger, retryBuildTrigger, buildDependencyTrigger, finishBuildTrigger, perforceShelveTrigger, unknown">[?]</span>
            </li>
        </ul>
        <div class="jwt-subject-preview">
            <label for="oidcConnSubjectPreview">Resulting <code>sub</code> claim:</label>
            <input id="oidcConnSubjectPreview" type="text" readonly/>
        </div>
        <span class="error" id="error_subject_dimensions"></span>
    </td>
</tr>
<tr>
    <th><nobr>Setup guides:</nobr></th>
    <td>
        <span class="smallNote">
            <a href="https://github.com/OctopusDeploy/teamcity-oidc-plugin/blob/main/docs/aws.md" target="_blank" rel="noopener">AWS</a> &middot;
            <a href="https://github.com/OctopusDeploy/teamcity-oidc-plugin/blob/main/docs/azure.md" target="_blank" rel="noopener">Azure</a> &middot;
            <a href="https://github.com/OctopusDeploy/teamcity-oidc-plugin/blob/main/docs/artifactory.md" target="_blank" rel="noopener">JFrog Artifactory</a> &middot;
            <a href="https://github.com/OctopusDeploy/teamcity-oidc-plugin/blob/main/docs/octopus-deploy.md" target="_blank" rel="noopener">Octopus Deploy</a>
        </span>
    </td>
</tr>

<script type="text/javascript">
    // Hide the redundant "Connection type:" row TC's dialog chrome renders
    // before our fragment, and surface the type name in the OAuth title heading
    // (TC leaves #OAuthConnectionTitle empty for unknown providers).
    $j(document).ready(() => {
        $j('th').filter((_, th) => $j(th).text().trim().startsWith('Connection type'))
                .closest('tr').hide();
        const title = $j('#OAuthConnectionTitle');
        if (title.length) {
            title.text('OIDC Identity Token').show();
        }
        $j('#displayName').attr('placeholder', 'e.g. Octopus production');
    });
</script>

<script type="text/javascript">
    $j(document).ready(() => {
        const stored = $j('#subject_dimensions').val().trim();
        const enabled = stored === '' ? [] : stored.split(/\s*,\s*/);
        $j('.oidc-conn-dimension-cb').each((_, el) => {
            $j(el).prop('checked', enabled.includes(el.value));
        });

        const updatePreview = () => {
            let sub = 'project:<project_id>:build_type:<build_type_id>';
            if ($j('.oidc-conn-dimension-cb[value="branch"]').is(':checked')) {
                sub += ':branch:<branch>';
            }
            if ($j('.oidc-conn-dimension-cb[value="trigger_type"]').is(':checked')) {
                sub += ':trigger_type:<trigger_type>';
            }
            $j('#oidcConnSubjectPreview').val(sub);
        };

        $j('.oidc-conn-dimension-cb').on('change', () => {
            const checked = $j('.oidc-conn-dimension-cb:checked').map((_, el) => el.value).get();
            $j('#subject_dimensions').val(checked.join(','));
            updatePreview();
        });

        updatePreview();
    });
</script>
