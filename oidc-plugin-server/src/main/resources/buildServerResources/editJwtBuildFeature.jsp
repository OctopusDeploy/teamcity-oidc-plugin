<%@ include file="/include-internal.jsp"%>
<%@ taglib prefix="props" tagdir="/WEB-INF/tags/props" %>
<%@ taglib prefix="l" tagdir="/WEB-INF/tags/layout" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<jsp:useBean id="buildForm" type="jetbrains.buildServer.controllers.admin.projects.EditableBuildTypeSettingsForm" scope="request"/>

<l:settingsGroup title="">
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

<script type="text/javascript">
    $j(document).ready(function() {
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
