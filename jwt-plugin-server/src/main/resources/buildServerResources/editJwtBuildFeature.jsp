<%@ include file="/include-internal.jsp"%>
<%@ taglib prefix="props" tagdir="/WEB-INF/tags/props" %>
<%@ taglib prefix="l" tagdir="/WEB-INF/tags/layout" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<l:settingsGroup title="JWT Build Feature">
    <tr>
        <th><label for="ttl_minutes">Token lifetime (minutes):</label></th>
        <td>
            <props:textProperty name="ttl_minutes" value="${empty param.ttl_minutes ? '10' : param.ttl_minutes}" style="width:5em;"/>
            <span class="smallNote">How long the JWT is valid for. Default: 10 minutes.</span>
            <span class="error" id="error_ttl_minutes"></span>
        </td>
    </tr>
    <tr>
        <th><label for="audience">Audience (<code>aud</code>):</label></th>
        <td>
            <props:textProperty name="audience" value="${param.audience}" style="width:30em;"/>
            <span class="smallNote">Value for the <code>aud</code> claim. Leave blank to use the TeamCity server URL. Cloud providers often require a specific value here (e.g. <code>api://AzureADTokenExchange</code>).</span>
            <span class="error" id="error_audience"></span>
        </td>
    </tr>
    <tr>
        <th><label for="algorithm">Signing algorithm:</label></th>
        <td>
            <props:selectProperty name="algorithm">
                <props:option value="RS256" selected="${empty param.algorithm || param.algorithm == 'RS256'}">RS256 (RSA, default)</props:option>
                <props:option value="ES256" selected="${param.algorithm == 'ES256'}">ES256 (ECDSA P-256)</props:option>
            </props:selectProperty>
            <span class="smallNote">ES256 produces smaller tokens and is widely supported by cloud providers.</span>
        </td>
    </tr>
    <tr>
        <th><label for="claims">Claims to include:</label></th>
        <td>
            <props:textProperty name="claims" value="${param.claims}" style="width:40em;"/>
            <span class="smallNote">Comma-separated list of claims to include in the token. Leave blank to include all.
                Available: <code>branch</code>, <code>build_type_external_id</code>, <code>project_external_id</code>,
                <code>triggered_by</code>, <code>triggered_by_id</code>, <code>build_number</code>.</span>
            <span class="error" id="error_claims"></span>
        </td>
    </tr>
</l:settingsGroup>
