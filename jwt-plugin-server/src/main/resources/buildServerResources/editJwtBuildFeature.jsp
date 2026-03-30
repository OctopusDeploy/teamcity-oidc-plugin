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
</l:settingsGroup>
