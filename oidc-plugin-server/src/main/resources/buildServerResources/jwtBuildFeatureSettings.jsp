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

JWKS:
<pre>
<c:out value="${jwks}" />
</pre>
<a href="data:application/json;charset=utf-8;base64,${jwksBase64}" download="jwks.json">download</a>
