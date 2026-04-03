<%@ include file="/include-internal.jsp"%>
<%@ taglib prefix="props" tagdir="/WEB-INF/tags/props" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

JWKS:
<pre>
<c:out value="${jwks}" />
</pre>
<a href="data:application/json;charset=utf-8;base64,${jwksBase64}" download="jwks.json">download</a>
