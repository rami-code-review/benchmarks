// CVE-inspired vulnerability patterns for Java.
// These patterns are based on real-world vulnerabilities and common attack vectors.
package benchmarks;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.sql.*;
import java.util.*;
import javax.crypto.*;
import javax.servlet.http.*;
import javax.xml.parsers.*;

// =============================================================================
// CVE-2021-44228 - Log4Shell style patterns
// =============================================================================

class CVELog4ShellPatterns {
    private java.util.logging.Logger logger = java.util.logging.Logger.getLogger("app");

    // java-cve-log4shell-lookup: JNDI lookup in log message
    public void logUserAgentUnsafe(HttpServletRequest request) {
        // UNSAFE: User-controlled data in log (Log4j would interpret JNDI lookups)
        String userAgent = request.getHeader("User-Agent");
        logger.info("User agent: " + userAgent);
    }

    // java-cve-log4shell-lookup-fix: Sanitize before logging
    public void logUserAgentSafe(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        // Remove potential JNDI lookup patterns
        String safeUserAgent = userAgent.replaceAll("\\$\\{[^}]*\\}", "[FILTERED]");
        logger.info("User agent: " + safeUserAgent);
    }
}

// =============================================================================
// CVE-2017-5638 - Apache Struts (Content-Type parsing)
// =============================================================================

class CVEStrutsPatterns {

    // java-cve-struts-header: Unsafe header parsing
    public void handleContentTypeUnsafe(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        // UNSAFE: Content-Type header directly used
        String contentType = request.getContentType();
        response.getWriter().write("Received content type: " + contentType);
    }

    // java-cve-struts-header-fix: Validate Content-Type
    public void handleContentTypeSafe(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String contentType = request.getContentType();
        Set<String> allowedTypes = Set.of("application/json", "application/xml", "text/plain");

        String baseType = contentType.split(";")[0].trim().toLowerCase();
        if (!allowedTypes.contains(baseType)) {
            response.sendError(415, "Unsupported media type");
            return;
        }
        response.getWriter().write("Received content type: " + baseType);
    }
}

// =============================================================================
// CVE-2019-0192 - Apache Solr Deserialization
// =============================================================================

class CVEDeserializationPatterns {

    // java-cve-deser-config: Config-driven deserialization
    public Object loadConfigUnsafe(String configPath) throws Exception {
        // UNSAFE: Deserializing config from file
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(configPath))) {
            return ois.readObject();
        }
    }

    // java-cve-deser-config-fix: Use safe configuration format
    public Properties loadConfigSafe(String configPath) throws Exception {
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(configPath)) {
            props.load(fis);
        }
        return props;
    }

    // java-cve-deser-rmi: RMI-based deserialization
    public Object lookupRemoteUnsafe(String rmiUrl) throws Exception {
        // UNSAFE: Connecting to untrusted RMI registry
        java.rmi.registry.Registry registry =
            java.rmi.registry.LocateRegistry.getRegistry(rmiUrl);
        return registry.lookup("RemoteService");
    }

    // java-cve-deser-rmi-fix: Validate RMI endpoint
    public Object lookupRemoteSafe(String rmiHost) throws Exception {
        Set<String> trustedHosts = Set.of("internal.example.com", "rmi.example.com");
        if (!trustedHosts.contains(rmiHost)) {
            throw new SecurityException("Untrusted RMI host: " + rmiHost);
        }
        java.rmi.registry.Registry registry =
            java.rmi.registry.LocateRegistry.getRegistry(rmiHost);
        return registry.lookup("RemoteService");
    }
}

// =============================================================================
// CVE-2018-1000861 - Jenkins Stapler Web Framework
// =============================================================================

class CVEAccessControlPatterns {

    // java-cve-idor-direct: Direct object reference
    public String getDocumentUnsafe(HttpServletRequest request) throws Exception {
        // UNSAFE: No authorization check
        String docId = request.getParameter("id");
        return readDocument(docId);
    }

    // java-cve-idor-direct-fix: Authorization check
    public String getDocumentSafe(HttpServletRequest request) throws Exception {
        String docId = request.getParameter("id");
        String userId = (String) request.getSession().getAttribute("userId");

        if (!isAuthorized(userId, docId)) {
            throw new SecurityException("Access denied");
        }
        return readDocument(docId);
    }

    // java-cve-priv-esc: Privilege escalation via role parameter
    public void updateUserRoleUnsafe(HttpServletRequest request) {
        // UNSAFE: Role from request parameter
        String userId = request.getParameter("userId");
        String newRole = request.getParameter("role");
        updateRole(userId, newRole);
    }

    // java-cve-priv-esc-fix: Require admin session
    public void updateUserRoleSafe(HttpServletRequest request) throws SecurityException {
        HttpSession session = request.getSession(false);
        if (session == null || !"admin".equals(session.getAttribute("role"))) {
            throw new SecurityException("Admin access required");
        }

        String userId = request.getParameter("userId");
        String newRole = request.getParameter("role");
        Set<String> validRoles = Set.of("user", "moderator", "admin");
        if (!validRoles.contains(newRole)) {
            throw new IllegalArgumentException("Invalid role");
        }
        updateRole(userId, newRole);
    }

    private String readDocument(String id) { return "content"; }
    private boolean isAuthorized(String userId, String docId) { return true; }
    private void updateRole(String userId, String role) { }
}

// =============================================================================
// CVE-2021-22118 - Spring Framework Directory Traversal
// =============================================================================

class CVESpringPatterns {

    // java-cve-spring-pathtraversal: Spring resource path traversal
    public byte[] serveResourceUnsafe(String resourcePath) throws Exception {
        // UNSAFE: Direct path usage
        return Files.readAllBytes(Paths.get("static/" + resourcePath));
    }

    // java-cve-spring-pathtraversal-fix: Validate path
    public byte[] serveResourceSafe(String resourcePath) throws Exception {
        Path base = Paths.get("static/").toAbsolutePath().normalize();
        Path resource = base.resolve(resourcePath).normalize();

        if (!resource.startsWith(base)) {
            throw new SecurityException("Path traversal detected");
        }
        return Files.readAllBytes(resource);
    }

    // java-cve-spring-spel: SpEL injection
    public Object evaluateExpressionUnsafe(String expression) {
        // UNSAFE: User-controlled SpEL expression
        org.springframework.expression.ExpressionParser parser =
            new org.springframework.expression.spel.standard.SpelExpressionParser();
        return parser.parseExpression(expression).getValue();
    }

    // java-cve-spring-spel-fix: Restricted SpEL context
    public Object evaluateExpressionSafe(String expression) {
        org.springframework.expression.ExpressionParser parser =
            new org.springframework.expression.spel.standard.SpelExpressionParser();
        org.springframework.expression.spel.support.SimpleEvaluationContext context =
            org.springframework.expression.spel.support.SimpleEvaluationContext.forReadOnlyDataBinding().build();
        return parser.parseExpression(expression).getValue(context);
    }
}

// =============================================================================
// CVE-2020-9484 - Apache Tomcat Session Persistence
// =============================================================================

class CVETomcatPatterns {

    // java-cve-session-fixation: Session fixation
    public void loginUnsafe(HttpServletRequest request, String username) {
        // UNSAFE: Session not invalidated after authentication
        HttpSession session = request.getSession();
        session.setAttribute("user", username);
        session.setAttribute("authenticated", true);
    }

    // java-cve-session-fixation-fix: Invalidate session on login
    public void loginSafe(HttpServletRequest request, String username) {
        // Invalidate existing session
        HttpSession oldSession = request.getSession(false);
        if (oldSession != null) {
            oldSession.invalidate();
        }

        // Create new session
        HttpSession newSession = request.getSession(true);
        newSession.setAttribute("user", username);
        newSession.setAttribute("authenticated", true);
    }
}

// =============================================================================
// CVE-2014-0094 - Apache Struts ClassLoader Manipulation
// =============================================================================

class CVEReflectionPatterns {

    // java-cve-classloader: Class instantiation from user input
    public Object createInstanceUnsafe(String className) throws Exception {
        // UNSAFE: Arbitrary class instantiation
        Class<?> clazz = Class.forName(className);
        return clazz.getDeclaredConstructor().newInstance();
    }

    // java-cve-classloader-fix: Allowlist classes
    public Object createInstanceSafe(String className) throws Exception {
        Set<String> allowedClasses = Set.of(
            "com.example.UserService",
            "com.example.OrderService"
        );

        if (!allowedClasses.contains(className)) {
            throw new SecurityException("Class not in allowlist: " + className);
        }

        Class<?> clazz = Class.forName(className);
        return clazz.getDeclaredConstructor().newInstance();
    }

    // java-cve-method-invoke: Unsafe method invocation
    public Object invokeMethodUnsafe(Object target, String methodName) throws Exception {
        // UNSAFE: Arbitrary method invocation
        java.lang.reflect.Method method = target.getClass().getMethod(methodName);
        return method.invoke(target);
    }

    // java-cve-method-invoke-fix: Allowlist methods
    public Object invokeMethodSafe(Object target, String methodName) throws Exception {
        Set<String> allowedMethods = Set.of("getName", "getId", "toString");

        if (!allowedMethods.contains(methodName)) {
            throw new SecurityException("Method not allowed: " + methodName);
        }

        java.lang.reflect.Method method = target.getClass().getMethod(methodName);
        return method.invoke(target);
    }
}

// =============================================================================
// CVE-2019-17571 - Log4j SocketServer Deserialization
// =============================================================================

class CVENetworkPatterns {

    // java-cve-socket-deser: Network deserialization
    public Object receiveObjectUnsafe(Socket socket) throws Exception {
        // UNSAFE: Deserializing from network
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        return ois.readObject();
    }

    // java-cve-socket-deser-fix: Use safe data format
    public String receiveDataSafe(Socket socket) throws Exception {
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(socket.getInputStream())
        );
        return reader.readLine(); // Plain text, not serialized objects
    }

    // java-cve-dns-rebinding: DNS rebinding vulnerability
    public boolean validateHostUnsafe(String url) throws Exception {
        // UNSAFE: Host validated once, may change
        URL urlObj = new URL(url);
        InetAddress addr = InetAddress.getByName(urlObj.getHost());

        if (addr.isLoopbackAddress()) {
            return false;
        }
        return true;
    }

    // java-cve-dns-rebinding-fix: Pin resolved address
    public String fetchWithPinnedDNS(String url) throws Exception {
        URL urlObj = new URL(url);
        InetAddress addr = InetAddress.getByName(urlObj.getHost());

        if (addr.isLoopbackAddress() || addr.isSiteLocalAddress()) {
            throw new SecurityException("Internal address not allowed");
        }

        // Connect using resolved IP directly
        HttpURLConnection conn = (HttpURLConnection) new URL(
            urlObj.getProtocol() + "://" + addr.getHostAddress() + ":" +
            (urlObj.getPort() != -1 ? urlObj.getPort() : urlObj.getDefaultPort()) +
            urlObj.getPath()
        ).openConnection();
        conn.setRequestProperty("Host", urlObj.getHost());

        return new String(conn.getInputStream().readAllBytes());
    }
}

// =============================================================================
// CVE-2020-5421 - Spring Framework RFD Attack
// =============================================================================

class CVEResponsePatterns {

    // java-cve-content-type: Content-Type injection
    public void serveFileUnsafe(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        // UNSAFE: User-controlled content type
        String contentType = request.getParameter("type");
        String filename = request.getParameter("file");

        response.setContentType(contentType);
        response.getOutputStream().write(Files.readAllBytes(Paths.get("files/" + filename)));
    }

    // java-cve-content-type-fix: Validate content type
    public void serveFileSafe(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String filename = request.getParameter("file");

        // Determine content type from file extension
        Map<String, String> mimeTypes = Map.of(
            "txt", "text/plain",
            "pdf", "application/pdf",
            "jpg", "image/jpeg",
            "png", "image/png"
        );

        String ext = filename.substring(filename.lastIndexOf('.') + 1).toLowerCase();
        String contentType = mimeTypes.getOrDefault(ext, "application/octet-stream");

        // Validate filename
        if (!filename.matches("[a-zA-Z0-9_-]+\\.[a-zA-Z]+")) {
            response.sendError(400, "Invalid filename");
            return;
        }

        response.setContentType(contentType);
        response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
        response.getOutputStream().write(Files.readAllBytes(Paths.get("files/" + filename)));
    }

    // java-cve-header-injection: HTTP header injection
    public void redirectUnsafe(HttpServletResponse response, String url) throws Exception {
        // UNSAFE: CRLF injection possible
        response.setHeader("Location", url);
        response.setStatus(302);
    }

    // java-cve-header-injection-fix: Sanitize header value
    public void redirectSafe(HttpServletResponse response, String url) throws Exception {
        // Remove any CRLF characters
        String safeUrl = url.replaceAll("[\\r\\n]", "");

        // Validate URL format
        new URL(safeUrl); // Throws if invalid

        response.setHeader("Location", safeUrl);
        response.setStatus(302);
    }
}

// =============================================================================
// CVE-2021-26291 - Apache Maven Dependency Confusion
// =============================================================================

class CVESupplyChainPatterns {

    // java-cve-exec-download: Downloading and executing code
    public void updatePluginUnsafe(String pluginUrl) throws Exception {
        // UNSAFE: Downloading and loading untrusted code
        URL url = new URL(pluginUrl);
        byte[] data = url.openStream().readAllBytes();
        Files.write(Paths.get("plugins/plugin.jar"), data);

        // Load the jar
        URLClassLoader loader = new URLClassLoader(
            new URL[]{Paths.get("plugins/plugin.jar").toUri().toURL()}
        );
        Class<?> pluginClass = loader.loadClass("com.plugin.Main");
        pluginClass.getDeclaredConstructor().newInstance();
    }

    // java-cve-exec-download-fix: Verify signatures
    public void updatePluginSafe(String pluginUrl, String expectedHash) throws Exception {
        URL url = new URL(pluginUrl);

        // Only allow trusted sources
        Set<String> trustedHosts = Set.of("plugins.example.com", "maven.example.com");
        if (!trustedHosts.contains(url.getHost())) {
            throw new SecurityException("Untrusted plugin source");
        }

        byte[] data = url.openStream().readAllBytes();

        // Verify hash
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(data);
        String actualHash = bytesToHex(hash);

        if (!actualHash.equals(expectedHash)) {
            throw new SecurityException("Plugin hash mismatch");
        }

        Files.write(Paths.get("plugins/plugin.jar"), data);
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

// =============================================================================
// CVE-2022-22965 - Spring4Shell
// =============================================================================

class CVESpring4ShellPatterns {

    // java-cve-spring4shell: Property binding to class loader
    public void bindRequestUnsafe(Object target, HttpServletRequest request) throws Exception {
        // UNSAFE: Binding request params to object properties
        Map<String, String[]> params = request.getParameterMap();
        for (Map.Entry<String, String[]> entry : params.entrySet()) {
            String propertyName = entry.getKey();
            String value = entry.getValue()[0];

            // Reflective property setting
            java.lang.reflect.Method setter = findSetter(target.getClass(), propertyName);
            if (setter != null) {
                setter.invoke(target, value);
            }
        }
    }

    // java-cve-spring4shell-fix: Block dangerous property paths
    public void bindRequestSafe(Object target, HttpServletRequest request) throws Exception {
        Set<String> blockedPatterns = Set.of(
            "class.classLoader",
            "class.module",
            "class.protectionDomain"
        );

        Map<String, String[]> params = request.getParameterMap();
        for (Map.Entry<String, String[]> entry : params.entrySet()) {
            String propertyName = entry.getKey();

            // Block dangerous property paths
            for (String blocked : blockedPatterns) {
                if (propertyName.toLowerCase().contains(blocked.toLowerCase())) {
                    throw new SecurityException("Blocked property path: " + propertyName);
                }
            }

            String value = entry.getValue()[0];
            java.lang.reflect.Method setter = findSetter(target.getClass(), propertyName);
            if (setter != null) {
                setter.invoke(target, value);
            }
        }
    }

    private java.lang.reflect.Method findSetter(Class<?> clazz, String propertyName) {
        String setterName = "set" + propertyName.substring(0, 1).toUpperCase() + propertyName.substring(1);
        for (java.lang.reflect.Method method : clazz.getMethods()) {
            if (method.getName().equals(setterName) && method.getParameterCount() == 1) {
                return method;
            }
        }
        return null;
    }
}

// =============================================================================
// CVE-2022-42889 - Apache Commons Text (Text4Shell)
// =============================================================================

class CVEText4ShellPatterns {

    // java-cve-text4shell: String interpolation with lookups
    public String formatMessageUnsafe(String template, Map<String, String> vars) {
        // UNSAFE: Using interpolation that supports lookups
        org.apache.commons.text.StringSubstitutor sub =
            new org.apache.commons.text.StringSubstitutor(vars);
        return sub.replace(template);
    }

    // java-cve-text4shell-fix: Disable lookups
    public String formatMessageSafe(String template, Map<String, String> vars) {
        org.apache.commons.text.StringSubstitutor sub =
            new org.apache.commons.text.StringSubstitutor(vars);
        sub.setDisableSubstitutionInValues(true);
        sub.setEnableUndefinedVariableException(true);
        return sub.replace(template);
    }
}

// =============================================================================
// FALSE POSITIVE PATTERNS
// =============================================================================

class JavaFalsePositivePatterns {

    // java-fp-sql-allowlist: SQL with allowlisted table
    public ResultSet queryAllowedTable(Connection conn, String tableKey) throws SQLException {
        Map<String, String> allowedTables = Map.of(
            "users", "app_users",
            "orders", "app_orders"
        );

        String table = allowedTables.get(tableKey);
        if (table == null) {
            throw new IllegalArgumentException("Invalid table");
        }

        // Safe: table from allowlist, not user input
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM " + table + " WHERE active = ?");
        ps.setBoolean(1, true);
        return ps.executeQuery();
    }

    // java-fp-cmd-constant: Command with constant arguments
    public void runConstantCommand() throws Exception {
        // Safe: No user input
        new ProcessBuilder("ls", "-la", "/var/log").start();
    }

    // java-fp-deser-internal: Internal deserialization
    public Object deserializeInternal(byte[] data) throws Exception {
        // Safe: Data from trusted internal source, not user input
        // This would require more context to determine safety
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }

    // java-fp-reflection-constant: Reflection with constant class
    public Object createKnownClass() throws Exception {
        // Safe: Class name is constant
        Class<?> clazz = Class.forName("java.util.ArrayList");
        return clazz.getDeclaredConstructor().newInstance();
    }
}
