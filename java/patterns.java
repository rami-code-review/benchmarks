// Benchmark patterns for Java security and quality detection.
// Each method represents a template pattern for testing code review capabilities.
package benchmarks;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.servlet.http.*;

// =============================================================================
// SQL INJECTION PATTERNS
// =============================================================================

class SQLInjectionPatterns {
    private Connection conn;
    private PreparedStatement pstmt;

    // java-sqli-concat-easy: String concatenation in SQL
    public ResultSet getUserByIdUnsafe(String userId) throws SQLException {
        // UNSAFE: String concatenation
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        return conn.createStatement().executeQuery(query);
    }

    // java-sqli-concat-easy-fix: Parameterized query
    public ResultSet getUserByIdSafe(String userId) throws SQLException {
        pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        pstmt.setString(1, userId);
        return pstmt.executeQuery();
    }

    // java-sqli-format-easy: String.format in SQL
    public ResultSet searchUsersUnsafe(String name) throws SQLException {
        // UNSAFE: String.format
        String query = String.format("SELECT * FROM users WHERE name LIKE '%%%s%%'", name);
        return conn.createStatement().executeQuery(query);
    }

    // java-sqli-format-easy-fix: Parameterized LIKE query
    public ResultSet searchUsersSafe(String name) throws SQLException {
        pstmt = conn.prepareStatement("SELECT * FROM users WHERE name LIKE ?");
        pstmt.setString(1, "%" + name + "%");
        return pstmt.executeQuery();
    }

    // java-sqli-builder-medium: StringBuilder SQL construction
    public ResultSet queryWithFiltersUnsafe(Map<String, String> filters) throws SQLException {
        // UNSAFE: Dynamic SQL building
        StringBuilder query = new StringBuilder("SELECT * FROM users WHERE 1=1");
        for (Map.Entry<String, String> entry : filters.entrySet()) {
            query.append(" AND ").append(entry.getKey()).append(" = '").append(entry.getValue()).append("'");
        }
        return conn.createStatement().executeQuery(query.toString());
    }

    // java-sqli-builder-medium-fix: Safe dynamic query building
    public ResultSet queryWithFiltersSafe(Map<String, String> filters) throws SQLException {
        List<String> conditions = new ArrayList<>();
        List<Object> params = new ArrayList<>();
        Set<String> allowedColumns = Set.of("name", "email", "status");

        for (Map.Entry<String, String> entry : filters.entrySet()) {
            if (allowedColumns.contains(entry.getKey())) {
                conditions.add(entry.getKey() + " = ?");
                params.add(entry.getValue());
            }
        }

        String query = "SELECT * FROM users WHERE " + String.join(" AND ", conditions);
        pstmt = conn.prepareStatement(query);
        for (int i = 0; i < params.size(); i++) {
            pstmt.setObject(i + 1, params.get(i));
        }
        return pstmt.executeQuery();
    }

    // java-sqli-orderby-hard: Order by injection
    public ResultSet sortUsersUnsafe(String sortColumn) throws SQLException {
        // UNSAFE: User-controlled ORDER BY
        String query = "SELECT * FROM users ORDER BY " + sortColumn;
        return conn.createStatement().executeQuery(query);
    }

    // java-sqli-orderby-hard-fix: Whitelist ORDER BY columns
    public ResultSet sortUsersSafe(String sortColumn) throws SQLException {
        Set<String> allowedColumns = Set.of("id", "name", "created_at");
        String safeColumn = allowedColumns.contains(sortColumn) ? sortColumn : "id";
        pstmt = conn.prepareStatement("SELECT * FROM users ORDER BY " + safeColumn);
        return pstmt.executeQuery();
    }
}

// =============================================================================
// COMMAND INJECTION PATTERNS
// =============================================================================

class CommandInjectionPatterns {

    // java-cmdi-runtime-easy: Runtime.exec with user input
    public String executeCommandUnsafe(String filename) throws Exception {
        // UNSAFE: Direct command execution
        Process p = Runtime.getRuntime().exec("cat " + filename);
        return new String(p.getInputStream().readAllBytes());
    }

    // java-cmdi-runtime-easy-fix: ProcessBuilder with args array
    public String executeCommandSafe(String filename) throws Exception {
        // Path validation
        Path path = Paths.get(filename).normalize();
        if (!path.startsWith("/safe/dir/")) {
            throw new SecurityException("Invalid path");
        }
        ProcessBuilder pb = new ProcessBuilder("cat", path.toString());
        Process p = pb.start();
        return new String(p.getInputStream().readAllBytes());
    }

    // java-cmdi-processbuilder-medium: ProcessBuilder with shell
    public void runShellUnsafe(String command) throws Exception {
        // UNSAFE: Shell execution
        new ProcessBuilder("sh", "-c", command).start();
    }

    // java-cmdi-processbuilder-medium-fix: Avoid shell, use direct command
    public void runShellSafe(String arg) throws Exception {
        // Safe: No shell, just direct execution with validated arg
        if (!arg.matches("[a-zA-Z0-9_-]+")) {
            throw new IllegalArgumentException("Invalid argument");
        }
        new ProcessBuilder("echo", arg).start();
    }

    // java-cmdi-array-hard: Command array with injection
    public void execWithArgsUnsafe(String userInput) throws Exception {
        // UNSAFE: User input in command array
        String[] cmd = {"/bin/sh", "-c", "grep " + userInput + " /var/log/app.log"};
        Runtime.getRuntime().exec(cmd);
    }

    // java-cmdi-array-hard-fix: Validate and escape input
    public void execWithArgsSafe(String userInput) throws Exception {
        // Validate input contains only alphanumeric
        if (!userInput.matches("[a-zA-Z0-9]+")) {
            throw new IllegalArgumentException("Invalid search term");
        }
        ProcessBuilder pb = new ProcessBuilder("grep", userInput, "/var/log/app.log");
        pb.start();
    }
}

// =============================================================================
// PATH TRAVERSAL PATTERNS
// =============================================================================

class PathTraversalPatterns {
    private static final String BASE_DIR = "/var/app/uploads/";

    // java-pathtraversal-direct-easy: Direct file access
    public byte[] readFileUnsafe(String filename) throws Exception {
        // UNSAFE: No path validation
        return Files.readAllBytes(Paths.get(BASE_DIR + filename));
    }

    // java-pathtraversal-direct-easy-fix: Validate within base directory
    public byte[] readFileSafe(String filename) throws Exception {
        Path basePath = Paths.get(BASE_DIR).toAbsolutePath().normalize();
        Path filePath = basePath.resolve(filename).normalize();

        if (!filePath.startsWith(basePath)) {
            throw new SecurityException("Path traversal attempt detected");
        }
        return Files.readAllBytes(filePath);
    }

    // java-pathtraversal-zip-medium: Zip slip vulnerability
    public void extractZipUnsafe(String zipFile, String destDir) throws Exception {
        // UNSAFE: Zip slip - no path validation
        try (java.util.zip.ZipInputStream zis = new java.util.zip.ZipInputStream(
                new FileInputStream(zipFile))) {
            java.util.zip.ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                File newFile = new File(destDir + File.separator + entry.getName());
                Files.copy(zis, newFile.toPath());
            }
        }
    }

    // java-pathtraversal-zip-medium-fix: Validate zip entries
    public void extractZipSafe(String zipFile, String destDir) throws Exception {
        Path destPath = Paths.get(destDir).toAbsolutePath().normalize();
        try (java.util.zip.ZipInputStream zis = new java.util.zip.ZipInputStream(
                new FileInputStream(zipFile))) {
            java.util.zip.ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                Path newPath = destPath.resolve(entry.getName()).normalize();
                if (!newPath.startsWith(destPath)) {
                    throw new SecurityException("Zip slip attempt: " + entry.getName());
                }
                Files.copy(zis, newPath);
            }
        }
    }

    // java-pathtraversal-url-hard: URL-based path injection
    public String serveFileUnsafe(HttpServletRequest request) throws Exception {
        // UNSAFE: URL parameter directly used
        String path = request.getParameter("file");
        return new String(Files.readAllBytes(Paths.get("/public/" + path)));
    }

    // java-pathtraversal-url-hard-fix: Strict validation
    public String serveFileSafe(HttpServletRequest request) throws Exception {
        String filename = request.getParameter("file");
        // Only allow alphanumeric and limited extensions
        if (!filename.matches("[a-zA-Z0-9_-]+\\.(txt|pdf|jpg)")) {
            throw new SecurityException("Invalid filename");
        }
        Path base = Paths.get("/public/").toAbsolutePath().normalize();
        Path file = base.resolve(filename).normalize();
        if (!file.startsWith(base)) {
            throw new SecurityException("Path traversal detected");
        }
        return new String(Files.readAllBytes(file));
    }
}

// =============================================================================
// XSS PATTERNS
// =============================================================================

class XSSPatterns {

    // java-xss-reflect-easy: Reflected XSS
    public void handleRequestUnsafe(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        // UNSAFE: Direct reflection
        String name = req.getParameter("name");
        resp.getWriter().write("<h1>Hello, " + name + "</h1>");
    }

    // java-xss-reflect-easy-fix: HTML encode output
    public void handleRequestSafe(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String name = req.getParameter("name");
        String safeName = org.apache.commons.text.StringEscapeUtils.escapeHtml4(name);
        resp.getWriter().write("<h1>Hello, " + safeName + "</h1>");
    }

    // java-xss-stored-medium: Stored XSS via database
    public void storeCommentUnsafe(String comment, PrintWriter out) {
        // UNSAFE: Stored without sanitization, rendered without encoding
        // Assuming comment was stored in DB and retrieved
        out.println("<div class='comment'>" + comment + "</div>");
    }

    // java-xss-stored-medium-fix: Encode on output
    public void storeCommentSafe(String comment, PrintWriter out) {
        String safeComment = org.apache.commons.text.StringEscapeUtils.escapeHtml4(comment);
        out.println("<div class='comment'>" + safeComment + "</div>");
    }

    // java-xss-json-hard: XSS in JSON response
    public void returnJsonUnsafe(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        // UNSAFE: Unescaped JSON
        String callback = req.getParameter("callback");
        String data = req.getParameter("data");
        resp.setContentType("application/javascript");
        resp.getWriter().write(callback + "({\"data\": \"" + data + "\"})");
    }

    // java-xss-json-hard-fix: Proper JSON encoding
    public void returnJsonSafe(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String data = req.getParameter("data");
        resp.setContentType("application/json");
        // Use proper JSON library
        org.json.JSONObject json = new org.json.JSONObject();
        json.put("data", data);
        resp.getWriter().write(json.toString());
    }
}

// =============================================================================
// DESERIALIZATION PATTERNS
// =============================================================================

class DeserializationPatterns {

    // java-deser-object-easy: Unsafe ObjectInputStream
    public Object deserializeUnsafe(byte[] data) throws Exception {
        // UNSAFE: Deserializing untrusted data
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }

    // java-deser-object-easy-fix: Use allowlist filter
    public Object deserializeSafe(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data)) {
            @Override
            protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                Set<String> allowedClasses = Set.of("com.myapp.SafeClass", "java.lang.String");
                if (!allowedClasses.contains(desc.getName())) {
                    throw new InvalidClassException("Unauthorized class: " + desc.getName());
                }
                return super.resolveClass(desc);
            }
        };
        return ois.readObject();
    }

    // java-deser-xml-medium: XML external entity
    public Object parseXmlUnsafe(String xml) throws Exception {
        // UNSAFE: XXE vulnerable
        javax.xml.parsers.DocumentBuilderFactory factory =
            javax.xml.parsers.DocumentBuilderFactory.newInstance();
        javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new java.io.ByteArrayInputStream(xml.getBytes()));
    }

    // java-deser-xml-medium-fix: Disable external entities
    public Object parseXmlSafe(String xml) throws Exception {
        javax.xml.parsers.DocumentBuilderFactory factory =
            javax.xml.parsers.DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new java.io.ByteArrayInputStream(xml.getBytes()));
    }

    // java-deser-yaml-hard: YAML deserialization
    public Object parseYamlUnsafe(String yaml) {
        // UNSAFE: Full object instantiation
        org.yaml.snakeyaml.Yaml parser = new org.yaml.snakeyaml.Yaml();
        return parser.load(yaml);
    }

    // java-deser-yaml-hard-fix: Safe YAML loading
    public Object parseYamlSafe(String yaml) {
        org.yaml.snakeyaml.Yaml parser = new org.yaml.snakeyaml.Yaml(
            new org.yaml.snakeyaml.constructor.SafeConstructor()
        );
        return parser.load(yaml);
    }
}

// =============================================================================
// CRYPTOGRAPHY PATTERNS
// =============================================================================

class CryptoPatterns {

    // java-crypto-md5-easy: Weak hash algorithm
    public byte[] hashPasswordUnsafe(String password) throws Exception {
        // UNSAFE: MD5 is cryptographically broken
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes());
    }

    // java-crypto-md5-easy-fix: Use strong hash with salt
    public byte[] hashPasswordSafe(String password) throws Exception {
        // Use bcrypt or similar
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt);
        return md.digest(password.getBytes());
    }

    // java-crypto-ecb-medium: ECB mode encryption
    public byte[] encryptUnsafe(byte[] data, SecretKey key) throws Exception {
        // UNSAFE: ECB mode is insecure
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    // java-crypto-ecb-medium-fix: Use GCM mode
    public byte[] encryptSafe(byte[] data, SecretKey key) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[12];
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new javax.crypto.spec.GCMParameterSpec(128, iv));
        return cipher.doFinal(data);
    }

    // java-crypto-random-hard: Predictable random
    public String generateTokenUnsafe() {
        // UNSAFE: Predictable random
        Random random = new Random();
        return Long.toHexString(random.nextLong());
    }

    // java-crypto-random-hard-fix: Secure random
    public String generateTokenSafe() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    // java-crypto-hardcoded-easy: Hardcoded key
    public SecretKey getKeyUnsafe() {
        // UNSAFE: Hardcoded key
        String keyStr = "MySecretKey12345";
        return new SecretKeySpec(keyStr.getBytes(), "AES");
    }

    // java-crypto-hardcoded-easy-fix: Load from secure storage
    public SecretKey getKeySafe() throws Exception {
        // Load from environment or secure key store
        String keyStr = System.getenv("ENCRYPTION_KEY");
        if (keyStr == null) {
            throw new SecurityException("Encryption key not configured");
        }
        return new SecretKeySpec(Base64.getDecoder().decode(keyStr), "AES");
    }
}

// =============================================================================
// NULL SAFETY PATTERNS
// =============================================================================

class NullSafetyPatterns {

    // java-null-deref-easy: Null pointer dereference
    public String getUserNameUnsafe(User user) {
        // UNSAFE: No null check
        return user.getName().toUpperCase();
    }

    // java-null-deref-easy-fix: Null check
    public String getUserNameSafe(User user) {
        if (user == null || user.getName() == null) {
            return "Anonymous";
        }
        return user.getName().toUpperCase();
    }

    // java-null-optional-medium: Optional misuse
    public String getEmailUnsafe(Optional<User> userOpt) {
        // UNSAFE: get() without isPresent()
        return userOpt.get().getEmail();
    }

    // java-null-optional-medium-fix: Proper Optional handling
    public String getEmailSafe(Optional<User> userOpt) {
        return userOpt.map(User::getEmail).orElse("no-email@example.com");
    }

    // java-null-chain-hard: Long null chain
    public String getCompanyNameUnsafe(User user) {
        // UNSAFE: Multiple potential NPEs
        return user.getDepartment().getCompany().getName();
    }

    // java-null-chain-hard-fix: Safe navigation
    public String getCompanyNameSafe(User user) {
        return Optional.ofNullable(user)
            .map(User::getDepartment)
            .map(Department::getCompany)
            .map(Company::getName)
            .orElse("Unknown");
    }

    // Helper classes for null patterns
    static class User {
        String name;
        String email;
        Department department;
        String getName() { return name; }
        String getEmail() { return email; }
        Department getDepartment() { return department; }
    }

    static class Department {
        Company company;
        Company getCompany() { return company; }
    }

    static class Company {
        String name;
        String getName() { return name; }
    }
}

// =============================================================================
// ERROR HANDLING PATTERNS
// =============================================================================

class ErrorHandlingPatterns {

    // java-err-swallowed-easy: Swallowed exception
    public void processDataUnsafe(String data) {
        try {
            // Process data
            Integer.parseInt(data);
        } catch (Exception e) {
            // UNSAFE: Exception swallowed
        }
    }

    // java-err-swallowed-easy-fix: Proper exception handling
    public void processDataSafe(String data) throws ProcessingException {
        try {
            Integer.parseInt(data);
        } catch (NumberFormatException e) {
            throw new ProcessingException("Invalid data format", e);
        }
    }

    // java-err-generic-medium: Catching generic Exception
    public void handleFileUnsafe(String path) {
        try {
            Files.readAllBytes(Paths.get(path));
        } catch (Exception e) {
            // UNSAFE: Too broad, catches unexpected exceptions
            System.err.println("Error: " + e.getMessage());
        }
    }

    // java-err-generic-medium-fix: Specific exception types
    public void handleFileSafe(String path) throws IOException {
        try {
            Files.readAllBytes(Paths.get(path));
        } catch (NoSuchFileException e) {
            throw new FileNotFoundException("File not found: " + path);
        } catch (AccessDeniedException e) {
            throw new SecurityException("Access denied: " + path);
        }
    }

    // java-err-info-leak-hard: Exception info leak
    public void handleWebRequestUnsafe(HttpServletResponse resp, Exception e) throws IOException {
        // UNSAFE: Stack trace exposed to user
        resp.sendError(500, e.toString() + "\n" + Arrays.toString(e.getStackTrace()));
    }

    // java-err-info-leak-hard-fix: Generic error message
    public void handleWebRequestSafe(HttpServletResponse resp, Exception e) throws IOException {
        // Log detailed error internally
        java.util.logging.Logger.getLogger("app").severe(e.toString());
        // Return generic message to user
        resp.sendError(500, "An internal error occurred");
    }

    static class ProcessingException extends Exception {
        ProcessingException(String msg, Throwable cause) { super(msg, cause); }
    }
}

// =============================================================================
// RESOURCE LEAK PATTERNS
// =============================================================================

class ResourceLeakPatterns {

    // java-resource-stream-easy: Unclosed stream
    public String readFileUnsafe(String path) throws IOException {
        // UNSAFE: Stream not closed
        FileInputStream fis = new FileInputStream(path);
        return new String(fis.readAllBytes());
    }

    // java-resource-stream-easy-fix: Try-with-resources
    public String readFileSafe(String path) throws IOException {
        try (FileInputStream fis = new FileInputStream(path)) {
            return new String(fis.readAllBytes());
        }
    }

    // java-resource-connection-medium: Unclosed connection
    public ResultSet queryDatabaseUnsafe(String query) throws SQLException {
        // UNSAFE: Connection not closed
        Connection conn = DriverManager.getConnection("jdbc:...");
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(query);
    }

    // java-resource-connection-medium-fix: Auto-close resources
    public List<String> queryDatabaseSafe(String query) throws SQLException {
        List<String> results = new ArrayList<>();
        try (Connection conn = DriverManager.getConnection("jdbc:...");
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            while (rs.next()) {
                results.add(rs.getString(1));
            }
        }
        return results;
    }

    // java-resource-lock-hard: Lock not released
    public void updateCounterUnsafe(ReentrantLock lock, int[] counter) {
        // UNSAFE: Lock may not be released on exception
        lock.lock();
        counter[0]++;
        // Missing unlock
    }

    // java-resource-lock-hard-fix: Proper lock handling
    public void updateCounterSafe(ReentrantLock lock, int[] counter) {
        lock.lock();
        try {
            counter[0]++;
        } finally {
            lock.unlock();
        }
    }
}

// =============================================================================
// CONCURRENCY PATTERNS
// =============================================================================

class ConcurrencyPatterns {

    // java-race-check-then-act-easy: Race condition
    private Map<String, Object> cache = new HashMap<>();

    public Object getCachedUnsafe(String key) {
        // UNSAFE: Race between check and put
        if (!cache.containsKey(key)) {
            cache.put(key, computeValue(key));
        }
        return cache.get(key);
    }

    // java-race-check-then-act-easy-fix: Use concurrent map
    private ConcurrentHashMap<String, Object> safeCache = new ConcurrentHashMap<>();

    public Object getCachedSafe(String key) {
        return safeCache.computeIfAbsent(key, this::computeValue);
    }

    // java-race-double-check-medium: Broken double-checked locking
    private volatile Object instance;

    public Object getInstanceUnsafe() {
        // UNSAFE: Missing volatile or sync
        if (instance == null) {
            synchronized (this) {
                if (instance == null) {
                    instance = new Object();
                }
            }
        }
        return instance;
    }

    // java-race-compound-hard: Non-atomic compound operations
    private int counter = 0;

    public void incrementUnsafe() {
        // UNSAFE: Not atomic
        counter++;
    }

    // java-race-compound-hard-fix: Use AtomicInteger
    private AtomicInteger atomicCounter = new AtomicInteger(0);

    public void incrementSafe() {
        atomicCounter.incrementAndGet();
    }

    private Object computeValue(String key) {
        return new Object();
    }
}

// =============================================================================
// SSRF PATTERNS
// =============================================================================

class SSRFPatterns {

    // java-ssrf-url-easy: Unvalidated URL fetch
    public String fetchUrlUnsafe(String url) throws Exception {
        // UNSAFE: No URL validation
        URL urlObj = new URL(url);
        return new String(urlObj.openStream().readAllBytes());
    }

    // java-ssrf-url-easy-fix: Validate URL against allowlist
    public String fetchUrlSafe(String url) throws Exception {
        URL urlObj = new URL(url);
        Set<String> allowedHosts = Set.of("api.example.com", "cdn.example.com");

        if (!allowedHosts.contains(urlObj.getHost())) {
            throw new SecurityException("Host not allowed: " + urlObj.getHost());
        }

        // Also block internal IPs
        InetAddress addr = InetAddress.getByName(urlObj.getHost());
        if (addr.isLoopbackAddress() || addr.isSiteLocalAddress()) {
            throw new SecurityException("Internal addresses not allowed");
        }

        return new String(urlObj.openStream().readAllBytes());
    }

    // java-ssrf-redirect-medium: Following redirects to internal
    public String fetchWithRedirectUnsafe(String url) throws Exception {
        // UNSAFE: Follows redirects without validation
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setInstanceFollowRedirects(true);
        return new String(conn.getInputStream().readAllBytes());
    }

    // java-ssrf-redirect-medium-fix: Validate redirect targets
    public String fetchWithRedirectSafe(String url) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setInstanceFollowRedirects(false);

        int status = conn.getResponseCode();
        if (status == 301 || status == 302) {
            String redirectUrl = conn.getHeaderField("Location");
            // Validate redirect target
            URL redirectUrlObj = new URL(redirectUrl);
            if (redirectUrlObj.getHost().equals("localhost") ||
                InetAddress.getByName(redirectUrlObj.getHost()).isSiteLocalAddress()) {
                throw new SecurityException("Redirect to internal address blocked");
            }
        }

        return new String(conn.getInputStream().readAllBytes());
    }
}

// =============================================================================
// LOGGING PATTERNS
// =============================================================================

class LoggingPatterns {
    private java.util.logging.Logger logger = java.util.logging.Logger.getLogger("app");

    // java-log-injection-easy: Log injection
    public void logLoginUnsafe(String username) {
        // UNSAFE: User input directly in log
        logger.info("User logged in: " + username);
    }

    // java-log-injection-easy-fix: Sanitize log input
    public void logLoginSafe(String username) {
        String safeUsername = username.replaceAll("[\n\r\t]", "_");
        logger.info("User logged in: " + safeUsername);
    }

    // java-log-sensitive-medium: Logging sensitive data
    public void logPaymentUnsafe(String cardNumber, double amount) {
        // UNSAFE: Sensitive data logged
        logger.info("Payment of $" + amount + " with card " + cardNumber);
    }

    // java-log-sensitive-medium-fix: Mask sensitive data
    public void logPaymentSafe(String cardNumber, double amount) {
        String maskedCard = "****-****-****-" + cardNumber.substring(cardNumber.length() - 4);
        logger.info("Payment of $" + amount + " with card " + maskedCard);
    }
}

// =============================================================================
// AUTHENTICATION PATTERNS
// =============================================================================

class AuthPatterns {

    // java-auth-timing-easy: Timing attack in password comparison
    public boolean checkPasswordUnsafe(String provided, String stored) {
        // UNSAFE: Early exit reveals password length
        return provided.equals(stored);
    }

    // java-auth-timing-easy-fix: Constant-time comparison
    public boolean checkPasswordSafe(String provided, String stored) {
        if (provided == null || stored == null) {
            return false;
        }
        return MessageDigest.isEqual(provided.getBytes(), stored.getBytes());
    }

    // java-auth-bypass-medium: Authentication bypass
    public boolean isAdminUnsafe(HttpServletRequest request) {
        // UNSAFE: Client-controlled admin flag
        return "true".equals(request.getParameter("isAdmin"));
    }

    // java-auth-bypass-medium-fix: Server-side session check
    public boolean isAdminSafe(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return false;
        }
        Object role = session.getAttribute("role");
        return "admin".equals(role);
    }
}

// =============================================================================
// PERFORMANCE PATTERNS
// =============================================================================

class PerformancePatterns {

    // java-perf-nplus1-easy: N+1 query problem
    public List<String> getOrderDetailsUnsafe(List<Integer> orderIds) throws SQLException {
        List<String> details = new ArrayList<>();
        Connection conn = null; // assume initialized
        for (Integer id : orderIds) {
            // UNSAFE: Query per item
            PreparedStatement ps = conn.prepareStatement("SELECT * FROM order_items WHERE order_id = ?");
            ps.setInt(1, id);
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                details.add(rs.getString("name"));
            }
        }
        return details;
    }

    // java-perf-nplus1-easy-fix: Batch query
    public List<String> getOrderDetailsSafe(List<Integer> orderIds) throws SQLException {
        List<String> details = new ArrayList<>();
        Connection conn = null; // assume initialized

        String placeholders = String.join(",", Collections.nCopies(orderIds.size(), "?"));
        PreparedStatement ps = conn.prepareStatement(
            "SELECT * FROM order_items WHERE order_id IN (" + placeholders + ")");
        for (int i = 0; i < orderIds.size(); i++) {
            ps.setInt(i + 1, orderIds.get(i));
        }
        ResultSet rs = ps.executeQuery();
        while (rs.next()) {
            details.add(rs.getString("name"));
        }
        return details;
    }

    // java-perf-string-concat-medium: String concatenation in loop
    public String buildStringUnsafe(List<String> items) {
        // UNSAFE: Creates many String objects
        String result = "";
        for (String item : items) {
            result += item + ",";
        }
        return result;
    }

    // java-perf-string-concat-medium-fix: Use StringBuilder
    public String buildStringSafe(List<String> items) {
        StringBuilder sb = new StringBuilder();
        for (String item : items) {
            if (sb.length() > 0) {
                sb.append(",");
            }
            sb.append(item);
        }
        return sb.toString();
    }

    // java-perf-regex-hard: Regex compilation in loop
    public List<String> filterItemsUnsafe(List<String> items, String pattern) {
        List<String> result = new ArrayList<>();
        for (String item : items) {
            // UNSAFE: Compiles regex on every iteration
            if (item.matches(pattern)) {
                result.add(item);
            }
        }
        return result;
    }

    // java-perf-regex-hard-fix: Pre-compile regex
    public List<String> filterItemsSafe(List<String> items, String pattern) {
        java.util.regex.Pattern compiled = java.util.regex.Pattern.compile(pattern);
        List<String> result = new ArrayList<>();
        for (String item : items) {
            if (compiled.matcher(item).matches()) {
                result.add(item);
            }
        }
        return result;
    }
}

// =============================================================================
// ADDITIONAL PATTERNS FOR TEMPLATE MATCHING
// =============================================================================

// java-cmdi-runtime-easy
void cmdiRuntimeEasy() {
    pb.redirectErrorStream(true);
    Process p = pb.start();
}

// java-pathtraversal-direct-easy
byte[] pathtraversalDirectEasy(Path basePath, String filename) throws Exception {
    Path requestedPath = basePath.resolve(filename).normalize();
    if (!requestedPath.startsWith(basePath)) {
        throw new SecurityException("Path traversal attempt");
    }
    return Files.readAllBytes(requestedPath);
}

// java-xss-reflect-easy
void xssReflectEasy(HttpServletResponse resp, String safeMessage) throws Exception {
    resp.getWriter().write("<div>" + safeMessage + "</div>");
}

// java-crypto-md5-easy
byte[] cryptoMd5Easy(String password, SecureRandom random) throws Exception {
    byte[] salt = new byte[16];
    random.nextBytes(salt);
    KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    return factory.generateSecret(spec).getEncoded();
}

// java-crypto-random-easy
String cryptoRandomEasy(SecureRandom random) {
    byte[] bytes = new byte[32];
    random.nextBytes(bytes);
    return Base64.getEncoder().encodeToString(bytes);
}

// java-null-deref-easy
String nullDerefEasy(User user) {
    if (user != null) {
        return user.getName();
    }
    return "";
}

// java-err-swallowed-easy
void errSwallowedEasy(Exception e) {
    logger.error("Database error", e);
    throw new ServiceException("Failed to process request", e);
}

// java-resource-leak-easy
ResultSet resourceLeakEasy(Connection conn, String query) throws Exception {
    // Use connection
    return conn.createStatement().executeQuery(query);
}

// java-ssrf-url-easy
InputStream ssrfUrlEasy(String targetUrl) throws Exception {
    if (!isAllowedUrl(targetUrl)) {
        throw new SecurityException("URL not allowed");
    }
    return new URL(targetUrl).openStream();
}

// java-sqli-builder-medium
void sqliBuilderMedium(PreparedStatement ps, String status) throws Exception {
    ps.setString(1, status);
}

// java-sqli-orderby-hard
void sqliOrderbyHard(String[] allowed, String sortBy, StringBuilder query) {
    if (Arrays.asList(allowed).contains(sortBy)) {
        query.append(" ORDER BY ").append(sortBy);
    }
}

// java-pathtraversal-zip-medium
void pathtraversalZipMedium(File destDir, String name) throws Exception {
    File destFile = new File(destDir, name);
    String destPath = destFile.getCanonicalPath();
    if (!destPath.startsWith(destDir.getCanonicalPath() + File.separator)) {
        throw new IOException("Entry outside target dir: " + name);
    }
}

// java-pathtraversal-url-hard
void pathtraversalUrlHard(String decoded, String baseDir) {
    String safe = new File(decoded).getName();
    Path path = Paths.get(baseDir, safe);
}

// java-xss-stored-medium
void xssStoredMedium(PrintWriter out, String safe) {
    out.println("<div>" + safe + "</div>");
}

// java-xss-json-hard
void xssJsonHard(PrintWriter out, String safe) {
    out.println("<script>var data = '" + safe + "';</script>");
}

// java-deser-xml-medium
void deserXmlMedium(DocumentBuilderFactory dbf) throws Exception {
    dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
}

// java-deser-yaml-hard
Object deserYamlHard(Yaml yaml, String input) {
    Object data = yaml.load(input);
    return data;
}

// java-crypto-hardcoded-easy
byte[] cryptoHardcodedEasy() {
    byte[] key = Base64.getDecoder().decode(System.getenv("ENCRYPTION_KEY"));
    return key;
}

// java-null-optional-medium
Object nullOptionalMedium(Optional optional, Object defaultValue) {
    return optional.orElse(defaultValue);
}

// java-null-chain-hard
String nullChainHard(Optional<User> userOpt) {
    return userOpt
        .map(User::getProfile)
        .map(Profile::getAddress)
        .map(Address::getCity)
        .orElse("Unknown");
}

// java-err-generic-medium
void errGenericMedium(Exception e) throws Exception {
    if (e instanceof IOException) {
        logger.error("IO error", e);
        throw new ServiceException("Failed to read file", e);
    }
    if (e instanceof ParseException) {
        logger.error("Parse error", e);
        throw new ServiceException("Invalid format", e);
    }
}

// java-err-info-leak-hard
ResponseEntity errInfoLeakHard(Exception e) {
    logger.error("Error processing request", e);
    return ResponseEntity.status(500).body("Internal server error");
}

// java-resource-stream-easy
byte[] resourceStreamEasy(InputStream is) throws Exception {
    try (is) {
        return IOUtils.toByteArray(is);
    }
}

// java-resource-connection-medium
void resourceConnectionMedium(Connection conn) {
    try (conn) {
        // use connection
    }
}

// java-resource-lock-hard
void resourceLockHard(Lock lock) {
    lock.lock();
    try {
        // critical section
    } finally {
        lock.unlock();
    }
}

// java-race-check-then-act-easy
Object raceCheckThenActEasy(Map map, String key) {
    synchronized(map) {
        if (!map.containsKey(key)) {
            map.put(key, computeValue());
        }
        return map.get(key);
    }
}

// java-race-compound-hard
void raceCompoundHard(AtomicInteger counter) {
    counter.incrementAndGet();
}

// java-log-injection-easy
void logInjectionEasy(Logger logger, String username) {
    logger.info("User login: {}", username.replaceAll("[\n\r]", "_"));
}

// java-log-sensitive-medium
void logSensitiveMedium(Logger logger, String userId) {
    logger.info("User authenticated: {}", userId);
}

// java-auth-timing-easy
boolean authTimingEasy(byte[] expected, byte[] provided) {
    return MessageDigest.isEqual(expected, provided);
}

// java-auth-bypass-medium
Object authBypassMedium(HttpServletRequest request, String id, UserService userService) {
    if (isAuthenticated(request)) {
        return userService.getUser(id);
    }
    throw new UnauthorizedException();
}

// java-perf-nplus1-easy
String perfNplus1Easy() {
    return "SELECT u FROM User u JOIN FETCH u.orders WHERE u.id IN :ids";
}

// java-perf-string-concat-medium
String perfStringConcatMedium(StringBuilder sb, String[] items) {
    for (String s : items) {
        sb.append(s);
    }
    return sb.toString();
}

// java-perf-regex-hard
void perfRegexHard(Pattern PATTERN, String[] items) {
    for (String s : items) {
        if (PATTERN.matcher(s).matches()) {
            // ...
        }
    }
}

// java-cve-log4shell-lookup
void cveLog4shellLookup(Logger logger, String userAgent) {
    logger.info("User-Agent: {}", sanitize(userAgent));
}

// java-cve-struts-header
void cveStrutsHeader(HttpServletResponse response, Map<String, String> ALLOWED_TYPES, String type) {
    response.setHeader("Content-Type", ALLOWED_TYPES.get(type));
}

// java-cve-deser-config
void cveDeserConfig(ObjectMapper mapper) {
    mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NONE);
}

// java-cve-idor-direct
Object cveIdorDirect(String orderId, OrderService orderService, HttpServletRequest request) {
    if (isAuthorized(request, orderId)) {
        return orderService.getOrder(orderId);
    }
    throw new ForbiddenException();
}

// java-cve-priv-esc
void cvePrivEsc(User user, String newRole, boolean isAdmin) {
    if (isAdmin) {
        user.setRole(newRole);
    }
}

// java-cve-spring-pathtraversal
Resource cveSpringPathtraversal(String filename) {
    return new ClassPathResource("static/" + FilenameUtils.getName(filename));
}

// java-cve-spring-spel
Object cveSpringSpel(Object value) {
    return value;
}

// java-cve-session-fixation
void cveSessionFixation(HttpServletRequest request, User user) {
    request.getSession().invalidate();
    HttpSession newSession = request.getSession(true);
    newSession.setAttribute("user", user);
}

// java-cve-classloader
void cveClassloader(Set<String> ALLOWED_CLASSES, String className) throws Exception {
    if (ALLOWED_CLASSES.contains(className)) {
        Class.forName(className);
    }
}

// java-cve-method-invoke
void cveMethodInvoke(Set<String> ALLOWED_METHODS, String methodName, Method method, Object target, Object[] args) throws Exception {
    if (ALLOWED_METHODS.contains(methodName)) {
        method.invoke(target, args);
    }
}

// java-cve-socket-deser
Object cveSocketDeser(BufferedReader reader, ObjectMapper objectMapper) throws Exception {
    String json = reader.readLine();
    return objectMapper.readValue(json, SafeClass.class);
}

// java-cve-dns-rebinding
void cveDnsRebinding(InetAddress addr) {
    if (addr.isSiteLocalAddress() || addr.isLoopbackAddress()) {
        throw new SecurityException("Internal address not allowed");
    }
}

// java-cve-content-type
void cveContentType(HttpServletResponse response, String json) throws Exception {
    response.setContentType("application/json");
    response.getWriter().write(json);
}

// java-cve-header-injection
void cveHeaderInjection(HttpServletResponse response, String safeValue) {
    response.setHeader("X-Custom", safeValue);
}

// java-cve-spring4shell
void cveSpring4shell(WebDataBinder binder) {
    String[] blacklist = {"class.*"};
    binder.setDisallowedFields(blacklist);
}

// java-cve-text4shell
String cveText4shell(String template, Object[] args) {
    return MessageFormat.format(template, args);
}

// java-fp-sql-allowlist
void fpSqlAllowlist(Statement stmt, String table) throws Exception {
    stmt.executeQuery("SELECT * FROM " + table);
}

// java-fp-cmd-constant
void fpCmdConstant() throws Exception {
    Runtime.getRuntime().exec(new String[]{"ls", "-la", "/tmp"});
}

// java-fp-reflection-constant
void fpReflectionConstant() throws Exception {
    Class.forName("com.myapp.MyClass");
}

// Helper interfaces
interface User { String getName(); Profile getProfile(); void setRole(String role); }
interface Profile { Address getAddress(); }
interface Address { String getCity(); }
interface UserService { Object getUser(String id); }
interface OrderService { Object getOrder(String id); }
class ServiceException extends RuntimeException { ServiceException(String msg, Exception e) { super(msg, e); } }
class UnauthorizedException extends RuntimeException {}
class ForbiddenException extends RuntimeException {}
class SafeClass {}
