package benchmarks;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.util.HtmlUtils;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

class UserEndpoint {
    private SecurityContext securityContext;
    private UserService userService;

    User fetch(String id) {
        if (securityContext.isAuthenticated()) {
            return userService.getUser(id);
        }
        throw new UnauthorizedException();
    }
}

class GrepRunner {
    void search(String pattern, String file) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("grep", pattern, file);
        pb.start();
    }
}

class SafeCommandRunner {
    private static final String safeCommand = "/usr/bin/uptime";
    private static final String safeArg = "--pretty";

    void run() throws IOException {
        ProcessBuilder pb = new ProcessBuilder(safeCommand, safeArg);
        pb.start();
    }
}

class TokenMinter {
    byte[] nonce() {
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[32];
        random.nextBytes(nonce);
        return nonce;
    }
}

class PasswordHasher {
    byte[] hash(String password) throws NoSuchAlgorithmException {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt);
        return md.digest(password.getBytes());
    }
}

class ClassLoaderGuard {
    private static final Set<String> ALLOWED_CLASSES =
        Set.of("com.myapp.ReportJob", "com.myapp.CleanupJob");

    void loadJob(String className) throws ClassNotFoundException {
        // Use allowlist of permitted classes
        if (ALLOWED_CLASSES.contains(className)) {
            Class.forName(className);
        }
    }
}

class OutboundHostGuard {
    void assertExternal(String host) throws UnknownHostException {
        InetAddress addr = InetAddress.getByName(host);
        if (addr.isSiteLocalAddress() || addr.isLoopbackAddress()) {
            throw new SecurityException("Internal address not allowed");
        }
    }
}

class RedirectEndpoint {
    void redirect(HttpServletResponse response, String url) throws IOException {
        String safeUrl = url.replaceAll("[\\r\\n]", "");
        new URL(safeUrl);
        response.setHeader("Location", safeUrl);
        response.setStatus(302);
    }
}

class DocumentEndpoint {
    private boolean isAuthorized(String userId, String docId) {
        return ownerOf(docId).equals(userId);
    }

    private String ownerOf(String docId) {
        return "";
    }

    private byte[] readDocument(String docId) throws IOException {
        return Files.readAllBytes(Paths.get("docs", docId));
    }

    byte[] fetch(HttpServletRequest request) throws IOException {
        String docId = request.getParameter("id");
        String userId = (String) request.getSession().getAttribute("userId");
        if (!isAuthorized(userId, docId)) {
            throw new SecurityException("Access denied");
        }
        return readDocument(docId);
    }
}

class MethodDispatcher {
    private static final Set<String> ALLOWED_METHODS = Set.of("start", "stop", "status");

    void dispatch(Method method, Object target, Object[] args, String methodName) throws Exception {
        // Use allowlist of permitted methods
        if (ALLOWED_METHODS.contains(methodName)) {
            method.invoke(target, args);
        }
    }
}

class RoleAdminEndpoint {
    void assignRole(Principal currentUser, User user, String newRole) {
        if (currentUser.hasRole("ADMIN")) {
            user.setRole(newRole);
        }
    }
}

class SocketLineReader {
    String readCommand(Socket socket) throws IOException {
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(socket.getInputStream())
        );
        return reader.readLine();
    }
}

class StaticResourceReader {
    byte[] read(String resourcePath) throws IOException {
        Path base = Paths.get("static/").toAbsolutePath().normalize();
        Path resource = base.resolve(resourcePath).normalize();
        if (!resource.startsWith(base)) {
            throw new SecurityException("Path traversal detected");
        }
        return Files.readAllBytes(resource);
    }
}

class ExpressionFreeEvaluator {
    String evaluate(String value) {
        // Use parameterized values, not expressions
        return value;
    }
}

@ControllerAdvice
class BinderConfig {
    @InitBinder
    public void initBinder(WebDataBinder binder) {
        String[] blacklist = {"class.*"};
        binder.setDisallowedFields(blacklist);
    }
}

class ContentTypeGate {
    void handle(HttpServletRequest request, HttpServletResponse response) throws IOException {
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

class MessageRenderer {
    String render(String template, Object[] args) {
        // Use parameterized messages
        return MessageFormat.format(template, args);
    }
}

class XmlParserFactory {
    DocumentBuilder create() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return dbf.newDocumentBuilder();
    }
}

class YamlConfigLoader {
    Object load(String input) {
        Yaml yaml = new Yaml(new SafeConstructor());
        Object data = yaml.load(input);
        return data;
    }
}

class ConstantCommandRunner {
    void listTemp() throws IOException {
        Runtime.getRuntime().exec("ls -la /tmp");
    }
}

class ConstantClassLoader {
    void loadKnown() throws ClassNotFoundException {
        Class.forName("com.myapp.MyClass");
    }
}

class AllowlistedTableQuery {
    private static final Map<String, String> ALLOWED_TABLES =
        Map.of("users", "app_users", "orders", "app_orders");

    ResultSet query(Statement stmt, String tableKey) throws SQLException {
        if (!ALLOWED_TABLES.containsKey(tableKey)) {
            throw new IllegalArgumentException("Unknown table key");
        }
        String table = ALLOWED_TABLES.get(tableKey);
        stmt.executeQuery("SELECT * FROM " + table);
        return stmt.getResultSet();
    }
}

class BaseDirFileReader {
    private static final String BASE_DIR = "/srv/app/data";

    byte[] read(String filename) throws IOException {
        Path basePath = Paths.get(BASE_DIR).toAbsolutePath().normalize();
        Path filePath = basePath.resolve(filename).normalize();
        if (!filePath.startsWith(basePath)) {
            throw new SecurityException("Path traversal attempt detected");
        }
        return Files.readAllBytes(filePath);
    }
}

class EncodedNameResolver {
    Path resolve(String baseDir, String filename) throws IOException {
        String decoded = URLDecoder.decode(filename, "UTF-8");
        String safe = new File(decoded).getName();
        Path path = Paths.get(baseDir, safe);
        return path;
    }
}

class ArchiveExtractor {
    void checkEntry(ZipEntry entry, File destDir) throws IOException {
        String name = entry.getName();
        File destFile = new File(destDir, name);
        String destPath = destFile.getCanonicalPath();
        if (!destPath.startsWith(destDir.getCanonicalPath() + File.separator)) {
            throw new IOException("Entry outside target dir: " + name);
        }
    }
}

class StatusQuery {
    ResultSet byStatus(Connection conn, String status) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE status = ?");
        ps.setString(1, status);
        return ps.executeQuery();
    }
}

class SortedUserQuery {
    String build(String sortBy) {
        String query = "SELECT * FROM users";
        String[] allowed = {"name", "email", "created_at"};
        if (Arrays.asList(allowed).contains(sortBy)) {
            query += " ORDER BY " + sortBy;
        }
        return query;
    }
}

class NoRedirectFetcher {
    HttpURLConnection open(URL url) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(false);
        return conn;
    }
}

class AllowlistedFetcher {
    String fetch(String url) throws IOException {
        URL urlObj = new URL(url);
        Set<String> allowedHosts = Set.of("api.example.com", "cdn.example.com");
        if (!allowedHosts.contains(urlObj.getHost())) {
            throw new SecurityException("Host not allowed: " + urlObj.getHost());
        }
        return new String(urlObj.openStream().readAllBytes());
    }
}

class ScriptDataWriter {
    void write(PrintWriter out, String data) {
        String safe = StringEscapeUtils.escapeEcmaScript(data);
        out.println("<script>var data = '" + safe + "';</script>");
    }
}

class GreetingServlet {
    void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        String safeName = StringEscapeUtils.escapeHtml4(name);
        resp.getWriter().write("<h1>Hello, " + safeName + "</h1>");
    }
}

class CommentRenderer {
    void render(PrintWriter out, String content) {
        String safe = HtmlUtils.htmlEscape(content);
        out.println("<div>" + safe + "</div>");
    }
}
