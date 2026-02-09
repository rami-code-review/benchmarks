// Benchmark patterns for C# security and quality detection.
// Each method represents a template pattern for testing code review capabilities.
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;
using System.Xml;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace Benchmarks
{
    // =============================================================================
    // SQL INJECTION PATTERNS
    // =============================================================================

    public class SqlInjectionPatterns
    {
        private SqlConnection _connection;

        // cs-sqli-concat-easy: String concatenation in SQL
        public DataTable GetUserByIdUnsafe(string userId)
        {
            // UNSAFE: String concatenation
            var query = "SELECT * FROM Users WHERE Id = '" + userId + "'";
            var cmd = new SqlCommand(query, _connection);
            var adapter = new SqlDataAdapter(cmd);
            var table = new DataTable();
            adapter.Fill(table);
            return table;
        }

        // cs-sqli-concat-easy-fix: Parameterized query
        public DataTable GetUserByIdSafe(string userId)
        {
            var query = "SELECT * FROM Users WHERE Id = @UserId";
            var cmd = new SqlCommand(query, _connection);
            cmd.Parameters.AddWithValue("@UserId", userId);
            var adapter = new SqlDataAdapter(cmd);
            var table = new DataTable();
            adapter.Fill(table);
            return table;
        }

        // cs-sqli-format-easy: String.Format in SQL
        public DataTable SearchUsersUnsafe(string name)
        {
            // UNSAFE: String.Format
            var query = string.Format("SELECT * FROM Users WHERE Name LIKE '%{0}%'", name);
            var cmd = new SqlCommand(query, _connection);
            var adapter = new SqlDataAdapter(cmd);
            var table = new DataTable();
            adapter.Fill(table);
            return table;
        }

        // cs-sqli-format-easy-fix: Parameterized LIKE
        public DataTable SearchUsersSafe(string name)
        {
            var query = "SELECT * FROM Users WHERE Name LIKE @Name";
            var cmd = new SqlCommand(query, _connection);
            cmd.Parameters.AddWithValue("@Name", "%" + name + "%");
            var adapter = new SqlDataAdapter(cmd);
            var table = new DataTable();
            adapter.Fill(table);
            return table;
        }

        // cs-sqli-interpolation-medium: String interpolation in SQL
        public DataTable GetOrdersUnsafe(string status, int limit)
        {
            // UNSAFE: String interpolation
            var query = $"SELECT TOP {limit} * FROM Orders WHERE Status = '{status}'";
            var cmd = new SqlCommand(query, _connection);
            var adapter = new SqlDataAdapter(cmd);
            var table = new DataTable();
            adapter.Fill(table);
            return table;
        }

        // cs-sqli-interpolation-medium-fix: Parameters for all values
        public DataTable GetOrdersSafe(string status, int limit)
        {
            var query = "SELECT TOP (@Limit) * FROM Orders WHERE Status = @Status";
            var cmd = new SqlCommand(query, _connection);
            cmd.Parameters.AddWithValue("@Limit", limit);
            cmd.Parameters.AddWithValue("@Status", status);
            var adapter = new SqlDataAdapter(cmd);
            var table = new DataTable();
            adapter.Fill(table);
            return table;
        }

        // cs-sqli-stored-proc-hard: Stored procedure with dynamic SQL
        public void ExecuteStoredProcUnsafe(string tableName)
        {
            // UNSAFE: Dynamic table name
            var cmd = new SqlCommand("EXEC sp_GetData @Table", _connection);
            cmd.Parameters.AddWithValue("@Table", tableName);
            cmd.ExecuteNonQuery();
        }

        // cs-sqli-stored-proc-hard-fix: Whitelist table names
        public void ExecuteStoredProcSafe(string tableName)
        {
            var allowedTables = new HashSet<string> { "Users", "Orders", "Products" };
            if (!allowedTables.Contains(tableName))
            {
                throw new ArgumentException("Invalid table name");
            }
            var cmd = new SqlCommand("EXEC sp_GetData @Table", _connection);
            cmd.Parameters.AddWithValue("@Table", tableName);
            cmd.ExecuteNonQuery();
        }
    }

    // =============================================================================
    // COMMAND INJECTION PATTERNS
    // =============================================================================

    public class CommandInjectionPatterns
    {
        // cs-cmdi-process-easy: Process.Start with user input
        public string ExecuteCommandUnsafe(string filename)
        {
            // UNSAFE: User input in command
            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c type " + filename,
                RedirectStandardOutput = true,
                UseShellExecute = false
            };
            using var process = Process.Start(psi);
            return process.StandardOutput.ReadToEnd();
        }

        // cs-cmdi-process-easy-fix: Validate and separate arguments
        public string ExecuteCommandSafe(string filename)
        {
            // Validate filename
            if (!Regex.IsMatch(filename, @"^[\w\-. ]+$"))
            {
                throw new ArgumentException("Invalid filename");
            }

            var basePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "files");
            var fullPath = Path.GetFullPath(Path.Combine(basePath, filename));

            if (!fullPath.StartsWith(basePath))
            {
                throw new SecurityException("Path traversal detected");
            }

            return File.ReadAllText(fullPath);
        }

        // cs-cmdi-shell-medium: Shell execution
        public void RunShellCommandUnsafe(string command)
        {
            // UNSAFE: Shell execution with user input
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-Command \"{command}\"",
                UseShellExecute = false
            };
            Process.Start(psi);
        }

        // cs-cmdi-shell-medium-fix: Avoid shell, use specific command
        public void RunShellCommandSafe(string arg)
        {
            // Validate argument
            if (!Regex.IsMatch(arg, @"^[\w\-]+$"))
            {
                throw new ArgumentException("Invalid argument");
            }

            var psi = new ProcessStartInfo
            {
                FileName = "echo",
                Arguments = arg,
                UseShellExecute = false
            };
            Process.Start(psi);
        }
    }

    // =============================================================================
    // PATH TRAVERSAL PATTERNS
    // =============================================================================

    public class PathTraversalPatterns
    {
        private static readonly string BaseDir = @"C:\App\Uploads";

        // cs-pathtraversal-combine-easy: Path.Combine without validation
        public byte[] ReadFileUnsafe(string filename)
        {
            // UNSAFE: Path.Combine doesn't prevent traversal
            var path = Path.Combine(BaseDir, filename);
            return File.ReadAllBytes(path);
        }

        // cs-pathtraversal-combine-easy-fix: Validate resolved path
        public byte[] ReadFileSafe(string filename)
        {
            var basePath = Path.GetFullPath(BaseDir);
            var fullPath = Path.GetFullPath(Path.Combine(basePath, filename));

            if (!fullPath.StartsWith(basePath + Path.DirectorySeparatorChar))
            {
                throw new SecurityException("Path traversal detected");
            }

            return File.ReadAllBytes(fullPath);
        }

        // cs-pathtraversal-zip-medium: Zip extraction vulnerability
        public void ExtractZipUnsafe(string zipPath, string destDir)
        {
            // UNSAFE: Zip slip vulnerability
            using var archive = System.IO.Compression.ZipFile.OpenRead(zipPath);
            foreach (var entry in archive.Entries)
            {
                var destPath = Path.Combine(destDir, entry.FullName);
                entry.ExtractToFile(destPath, true);
            }
        }

        // cs-pathtraversal-zip-medium-fix: Validate entry paths
        public void ExtractZipSafe(string zipPath, string destDir)
        {
            var basePath = Path.GetFullPath(destDir);

            using var archive = System.IO.Compression.ZipFile.OpenRead(zipPath);
            foreach (var entry in archive.Entries)
            {
                var destPath = Path.GetFullPath(Path.Combine(destDir, entry.FullName));

                if (!destPath.StartsWith(basePath + Path.DirectorySeparatorChar))
                {
                    throw new SecurityException("Zip slip attempt: " + entry.FullName);
                }

                if (entry.FullName.EndsWith("/"))
                {
                    Directory.CreateDirectory(destPath);
                }
                else
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(destPath));
                    entry.ExtractToFile(destPath, true);
                }
            }
        }
    }

    // =============================================================================
    // XSS PATTERNS
    // =============================================================================

    public class XssPatterns : Controller
    {
        // cs-xss-razor-easy: Unencoded output in MVC
        public IActionResult DisplayMessageUnsafe(string message)
        {
            // UNSAFE: Raw output
            ViewBag.Message = new HtmlString(message);
            return View();
        }

        // cs-xss-razor-easy-fix: Encoded output
        public IActionResult DisplayMessageSafe(string message)
        {
            // Safe: Razor will encode by default
            ViewBag.Message = message;
            return View();
        }

        // cs-xss-content-medium: ContentResult without encoding
        public IActionResult ReturnContentUnsafe(string content)
        {
            // UNSAFE: Direct content output
            return Content("<div>" + content + "</div>", "text/html");
        }

        // cs-xss-content-medium-fix: Encode content
        public IActionResult ReturnContentSafe(string content)
        {
            var encoded = System.Web.HttpUtility.HtmlEncode(content);
            return Content("<div>" + encoded + "</div>", "text/html");
        }

        // cs-xss-json-hard: JSON in script tag
        public IActionResult ReturnJsonInScriptUnsafe(object data)
        {
            // UNSAFE: JSON may contain script-breaking characters
            var json = JsonConvert.SerializeObject(data);
            ViewBag.Data = json;
            return View(); // View contains: <script>var data = @Html.Raw(ViewBag.Data);</script>
        }

        // cs-xss-json-hard-fix: Use proper JSON encoding
        public IActionResult ReturnJsonInScriptSafe(object data)
        {
            // Safe: Use proper JSON encoding that escapes </script>
            var json = System.Text.Json.JsonSerializer.Serialize(data);
            ViewBag.Data = json.Replace("</", "<\\/");
            return View();
        }
    }

    // =============================================================================
    // DESERIALIZATION PATTERNS
    // =============================================================================

    public class DeserializationPatterns
    {
        // cs-deser-binary-easy: BinaryFormatter deserialization
        public object DeserializeBinaryUnsafe(byte[] data)
        {
            // UNSAFE: BinaryFormatter is insecure
            using var ms = new MemoryStream(data);
            var formatter = new BinaryFormatter();
            return formatter.Deserialize(ms);
        }

        // cs-deser-binary-easy-fix: Use safe serializer
        public T DeserializeSafe<T>(string json)
        {
            return System.Text.Json.JsonSerializer.Deserialize<T>(json);
        }

        // cs-deser-json-typenamehandling-medium: Json.NET TypeNameHandling
        public object DeserializeJsonUnsafe(string json)
        {
            // UNSAFE: TypeNameHandling.All allows arbitrary type instantiation
            var settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All
            };
            return JsonConvert.DeserializeObject(json, settings);
        }

        // cs-deser-json-typenamehandling-medium-fix: Avoid TypeNameHandling
        public T DeserializeJsonSafe<T>(string json)
        {
            // Safe: No TypeNameHandling
            return JsonConvert.DeserializeObject<T>(json);
        }

        // cs-deser-xml-hard: XML deserialization with DTD
        public object DeserializeXmlUnsafe(string xml)
        {
            // UNSAFE: XXE possible
            var settings = new XmlReaderSettings();
            using var reader = XmlReader.Create(new StringReader(xml), settings);
            var doc = new XmlDocument();
            doc.Load(reader);
            return doc;
        }

        // cs-deser-xml-hard-fix: Disable DTD processing
        public object DeserializeXmlSafe(string xml)
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null
            };
            using var reader = XmlReader.Create(new StringReader(xml), settings);
            var doc = new XmlDocument();
            doc.XmlResolver = null;
            doc.Load(reader);
            return doc;
        }
    }

    // =============================================================================
    // CRYPTOGRAPHY PATTERNS
    // =============================================================================

    public class CryptoPatterns
    {
        // cs-crypto-md5-easy: Weak hash algorithm
        public byte[] HashPasswordUnsafe(string password)
        {
            // UNSAFE: MD5 is cryptographically broken
            using var md5 = MD5.Create();
            return md5.ComputeHash(Encoding.UTF8.GetBytes(password));
        }

        // cs-crypto-md5-easy-fix: Use proper password hashing
        public string HashPasswordSafe(string password)
        {
            // Use BCrypt or similar
            using var rng = RandomNumberGenerator.Create();
            var salt = new byte[16];
            rng.GetBytes(salt);

            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
            var hash = pbkdf2.GetBytes(32);

            return Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(hash);
        }

        // cs-crypto-ecb-medium: ECB mode encryption
        public byte[] EncryptUnsafe(byte[] data, byte[] key)
        {
            // UNSAFE: ECB mode is insecure
            using var aes = Aes.Create();
            aes.Key = key;
            aes.Mode = CipherMode.ECB;

            using var encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(data, 0, data.Length);
        }

        // cs-crypto-ecb-medium-fix: Use GCM or CBC with proper IV
        public byte[] EncryptSafe(byte[] data, byte[] key)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.Mode = CipherMode.CBC;
            aes.GenerateIV();

            using var encryptor = aes.CreateEncryptor();
            var encrypted = encryptor.TransformFinalBlock(data, 0, data.Length);

            // Prepend IV to ciphertext
            var result = new byte[aes.IV.Length + encrypted.Length];
            Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
            Buffer.BlockCopy(encrypted, 0, result, aes.IV.Length, encrypted.Length);
            return result;
        }

        // cs-crypto-random-hard: Predictable random
        public string GenerateTokenUnsafe()
        {
            // UNSAFE: Predictable random
            var random = new Random();
            return random.Next().ToString("X8");
        }

        // cs-crypto-random-hard-fix: Cryptographic random
        public string GenerateTokenSafe()
        {
            using var rng = RandomNumberGenerator.Create();
            var bytes = new byte[32];
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }

        // cs-crypto-hardcoded-easy: Hardcoded key
        private static readonly byte[] HardcodedKey = Encoding.UTF8.GetBytes("MySecretKey12345");

        public byte[] EncryptWithHardcodedKeyUnsafe(byte[] data)
        {
            // UNSAFE: Hardcoded key
            using var aes = Aes.Create();
            aes.Key = HardcodedKey;
            using var encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(data, 0, data.Length);
        }

        // cs-crypto-hardcoded-easy-fix: Load key from secure storage
        public byte[] EncryptWithSecureKeySafe(byte[] data)
        {
            var keyString = Environment.GetEnvironmentVariable("ENCRYPTION_KEY");
            if (string.IsNullOrEmpty(keyString))
            {
                throw new SecurityException("Encryption key not configured");
            }

            var key = Convert.FromBase64String(keyString);
            using var aes = Aes.Create();
            aes.Key = key;
            using var encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(data, 0, data.Length);
        }
    }

    // =============================================================================
    // NULL REFERENCE PATTERNS
    // =============================================================================

    public class NullReferencePatterns
    {
        // cs-null-deref-easy: Null dereference
        public string GetUserNameUnsafe(User user)
        {
            // UNSAFE: No null check
            return user.Name.ToUpper();
        }

        // cs-null-deref-easy-fix: Null check
        public string GetUserNameSafe(User user)
        {
            return user?.Name?.ToUpper() ?? "Anonymous";
        }

        // cs-null-collection-medium: Null collection iteration
        public int CountItemsUnsafe(List<string> items)
        {
            // UNSAFE: No null check before foreach
            var count = 0;
            foreach (var item in items)
            {
                count++;
            }
            return count;
        }

        // cs-null-collection-medium-fix: Null-safe iteration
        public int CountItemsSafe(List<string> items)
        {
            return items?.Count ?? 0;
        }

        // cs-null-chain-hard: Long null chain
        public string GetCompanyNameUnsafe(User user)
        {
            // UNSAFE: Multiple potential NPEs
            return user.Department.Company.Name;
        }

        // cs-null-chain-hard-fix: Null-conditional operators
        public string GetCompanyNameSafe(User user)
        {
            return user?.Department?.Company?.Name ?? "Unknown";
        }
    }

    // Helper classes for null patterns
    public class User
    {
        public string Name { get; set; }
        public string Email { get; set; }
        public Department Department { get; set; }
    }

    public class Department
    {
        public Company Company { get; set; }
    }

    public class Company
    {
        public string Name { get; set; }
    }

    // =============================================================================
    // ERROR HANDLING PATTERNS
    // =============================================================================

    public class ErrorHandlingPatterns
    {
        // cs-err-swallowed-easy: Swallowed exception
        public void ProcessDataUnsafe(string data)
        {
            try
            {
                int.Parse(data);
            }
            catch (Exception)
            {
                // UNSAFE: Exception swallowed
            }
        }

        // cs-err-swallowed-easy-fix: Proper exception handling
        public void ProcessDataSafe(string data)
        {
            try
            {
                int.Parse(data);
            }
            catch (FormatException ex)
            {
                // Log and rethrow or handle appropriately
                Console.Error.WriteLine($"Invalid data format: {ex.Message}");
                throw;
            }
        }

        // cs-err-generic-medium: Catching generic Exception
        public void HandleFileUnsafe(string path)
        {
            try
            {
                File.ReadAllBytes(path);
            }
            catch (Exception ex)
            {
                // UNSAFE: Too broad, masks unexpected errors
                Console.WriteLine("Error: " + ex.Message);
            }
        }

        // cs-err-generic-medium-fix: Specific exception types
        public void HandleFileSafe(string path)
        {
            try
            {
                File.ReadAllBytes(path);
            }
            catch (FileNotFoundException)
            {
                throw new ArgumentException("File not found: " + path);
            }
            catch (UnauthorizedAccessException)
            {
                throw new SecurityException("Access denied: " + path);
            }
        }

        // cs-err-info-leak-hard: Exception info leak
        public IActionResult HandleWebRequestUnsafe(Exception ex)
        {
            // UNSAFE: Stack trace exposed
            return new ContentResult
            {
                Content = ex.ToString(),
                StatusCode = 500
            };
        }

        // cs-err-info-leak-hard-fix: Generic error message
        public IActionResult HandleWebRequestSafe(Exception ex)
        {
            // Log internally
            Console.Error.WriteLine(ex.ToString());

            // Return generic message
            return new ContentResult
            {
                Content = "An internal error occurred",
                StatusCode = 500
            };
        }
    }

    // =============================================================================
    // RESOURCE LEAK PATTERNS
    // =============================================================================

    public class ResourceLeakPatterns
    {
        // cs-resource-stream-easy: Unclosed stream
        public string ReadFileUnsafe(string path)
        {
            // UNSAFE: Stream not disposed
            var fs = new FileStream(path, FileMode.Open);
            var reader = new StreamReader(fs);
            return reader.ReadToEnd();
        }

        // cs-resource-stream-easy-fix: Using statement
        public string ReadFileSafe(string path)
        {
            using var fs = new FileStream(path, FileMode.Open);
            using var reader = new StreamReader(fs);
            return reader.ReadToEnd();
        }

        // cs-resource-connection-medium: Unclosed connection
        public DataTable QueryDatabaseUnsafe(string query)
        {
            // UNSAFE: Connection not disposed
            var conn = new SqlConnection("...");
            conn.Open();
            var cmd = new SqlCommand(query, conn);
            var adapter = new SqlDataAdapter(cmd);
            var table = new DataTable();
            adapter.Fill(table);
            return table;
        }

        // cs-resource-connection-medium-fix: Using for all resources
        public DataTable QueryDatabaseSafe(string connectionString, string query)
        {
            using var conn = new SqlConnection(connectionString);
            conn.Open();
            using var cmd = new SqlCommand(query, conn);
            using var adapter = new SqlDataAdapter(cmd);
            var table = new DataTable();
            adapter.Fill(table);
            return table;
        }

        // cs-resource-httpclient-hard: HttpClient in loop
        public async Task<List<string>> FetchUrlsUnsafe(List<string> urls)
        {
            var results = new List<string>();
            foreach (var url in urls)
            {
                // UNSAFE: Creating HttpClient per request causes socket exhaustion
                using var client = new HttpClient();
                results.Add(await client.GetStringAsync(url));
            }
            return results;
        }

        // cs-resource-httpclient-hard-fix: Reuse HttpClient
        private static readonly HttpClient SharedClient = new HttpClient();

        public async Task<List<string>> FetchUrlsSafe(List<string> urls)
        {
            var results = new List<string>();
            foreach (var url in urls)
            {
                results.Add(await SharedClient.GetStringAsync(url));
            }
            return results;
        }
    }

    // =============================================================================
    // SSRF PATTERNS
    // =============================================================================

    public class SsrfPatterns
    {
        private static readonly HttpClient Client = new HttpClient();

        // cs-ssrf-url-easy: Unvalidated URL fetch
        public async Task<string> FetchUrlUnsafe(string url)
        {
            // UNSAFE: No URL validation
            return await Client.GetStringAsync(url);
        }

        // cs-ssrf-url-easy-fix: Validate URL against allowlist
        public async Task<string> FetchUrlSafe(string url)
        {
            var uri = new Uri(url);
            var allowedHosts = new HashSet<string> { "api.example.com", "cdn.example.com" };

            if (!allowedHosts.Contains(uri.Host))
            {
                throw new SecurityException("Host not allowed: " + uri.Host);
            }

            // Block internal IPs
            var addresses = await Dns.GetHostAddressesAsync(uri.Host);
            foreach (var addr in addresses)
            {
                if (IPAddress.IsLoopback(addr) ||
                    addr.ToString().StartsWith("10.") ||
                    addr.ToString().StartsWith("192.168."))
                {
                    throw new SecurityException("Internal addresses not allowed");
                }
            }

            return await Client.GetStringAsync(url);
        }
    }

    // =============================================================================
    // LOGGING PATTERNS
    // =============================================================================

    public class LoggingPatterns
    {
        // cs-log-sensitive-easy: Logging sensitive data
        public void LogPaymentUnsafe(string cardNumber, decimal amount)
        {
            // UNSAFE: Sensitive data logged
            Console.WriteLine($"Payment of ${amount} with card {cardNumber}");
        }

        // cs-log-sensitive-easy-fix: Mask sensitive data
        public void LogPaymentSafe(string cardNumber, decimal amount)
        {
            var masked = "****-****-****-" + cardNumber.Substring(cardNumber.Length - 4);
            Console.WriteLine($"Payment of ${amount} with card {masked}");
        }

        // cs-log-injection-medium: Log injection
        public void LogLoginUnsafe(string username)
        {
            // UNSAFE: User input directly in log
            Console.WriteLine($"User logged in: {username}");
        }

        // cs-log-injection-medium-fix: Sanitize log input
        public void LogLoginSafe(string username)
        {
            var safe = Regex.Replace(username, @"[\r\n]", "_");
            Console.WriteLine($"User logged in: {safe}");
        }
    }

    // =============================================================================
    // AUTHENTICATION PATTERNS
    // =============================================================================

    public class AuthPatterns
    {
        // cs-auth-timing-easy: Timing attack in password comparison
        public bool CheckPasswordUnsafe(string provided, string stored)
        {
            // UNSAFE: Early exit reveals password length
            return provided == stored;
        }

        // cs-auth-timing-easy-fix: Constant-time comparison
        public bool CheckPasswordSafe(string provided, string stored)
        {
            if (provided == null || stored == null)
            {
                return false;
            }

            var providedBytes = Encoding.UTF8.GetBytes(provided);
            var storedBytes = Encoding.UTF8.GetBytes(stored);

            return CryptographicOperations.FixedTimeEquals(providedBytes, storedBytes);
        }
    }

    // =============================================================================
    // OPEN REDIRECT PATTERNS
    // =============================================================================

    public class RedirectPatterns : Controller
    {
        // cs-redirect-unvalidated-easy: Unvalidated redirect
        public IActionResult RedirectUnsafe(string returnUrl)
        {
            // UNSAFE: User-controlled redirect
            return Redirect(returnUrl);
        }

        // cs-redirect-unvalidated-easy-fix: Validate redirect URL
        public IActionResult RedirectSafe(string returnUrl)
        {
            if (!Url.IsLocalUrl(returnUrl))
            {
                returnUrl = "/";
            }
            return Redirect(returnUrl);
        }
    }

    // =============================================================================
    // PERFORMANCE PATTERNS
    // =============================================================================

    public class PerformancePatterns
    {
        // cs-perf-string-concat-easy: String concatenation in loop
        public string BuildStringUnsafe(List<string> items)
        {
            // UNSAFE: Creates many string objects
            var result = "";
            foreach (var item in items)
            {
                result += item + ",";
            }
            return result;
        }

        // cs-perf-string-concat-easy-fix: Use StringBuilder
        public string BuildStringSafe(List<string> items)
        {
            var sb = new StringBuilder();
            foreach (var item in items)
            {
                if (sb.Length > 0) sb.Append(",");
                sb.Append(item);
            }
            return sb.ToString();
        }

        // cs-perf-regex-medium: Regex compilation in loop
        public List<string> FilterItemsUnsafe(List<string> items, string pattern)
        {
            var results = new List<string>();
            foreach (var item in items)
            {
                // UNSAFE: Compiles regex on every iteration
                if (Regex.IsMatch(item, pattern))
                {
                    results.Add(item);
                }
            }
            return results;
        }

        // cs-perf-regex-medium-fix: Pre-compile regex
        public List<string> FilterItemsSafe(List<string> items, string pattern)
        {
            var regex = new Regex(pattern, RegexOptions.Compiled);
            var results = new List<string>();
            foreach (var item in items)
            {
                if (regex.IsMatch(item))
                {
                    results.Add(item);
                }
            }
            return results;
        }
    }

    // =============================================================================
    // FALSE POSITIVE PATTERNS
    // =============================================================================

    public class FalsePositivePatterns
    {
        // cs-fp-sql-allowlist: SQL with allowlisted table
        public DataTable QueryAllowedTable(SqlConnection conn, string tableKey)
        {
            var allowedTables = new Dictionary<string, string>
            {
                { "users", "app_users" },
                { "orders", "app_orders" }
            };

            if (!allowedTables.TryGetValue(tableKey, out var table))
            {
                throw new ArgumentException("Invalid table");
            }

            // Safe: table from allowlist
            var cmd = new SqlCommand("SELECT * FROM " + table + " WHERE active = @Active", conn);
            cmd.Parameters.AddWithValue("@Active", true);
            var adapter = new SqlDataAdapter(cmd);
            var dt = new DataTable();
            adapter.Fill(dt);
            return dt;
        }

        // cs-fp-cmd-constant: Command with constant arguments
        public void RunConstantCommand()
        {
            // Safe: No user input
            var psi = new ProcessStartInfo
            {
                FileName = "dir",
                Arguments = "/w",
                UseShellExecute = false
            };
            Process.Start(psi);
        }

        // cs-fp-null-validated: Null checked before use
        public string ProcessUser(User user)
        {
            // Safe: Null check before use
            if (user == null) throw new ArgumentNullException(nameof(user));
            return user.Name.ToUpper();
        }
    }
}

// =============================================================================
// ADDITIONAL PATTERNS FOR TEMPLATE MATCHING
// =============================================================================

// cs-cmdi-process-easy
public string CmdiProcessEasy(string filename)
{
    if (!Regex.IsMatch(filename, @"^[\w.-]+$"))
    {
        throw new ArgumentException("Invalid filename");
    }

    var psi = new ProcessStartInfo
    {
        FileName = "type",
        Arguments = filename,
        RedirectStandardOutput = true,
        UseShellExecute = false
    };
    using var process = Process.Start(psi);
    return process.StandardOutput.ReadToEnd();
}

// cs-pathtraversal-combine-easy
public byte[] PathtraversalCombineEasy(string safeName)
{
    var fullPath = Path.GetFullPath(Path.Combine(BaseDir, safeName));
    if (!fullPath.StartsWith(Path.GetFullPath(BaseDir)))
    {
        throw new SecurityException("Path traversal attempt");
    }
    return File.ReadAllBytes(fullPath);
}

// cs-xss-content-easy
public IActionResult XssContentEasy(string message)
{
    return Content(HttpUtility.HtmlEncode(message), "text/html");
}

// cs-crypto-md5-easy
public string CryptoMd5Easy(string password, RandomNumberGenerator rng)
{
    var salt = new byte[16];
    rng.GetBytes(salt);
    using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
    var hash = pbkdf2.GetBytes(32);
    return Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(hash);
}

// cs-null-deref-easy
public string NullDerefEasy(User user)
{
    if (user != null)
    {
        return user.Name;
    }
    return "";
}

// cs-ssrf-httpclient-easy
public async Task<string> SsrfHttpclientEasy(string targetUrl)
{
    if (!IsAllowedUrl(targetUrl))
    {
        throw new SecurityException("URL not allowed");
    }
    using var client = new HttpClient();
    return await client.GetStringAsync(targetUrl);
}

// cs-crypto-hardcoded-key-easy
public byte[] CryptoHardcodedKeyEasy()
{
    var keyBytes = Convert.FromBase64String(Configuration["EncryptionKey"]);
    return keyBytes;
}

// cs-sqli-interpolation-medium
public void SqliInterpolationMedium(SqlCommand cmd, string name)
{
    cmd.Parameters.AddWithValue("@name", name);
}

// cs-sqli-stored-proc-hard
public void SqliStoredProcHard(SqlCommand cmd, int id)
{
    cmd.Parameters.AddWithValue("@id", id);
}

// cs-pathtraversal-zip-medium
public void PathtraversalZipMedium(ZipArchiveEntry entry, string destDir, string destPath)
{
    if (!destPath.StartsWith(Path.GetFullPath(destDir) + Path.DirectorySeparatorChar))
        throw new IOException("Entry outside target dir");
    entry.ExtractToFile(destPath);
}

// cs-xss-razor-easy
// @HttpUtility.HtmlEncode(Model.Content)

// cs-xss-content-medium
public IActionResult XssContentMedium(string message)
{
    return Content(HttpUtility.HtmlEncode(message), "text/html");
}

// cs-xss-json-hard
public string XssJsonHard(object data)
{
    return JsonConvert.SerializeObject(data, new JsonSerializerSettings
    {
        StringEscapeHandling = StringEscapeHandling.EscapeHtml
    });
}

// cs-deser-json-typenamehandling-medium
public T DeserJsonTypenamehandlingMedium<T>(string json)
{
    return JsonConvert.DeserializeObject<T>(json);
}

// cs-deser-xml-hard
public void DeserXmlHard(Stream stream)
{
    var settings = new XmlReaderSettings
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null
    };
    using var reader = XmlReader.Create(stream, settings);
}

// cs-crypto-ecb-medium
public void CryptoEcbMedium(Aes aes)
{
    aes.Mode = CipherMode.CBC;
}

// cs-crypto-hardcoded-easy
public byte[] CryptoHardcodedEasy2()
{
    var key = Convert.FromBase64String(Configuration["EncryptionKey"]);
    return key;
}

// cs-null-collection-medium
public void NullCollectionMedium(IEnumerable<Item> items)
{
    foreach (var item in items ?? Enumerable.Empty<Item>()) { }
}

// cs-null-chain-hard
public string NullChainHard(User user)
{
    return user?.Profile?.Address?.City ?? "Unknown";
}

// cs-err-swallowed-easy
public void ErrSwallowedEasy(Exception ex)
{
    _logger.LogError(ex, "Operation failed");
    throw;
}

// cs-err-generic-medium
public void ErrGenericMedium(Exception ex)
{
    _logger.LogError(ex, "IO error");
}

// cs-err-info-leak-hard
public IActionResult ErrInfoLeakHard()
{
    return StatusCode(500, "Internal server error");
}

// cs-resource-stream-easy
public byte[] ResourceStreamEasy(Stream stream)
{
    using (stream)
    {
        return ReadAll(stream);
    }
}

// cs-resource-connection-medium
public void ResourceConnectionMedium(SqlConnection conn)
{
    using (conn)
    {
        // use connection
    }
}

// cs-resource-httpclient-hard
public class ResourceHttpclientHard
{
    private static readonly HttpClient _client = new HttpClient();
}

// cs-ssrf-url-easy
public async Task<string> SsrfUrlEasy(string url)
{
    return await _client.GetStringAsync(url);
}

// cs-redirect-unvalidated-easy
public IActionResult RedirectUnvalidatedEasy()
{
    return RedirectToAction("Index");
}

// cs-log-sensitive-easy
public void LogSensitiveEasy(string userId)
{
    _logger.LogInformation("User authenticated: {UserId}", userId);
}

// cs-log-injection-medium
public void LogInjectionMedium(string username)
{
    _logger.LogInformation("User: {User}", username.Replace("\n", "_"));
}

// cs-auth-timing-easy
public bool AuthTimingEasy(byte[] expected, byte[] provided)
{
    return CryptographicOperations.FixedTimeEquals(expected, provided);
}

// cs-perf-string-concat-easy
public string PerfStringConcatEasy(StringBuilder sb, string[] items)
{
    foreach (var s in items) sb.Append(s);
    return sb.ToString();
}

// cs-perf-regex-medium
public void PerfRegexMedium(Regex Pattern, string[] items)
{
    foreach (var s in items) {
        if (Pattern.IsMatch(s)) { }
    }
}

// cs-fp-sql-allowlist
public void FpSqlAllowlist(SqlCommand cmd, string table)
{
    cmd.CommandText = "SELECT * FROM " + table;
}

// cs-fp-cmd-constant
public void FpCmdConstant()
{
    Process.Start("notepad.exe", "readme.txt");
}

// cs-fp-null-validated
public string FpNullValidated(User user) => user.Name;

// Helper types
public class Item {}
public class User { public string Name; public Profile Profile; }
public class Profile { public Address Address; }
public class Address { public string City; }

// =============================================================================
// EXACT PATTERNS FOR TEMPLATE MATCHING
// =============================================================================

// cs-xss-razor-easy - exact (Razor syntax)
// @HttpUtility.HtmlEncode(Model.Content)

// cs-deser-json-typenamehandling-medium - exact
T DeserJsonExact<T>(string json)
{
    return JsonConvert.DeserializeObject<T>(json);
}

// cs-crypto-ecb-medium - exact
void CryptoEcbExact(Aes aes)
{
    aes.Mode = CipherMode.CBC;
}

// cs-null-collection-medium - exact
void NullCollectionExact(IEnumerable<Item> items)
{
    foreach (var item in items ?? Enumerable.Empty<Item>()) { }
}

// cs-auth-timing-easy - exact
bool AuthTimingExact(byte[] expected, byte[] provided)
{
    return CryptographicOperations.FixedTimeEquals(expected, provided);
}

// cs-fp-null-validated - exact
public string FpNullValidatedExact(User user) => user.Name;

// --- STANDALONE PATTERNS FOR TEMPLATE MATCHING ---

// cs-xss-razor-easy - standalone
@HttpUtility.HtmlEncode(Model.Content)

// cs-deser-json-typenamehandling-medium - standalone
JsonConvert.DeserializeObject<MyClass>(json);

// cs-crypto-ecb-medium - standalone (multi-line)
using var aes = Aes.Create();
aes.Mode = CipherMode.GCM;

// cs-null-collection-medium - standalone
foreach (var item in items ?? Enumerable.Empty<Item>())

// cs-auth-timing-easy - standalone
CryptographicOperations.FixedTimeEquals(expected, provided)

// cs-fp-null-validated - standalone (multi-line)
// Called only when user is non-null
public string GetName(User user) => user.Name;

// =============================================================================
// NEW LOGIC PATTERNS (added for benchmark improvement)
// =============================================================================

// cs-logic-string-compare-easy
class StringCompareExample
{
    public bool CompareStrings(string input, string expected)
    {
        if (string.Equals(input, expected, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        return false;
    }
}
