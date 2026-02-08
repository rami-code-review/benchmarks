// Benchmark patterns for Rust security and quality detection.
// Each function represents a template pattern for testing code review capabilities.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;

// =============================================================================
// UNSAFE BLOCK PATTERNS
// =============================================================================

/// rust-unsafe-deref-easy: Raw pointer dereference
pub fn read_raw_pointer_unsafe(ptr: *const i32) -> i32 {
    // UNSAFE: Dereferencing raw pointer without null check
    unsafe { *ptr }
}

/// rust-unsafe-deref-easy-fix: Safe pointer access
pub fn read_raw_pointer_safe(ptr: *const i32) -> Option<i32> {
    if ptr.is_null() {
        None
    } else {
        // Still needs unsafe, but with null check
        Some(unsafe { *ptr })
    }
}

/// rust-unsafe-transmute-medium: Type transmutation
pub fn bytes_to_string_unsafe(bytes: &[u8]) -> String {
    // UNSAFE: Transmute without validation
    unsafe { String::from_utf8_unchecked(bytes.to_vec()) }
}

/// rust-unsafe-transmute-medium-fix: Validated conversion
pub fn bytes_to_string_safe(bytes: &[u8]) -> Result<String, std::string::FromUtf8Error> {
    String::from_utf8(bytes.to_vec())
}

/// rust-unsafe-slice-from-raw-hard: Creating slice from raw parts
pub fn create_slice_unsafe(ptr: *const u8, len: usize) -> &'static [u8] {
    // UNSAFE: No validation of pointer or length
    unsafe { std::slice::from_raw_parts(ptr, len) }
}

/// rust-unsafe-slice-from-raw-hard-fix: Validated slice creation
pub fn create_slice_safe<'a>(data: &'a [u8], offset: usize, len: usize) -> Option<&'a [u8]> {
    if offset.saturating_add(len) <= data.len() {
        Some(&data[offset..offset + len])
    } else {
        None
    }
}

// =============================================================================
// COMMAND INJECTION PATTERNS
// =============================================================================

/// rust-cmdi-shell-easy: Shell command with user input
pub fn run_command_unsafe(filename: &str) -> io::Result<String> {
    // UNSAFE: Shell injection possible
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("cat {}", filename))
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// rust-cmdi-shell-easy-fix: Direct command with arguments
pub fn run_command_safe(filename: &str) -> io::Result<String> {
    // Validate filename
    if !filename.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '_' || c == '-') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid filename"));
    }

    let output = Command::new("cat")
        .arg(filename)
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// rust-cmdi-format-medium: Format string in command
pub fn search_files_unsafe(pattern: &str, directory: &str) -> io::Result<String> {
    // UNSAFE: User input in shell command
    let cmd = format!("grep -r '{}' {}", pattern, directory);
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// rust-cmdi-format-medium-fix: Separate arguments
pub fn search_files_safe(pattern: &str, directory: &str) -> io::Result<String> {
    // Validate inputs
    if pattern.contains('\'') || pattern.contains('"') || pattern.contains('\\') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid pattern"));
    }

    let output = Command::new("grep")
        .arg("-r")
        .arg(pattern)
        .arg(directory)
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// =============================================================================
// PATH TRAVERSAL PATTERNS
// =============================================================================

/// rust-pathtraversal-join-easy: Path join without validation
pub fn read_file_unsafe(base_dir: &str, filename: &str) -> io::Result<Vec<u8>> {
    // UNSAFE: Path traversal possible
    let path = Path::new(base_dir).join(filename);
    fs::read(&path)
}

/// rust-pathtraversal-join-easy-fix: Validated path
pub fn read_file_safe(base_dir: &str, filename: &str) -> io::Result<Vec<u8>> {
    let base = Path::new(base_dir).canonicalize()?;
    let full_path = base.join(filename).canonicalize()?;

    if !full_path.starts_with(&base) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Path traversal detected",
        ));
    }

    fs::read(&full_path)
}

/// rust-pathtraversal-strip-prefix-medium: Strip prefix bypass
pub fn serve_file_unsafe(base_dir: &Path, user_path: &str) -> io::Result<Vec<u8>> {
    // UNSAFE: Doesn't handle encoded paths
    let clean_path = user_path.trim_start_matches('/');
    let full_path = base_dir.join(clean_path);
    fs::read(&full_path)
}

/// rust-pathtraversal-strip-prefix-medium-fix: Proper canonicalization
pub fn serve_file_safe(base_dir: &Path, user_path: &str) -> io::Result<Vec<u8>> {
    // Decode URL-encoded paths
    let decoded = urlencoding::decode(user_path)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let base = base_dir.canonicalize()?;
    let full_path = base.join(decoded.trim_start_matches('/')).canonicalize()?;

    if !full_path.starts_with(&base) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Path traversal detected",
        ));
    }

    fs::read(&full_path)
}

// =============================================================================
// ERROR HANDLING PATTERNS
// =============================================================================

/// rust-err-unwrap-easy: Unchecked unwrap
pub fn parse_number_unsafe(s: &str) -> i32 {
    // UNSAFE: Panics on invalid input
    s.parse().unwrap()
}

/// rust-err-unwrap-easy-fix: Proper error handling
pub fn parse_number_safe(s: &str) -> Result<i32, std::num::ParseIntError> {
    s.parse()
}

/// rust-err-expect-medium: Expect without context
pub fn get_config_value_unsafe(config: &HashMap<String, String>, key: &str) -> String {
    // UNSAFE: Panics with generic message
    config.get(key).expect("key not found").clone()
}

/// rust-err-expect-medium-fix: Option handling
pub fn get_config_value_safe(
    config: &HashMap<String, String>,
    key: &str,
) -> Option<String> {
    config.get(key).cloned()
}

/// rust-err-ignore-hard: Ignoring Result
pub fn write_log_unsafe(path: &str, message: &str) {
    // UNSAFE: Error ignored
    let _ = fs::write(path, message);
}

/// rust-err-ignore-hard-fix: Handle or propagate error
pub fn write_log_safe(path: &str, message: &str) -> io::Result<()> {
    fs::write(path, message)
}

/// rust-err-question-mark-leak: ? operator leaking sensitive info
pub fn read_secret_unsafe(path: &str) -> io::Result<String> {
    // UNSAFE: Error message may leak path
    let content = fs::read_to_string(path)?;
    Ok(content)
}

/// rust-err-question-mark-leak-fix: Wrap error without sensitive data
pub fn read_secret_safe(path: &str) -> Result<String, &'static str> {
    fs::read_to_string(path).map_err(|_| "Failed to read secret file")
}

// =============================================================================
// MEMORY SAFETY PATTERNS
// =============================================================================

/// rust-mem-use-after-move-easy: Use after move
pub fn use_after_move_unsafe() -> String {
    let s = String::from("hello");
    let _moved = s;
    // This would not compile: s.clone()
    // Simulating the pattern for benchmark purposes
    String::new()
}

/// rust-mem-double-free-medium: Double free via unsafe
pub fn double_free_unsafe(ptr: *mut u8) {
    // UNSAFE: Double free possible
    unsafe {
        let _ = Box::from_raw(ptr);
        // If called again, double free
    }
}

/// rust-mem-double-free-medium-fix: Take ownership properly
pub fn deallocate_safe(boxed: Box<[u8]>) {
    // Safe: Box handles deallocation
    drop(boxed);
}

// =============================================================================
// CONCURRENCY PATTERNS
// =============================================================================

/// rust-race-shared-mut-easy: Shared mutable state without synchronization
static mut COUNTER_UNSAFE: i32 = 0;

pub fn increment_counter_unsafe() {
    // UNSAFE: Data race
    unsafe {
        COUNTER_UNSAFE += 1;
    }
}

/// rust-race-shared-mut-easy-fix: Use atomic or mutex
use std::sync::atomic::{AtomicI32, Ordering};

static COUNTER_SAFE: AtomicI32 = AtomicI32::new(0);

pub fn increment_counter_safe() {
    COUNTER_SAFE.fetch_add(1, Ordering::SeqCst);
}

/// rust-race-arc-mutex-medium: Arc without Mutex for mutable access
pub fn shared_data_unsafe() {
    let data = Arc::new(vec![1, 2, 3]);
    let data_clone = Arc::clone(&data);

    thread::spawn(move || {
        // Cannot mutate without Mutex - this is actually safe in Rust
        // but demonstrates the pattern
        println!("{:?}", data_clone);
    });
}

/// rust-race-arc-mutex-medium-fix: Arc with Mutex
pub fn shared_data_safe() {
    let data = Arc::new(Mutex::new(vec![1, 2, 3]));
    let data_clone = Arc::clone(&data);

    thread::spawn(move || {
        let mut guard = data_clone.lock().unwrap();
        guard.push(4);
    });
}

/// rust-race-rwlock-hard: RwLock deadlock potential
pub fn rwlock_deadlock_unsafe(lock: &RwLock<i32>) {
    let _read1 = lock.read().unwrap();
    // UNSAFE: Attempting write while holding read lock can deadlock
    // This is a pattern to detect, actual code would vary
}

// =============================================================================
// SQL INJECTION PATTERNS (with sqlx/diesel)
// =============================================================================

/// rust-sqli-format-easy: Format string in SQL
pub fn query_user_unsafe(conn: &str, user_id: &str) -> String {
    // UNSAFE: SQL injection
    format!("SELECT * FROM users WHERE id = '{}'", user_id)
}

/// rust-sqli-format-easy-fix: Use parameterized query
pub fn query_user_safe(_conn: &str, user_id: &str) -> (String, Vec<String>) {
    // Return query with placeholder and parameters separately
    ("SELECT * FROM users WHERE id = $1".to_string(), vec![user_id.to_string()])
}

/// rust-sqli-concat-medium: String concatenation in SQL
pub fn search_users_unsafe(name: &str, status: &str) -> String {
    // UNSAFE: Multiple injection points
    let mut query = "SELECT * FROM users WHERE 1=1".to_string();
    if !name.is_empty() {
        query.push_str(&format!(" AND name LIKE '%{}%'", name));
    }
    if !status.is_empty() {
        query.push_str(&format!(" AND status = '{}'", status));
    }
    query
}

/// rust-sqli-concat-medium-fix: Build query with parameters
pub fn search_users_safe(name: &str, status: &str) -> (String, Vec<String>) {
    let mut query = "SELECT * FROM users WHERE 1=1".to_string();
    let mut params = Vec::new();
    let mut param_idx = 1;

    if !name.is_empty() {
        query.push_str(&format!(" AND name LIKE ${}", param_idx));
        params.push(format!("%{}%", name));
        param_idx += 1;
    }
    if !status.is_empty() {
        query.push_str(&format!(" AND status = ${}", param_idx));
        params.push(status.to_string());
    }

    (query, params)
}

// =============================================================================
// CRYPTOGRAPHY PATTERNS
// =============================================================================

/// rust-crypto-weak-random-easy: Using non-cryptographic random
use rand::Rng;

pub fn generate_token_unsafe() -> String {
    // UNSAFE: Not cryptographically secure
    let mut rng = rand::thread_rng();
    format!("{:x}", rng.gen::<u64>())
}

/// rust-crypto-weak-random-easy-fix: Use cryptographic random
use rand::RngCore;

pub fn generate_token_safe() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// rust-crypto-hardcoded-medium: Hardcoded secret
const HARDCODED_KEY: &str = "super_secret_key_12345";

pub fn encrypt_unsafe(data: &[u8]) -> Vec<u8> {
    // UNSAFE: Hardcoded key
    let key = HARDCODED_KEY.as_bytes();
    // Simulated encryption
    data.iter().zip(key.iter().cycle()).map(|(d, k)| d ^ k).collect()
}

/// rust-crypto-hardcoded-medium-fix: Load key from environment
pub fn encrypt_safe(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let key = std::env::var("ENCRYPTION_KEY")
        .map_err(|_| "ENCRYPTION_KEY not set")?;
    let key_bytes = key.as_bytes();
    Ok(data.iter().zip(key_bytes.iter().cycle()).map(|(d, k)| d ^ k).collect())
}

// =============================================================================
// INPUT VALIDATION PATTERNS
// =============================================================================

/// rust-input-unchecked-easy: Unchecked array index
pub fn get_item_unsafe(items: &[String], index: usize) -> &String {
    // UNSAFE: Panics on out-of-bounds
    &items[index]
}

/// rust-input-unchecked-easy-fix: Checked access
pub fn get_item_safe(items: &[String], index: usize) -> Option<&String> {
    items.get(index)
}

/// rust-input-overflow-medium: Integer overflow
pub fn add_numbers_unsafe(a: u32, b: u32) -> u32 {
    // UNSAFE: May overflow in release mode
    a + b
}

/// rust-input-overflow-medium-fix: Checked arithmetic
pub fn add_numbers_safe(a: u32, b: u32) -> Option<u32> {
    a.checked_add(b)
}

/// rust-input-regex-redos-hard: ReDoS vulnerable regex
pub fn validate_email_unsafe(email: &str) -> bool {
    // UNSAFE: Catastrophic backtracking possible
    let re = regex::Regex::new(r"^([a-zA-Z0-9]+)*@[a-zA-Z0-9]+\.[a-zA-Z]+$").unwrap();
    re.is_match(email)
}

/// rust-input-regex-redos-hard-fix: Non-backtracking regex
pub fn validate_email_safe(email: &str) -> bool {
    // Simpler regex without nested quantifiers
    let re = regex::Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    re.is_match(email)
}

// =============================================================================
// DESERIALIZATION PATTERNS
// =============================================================================

/// rust-deser-untrusted-easy: Deserializing untrusted data
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct Config {
    pub path: String,
    pub command: String,
}

pub fn load_config_unsafe(json: &str) -> Config {
    // UNSAFE: Deserializing untrusted input
    serde_json::from_str(json).unwrap()
}

/// rust-deser-untrusted-easy-fix: Validate after deserialization
pub fn load_config_safe(json: &str) -> Result<Config, &'static str> {
    let config: Config = serde_json::from_str(json)
        .map_err(|_| "Invalid JSON")?;

    // Validate fields
    if config.path.contains("..") {
        return Err("Invalid path");
    }
    if config.command.contains(';') || config.command.contains('|') {
        return Err("Invalid command");
    }

    Ok(config)
}

// =============================================================================
// LOGGING PATTERNS
// =============================================================================

/// rust-log-sensitive-easy: Logging sensitive data
pub fn log_request_unsafe(auth_header: &str, body: &str) {
    // UNSAFE: Logging sensitive headers
    println!("Request - Auth: {}, Body: {}", auth_header, body);
}

/// rust-log-sensitive-easy-fix: Redact sensitive data
pub fn log_request_safe(auth_header: &str, body: &str) {
    let redacted_auth = if auth_header.len() > 4 {
        format!("{}...", &auth_header[..4])
    } else {
        "[REDACTED]".to_string()
    };
    println!("Request - Auth: {}, Body: {}", redacted_auth, body);
}

// =============================================================================
// RESOURCE MANAGEMENT PATTERNS
// =============================================================================

/// rust-resource-file-leak-easy: File handle leak
pub fn read_partial_unsafe(path: &str, bytes: usize) -> io::Result<Vec<u8>> {
    // UNSAFE: File not explicitly closed on error path
    let mut file = File::open(path)?;
    let mut buffer = vec![0u8; bytes];
    file.read_exact(&mut buffer)?;
    // File closed when dropped, but pattern shows potential issue
    Ok(buffer)
}

/// rust-resource-file-leak-easy-fix: Explicit resource management
pub fn read_partial_safe(path: &str, bytes: usize) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut buffer = vec![0u8; bytes];

    // Use read to handle partial reads
    let read = file.read(&mut buffer)?;
    buffer.truncate(read);

    Ok(buffer)
}

/// rust-resource-temp-file-medium: Temp file not cleaned up
pub fn process_data_unsafe(data: &[u8]) -> io::Result<()> {
    // UNSAFE: Temp file may not be cleaned up
    let temp_path = "/tmp/processing_temp";
    fs::write(temp_path, data)?;
    // Process...
    // If error occurs here, temp file remains
    fs::remove_file(temp_path)?;
    Ok(())
}

/// rust-resource-temp-file-medium-fix: Use tempfile crate
pub fn process_data_safe(data: &[u8]) -> io::Result<()> {
    // Safe: tempfile is automatically cleaned up
    use std::io::Write;

    let mut temp = tempfile::NamedTempFile::new()?;
    temp.write_all(data)?;
    // Process using temp.path()
    // File is automatically deleted when temp goes out of scope
    Ok(())
}

// =============================================================================
// TIMING ATTACK PATTERNS
// =============================================================================

/// rust-timing-comparison-easy: Non-constant-time comparison
pub fn verify_token_unsafe(provided: &str, expected: &str) -> bool {
    // UNSAFE: Early exit reveals information
    provided == expected
}

/// rust-timing-comparison-easy-fix: Constant-time comparison
pub fn verify_token_safe(provided: &[u8], expected: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    provided.ct_eq(expected).into()
}

// =============================================================================
// SSRF PATTERNS
// =============================================================================

/// rust-ssrf-url-easy: Unvalidated URL fetch
pub async fn fetch_url_unsafe(url: &str) -> Result<String, &'static str> {
    // UNSAFE: No URL validation
    // reqwest::get(url).await?.text().await
    Ok(format!("Fetched: {}", url))
}

/// rust-ssrf-url-easy-fix: Validate URL against allowlist
pub async fn fetch_url_safe(url: &str) -> Result<String, &'static str> {
    let parsed = url::Url::parse(url).map_err(|_| "Invalid URL")?;

    let allowed_hosts = ["api.example.com", "cdn.example.com"];
    let host = parsed.host_str().ok_or("No host in URL")?;

    if !allowed_hosts.contains(&host) {
        return Err("Host not allowed");
    }

    // Check for internal IPs would go here
    if host == "localhost" || host.starts_with("127.") || host.starts_with("10.") {
        return Err("Internal addresses not allowed");
    }

    // reqwest::get(url).await?.text().await
    Ok(format!("Fetched: {}", url))
}

// =============================================================================
// FALSE POSITIVE PATTERNS
// =============================================================================

/// rust-fp-unsafe-ffi: Necessary unsafe for FFI
extern "C" {
    fn strlen(s: *const std::os::raw::c_char) -> usize;
}

pub fn get_c_string_length(s: &std::ffi::CStr) -> usize {
    // Safe: CStr guarantees null-terminated, valid UTF-8
    unsafe { strlen(s.as_ptr()) }
}

/// rust-fp-unwrap-guaranteed: Unwrap with guaranteed success
pub fn parse_constant() -> i32 {
    // Safe: Constant is known-valid
    "42".parse().unwrap()
}

/// rust-fp-index-checked: Index after bounds check
pub fn get_checked_item(items: &[String], index: usize) -> Option<&String> {
    if index < items.len() {
        // Safe: Bounds already checked
        Some(&items[index])
    } else {
        None
    }
}

// =============================================================================
// PERFORMANCE PATTERNS
// =============================================================================

/// rust-perf-clone-easy: Unnecessary clone
pub fn process_string_unsafe(s: String) -> String {
    // UNSAFE: Unnecessary clone
    let copy = s.clone();
    copy.to_uppercase()
}

/// rust-perf-clone-easy-fix: Take ownership directly
pub fn process_string_safe(s: String) -> String {
    s.to_uppercase()
}

/// rust-perf-collect-medium: Collecting to re-iterate
pub fn sum_doubled_unsafe(items: &[i32]) -> i32 {
    // UNSAFE: Unnecessary allocation
    let doubled: Vec<i32> = items.iter().map(|x| x * 2).collect();
    doubled.iter().sum()
}

/// rust-perf-collect-medium-fix: Chain iterators
pub fn sum_doubled_safe(items: &[i32]) -> i32 {
    items.iter().map(|x| x * 2).sum()
}

/// rust-perf-string-push-hard: String concatenation in loop
pub fn build_string_unsafe(items: &[&str]) -> String {
    // UNSAFE: Many reallocations
    let mut result = String::new();
    for item in items {
        result = result + item + ",";
    }
    result
}

/// rust-perf-string-push-hard-fix: Use with_capacity and push_str
pub fn build_string_safe(items: &[&str]) -> String {
    let total_len: usize = items.iter().map(|s| s.len() + 1).sum();
    let mut result = String::with_capacity(total_len);
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            result.push(',');
        }
        result.push_str(item);
    }
    result
}

// Module exports for compilation check
pub mod patterns {
    pub use super::*;
}

// =============================================================================
// ADDITIONAL PATTERNS FOR TEMPLATE MATCHING
// =============================================================================

// rust-pathtraversal-join-easy
fn pathtraversal_join_easy(base: &Path, filename: &str) -> io::Result<Vec<u8>> {
    let full_path = base.join(filename).canonicalize()?;

    if !full_path.starts_with(&base) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Path traversal"));
    }

    fs::read(full_path)
}

// rust-err-unwrap-easy
fn err_unwrap_easy(s: &str) -> Result<i32, std::num::ParseIntError> {
    s.parse::<i32>()
}

// rust-race-shared-mut-easy
fn race_shared_mut_easy() {
    COUNTER.fetch_add(1, Ordering::SeqCst);
}

static COUNTER: AtomicUsize = AtomicUsize::new(0);

// rust-sqli-format-easy
fn sqli_format_easy(user_id: i32) -> (String, Vec<String>) {
    ("SELECT id, name, email FROM users WHERE id = $1".to_string(), vec![user_id.to_string()])
}

// rust-crypto-weak-hash-easy
fn crypto_weak_hash_easy(password: &str) -> impl AsRef<[u8]> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.finalize()
}

// rust-index-unchecked-easy
fn index_unchecked_easy(data: &[u8], index: usize) -> Option<u8> {
    data.get(index).copied()
}

// rust-unsafe-slice-from-raw-hard
fn unsafe_slice_from_raw_hard(data: &[u8], offset: usize, len: usize) -> &[u8] {
    &data[offset..offset + len]
}

// rust-cmdi-format-medium
fn cmdi_format_medium(pattern: &str, file: &str) -> io::Result<Output> {
    Command::new("grep")
        .arg(pattern)
        .arg(file)
        .output()
}

// rust-pathtraversal-strip-prefix-medium
fn pathtraversal_strip_prefix_medium(base: &Path, filename: &str) -> Result<PathBuf, &'static str> {
    let full = base.join(filename).canonicalize().map_err(|_| "Invalid path")?;
    if !full.starts_with(&base) {
        return Err("Path traversal");
    }
    Ok(full)
}

// rust-err-ignore-hard
fn err_ignore_hard(file: &File) -> io::Result<()> {
    file.sync_all()
}

// rust-err-question-mark-leak
fn err_question_mark_leak<T>(result: Result<T, DbError>) -> Result<T, ApiError> {
    result.map_err(|_| ApiError::Internal("Database error".into()))
}

struct DbError;
struct ApiError { msg: String }
impl ApiError {
    fn Internal(msg: String) -> Self { ApiError { msg } }
}

// rust-sqli-concat-medium
async fn sqli_concat_medium(pool: &Pool, user_id: i32) -> Result<User, Error> {
    sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
}

// rust-crypto-weak-random-easy
fn crypto_weak_random_easy() -> [u8; 32] {
    let mut rng = OsRng;
    let key: [u8; 32] = rng.gen();
    key
}

// rust-crypto-hardcoded-medium
fn crypto_hardcoded_medium() -> Result<String, std::env::VarError> {
    let key = std::env::var("ENCRYPTION_KEY")?;
    Ok(key)
}

// rust-input-unchecked-easy
fn input_unchecked_easy(data: &[u8], index: usize) -> Option<u8> {
    data.get(index).copied()
}

// rust-input-overflow-medium
fn input_overflow_medium(a: u32, b: u32) -> Result<u32, &'static str> {
    a.checked_add(b).ok_or("overflow")
}

// rust-input-regex-redos-hard
fn input_regex_redos_hard() -> Result<Regex, regex::Error> {
    Regex::new(r"^[a-zA-Z0-9]+$")
}

// rust-deser-untrusted-easy
fn deser_untrusted_easy<T: DeserializeOwned>(input: &str) -> Result<T, serde_json::Error> {
    serde_json::from_str::<T>(input)
}

// rust-log-sensitive-easy
fn log_sensitive_easy(user_id: &str) {
    info!("User authenticated: {}", user_id);
}

// rust-resource-file-leak-easy
fn resource_file_leak_easy(path: &Path) -> io::Result<String> {
    let file = File::open(path)?;
    let mut contents = String::new();
    // File dropped automatically
    Ok(contents)
}

// rust-resource-temp-file-medium
fn resource_temp_file_medium() -> io::Result<()> {
    let temp = tempfile::NamedTempFile::new()?;
    // Automatically cleaned up on drop
    Ok(())
}

// rust-timing-comparison-easy
fn timing_comparison_easy(a: &[u8], b: &[u8]) -> bool {
    constant_time_eq::constant_time_eq(a, b)
}

// rust-ssrf-url-easy
async fn ssrf_url_easy(url: &str) -> Result<Response, reqwest::Error> {
    if !is_allowed_host(url) {
        return Err("Host not allowed".into());
    }
    reqwest::get(url).await
}

// rust-perf-clone-easy
fn perf_clone_easy(data: &Data) {
    process(data);
}

// rust-perf-collect-medium
fn perf_collect_medium(items: &[Item]) {
    items.iter().filter(|x| x.active).for_each(process_item);
}

// rust-perf-string-push-hard
fn perf_string_push_hard(items: &[&str]) -> String {
    let mut result = String::new();
    for s in items {
        result.push_str(s);
    }
    result
}

// rust-fp-unsafe-ffi
unsafe fn fp_unsafe_ffi(ptr: *const u8, len: usize) {
    unsafe { ffi_function(ptr, len) }
}

extern "C" { fn ffi_function(ptr: *const u8, len: usize); }

// rust-fp-unwrap-guaranteed
fn fp_unwrap_guaranteed() -> Regex {
    let re = Regex::new(r"^\d+$").unwrap();
    re
}

// rust-fp-index-checked
fn fp_index_checked(data: &[u8]) -> Option<u8> {
    if !data.is_empty() {
        let first = data[0]; // Safe after check
        Some(first)
    } else {
        None
    }
}

// Types for patterns
struct User { id: i32, name: String }
struct Item { active: bool }
struct Data;
struct Pool;
struct Error;
struct Response;
fn process<T>(_: T) {}
fn process_item<T>(_: T) {}
fn is_allowed_host(_: &str) -> bool { true }
