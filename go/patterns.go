//go:build patterns

// Package benchmarks contains exact template patterns for benchmark testing.
// Each function contains the EXACT OriginalCode from templates.go.
package benchmarks

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// Interfaces for pattern matching
var db *sql.DB
var userID, name, filters, role string
var apiKey, password string
var err error
var file interface{ Close() error }
var path string
var data []byte
var mu sync.Mutex
var counter int
var user struct {
	IsAdmin       bool
	HasPermission func(string) bool
	Name          string
}
var items []string
var resource string
var dir, pattern, safeDir, username string
var baseDir, userPath string
var key, value string
var m map[string]int
var val interface{}
var status, StatusActive int
var results []struct{ Value string }
var item string
var op func() error
var condition1, condition2, condition3 bool
var files []string
var f *os.File
var userIDs []int
var logger interface{ Info(string, ...interface{}) }
var targetURL string
var request interface {
	GetParameter(string) string
	FormValue(string) string
}
var r *http.Request
var w http.ResponseWriter
var providedToken, expectedToken string
var allowedTables map[string]string
var tableKey string
var id int

// =============================================================================
// SQL INJECTION PATTERNS
// =============================================================================

// SQLiConcatEasy - go-sqli-concat-easy
func SQLiConcatEasy() {
	db.Query("SELECT * FROM users WHERE id = $1", userID)
}

// SQLiSprintfEasy - go-sqli-sprintf-easy
func SQLiSprintfEasy() {
	db.Query("SELECT * FROM users WHERE name = $1", name)
}

// SQLiBuilderMedium - go-sqli-builder-medium
func SQLiBuilderMedium() {
	query, args := buildQuery(filters)
	db.Query(query, args...)
}

func buildQuery(filters string) (string, []interface{}) {
	return "", nil
}

// SQLiIndirectHard - go-sqli-indirect-hard
func SQLiIndirectHard() {
	stmt, _ := db.Prepare("SELECT * FROM users WHERE role = $1")
	rows, _ := stmt.Query(role)
	_ = rows
}

// =============================================================================
// SECRETS PATTERNS
// =============================================================================

// SecretAPIKeyEasy - go-secret-apikey-easy
func SecretAPIKeyEasy() {
	apiKey := os.Getenv("API_KEY")
	_ = apiKey
}

// SecretPasswordEasy - go-secret-password-easy
func SecretPasswordEasy() {
	password := os.Getenv("DB_PASSWORD")
	_ = password
}

// =============================================================================
// CRYPTO PATTERNS
// =============================================================================

// CryptoMD5Easy - go-crypto-md5-easy
func CryptoMD5Easy() {
	hash := sha256.Sum256([]byte(password))
	_ = hash
}

// CryptoSHA1Easy - go-crypto-sha1-easy
func CryptoSHA1Easy() {
	hash := sha256.Sum256(data)
	_ = hash
}

// =============================================================================
// ERROR HANDLING PATTERNS
// =============================================================================

// ErrSwallowedEasy - go-err-swallowed-easy
func ErrSwallowedEasy() error {
	if err != nil {
		return fmt.Errorf("failed to process: %w", err)
	}
	return nil
}

// ErrIgnoredEasy - go-err-ignored-easy
func ErrIgnoredEasy() error {
	if err := file.Close(); err != nil {
		return err
	}
	return nil
}

// ErrBlankEasy - go-err-blank-easy
func ErrBlankEasy() ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// ErrShadowMedium - go-err-shadow-medium
func ErrShadowMedium() error {
	if err := doSomething(); err != nil {
		return err
	}
	return nil
}

func doSomething() error { return nil }
func handleError(err error) error { return err }

// =============================================================================
// NULL SAFETY PATTERNS
// =============================================================================

// NilDerefEasy - go-nil-deref-easy
func NilDerefEasy(user *struct{ Name string }) string {
	if user != nil {
		return user.Name
	}
	return ""
}

// NilMapEasy - go-nil-map-easy
func NilMapEasy() {
	m := make(map[string]int)
	m[key] = 1
	_ = m
}

// NilSliceMedium - go-nil-slice-medium
func NilSliceMedium() {
	if len(items) > 0 {
		first := items[0]
		_ = first
	}
}

// NilInterfaceMedium - go-nil-interface-medium
func NilInterfaceMedium() {
	if val != nil {
		str := val.(string)
		_ = str
	}
}

// =============================================================================
// LOGIC PATTERNS
// =============================================================================

// LogicOffByOneEasy - go-logic-offbyone-easy
func LogicOffByOneEasy() {
	for i := 0; i < len(items); i++ {
		_ = items[i]
	}
}

// LogicRaceEasy - go-logic-race-easy
func LogicRaceEasy() {
	mu.Lock()
	defer mu.Unlock()
	counter++
}

// LogicBooleanEasy - go-logic-boolean-easy
func LogicBooleanEasy() bool {
	if user.IsAdmin || user.HasPermission(resource) {
		return true
	}
	return false
}

// LogicEqualityMedium - go-logic-equality-medium
func LogicEqualityMedium() {
	if status == StatusActive {
		process()
	}
}

func process() {}

// LogicDeferLoopMedium - go-logic-defer-loop-medium
func LogicDeferLoopMedium() {
	for _, file := range files {
		f, _ := os.Open(file)
		data, _ := io.ReadAll(f)
		f.Close()
		processData(data)
	}
}

func processData(data []byte) {}

// LogicGoroutineVarMedium - go-logic-goroutine-var-medium
func LogicGoroutineVarMedium() {
	for _, item := range items {
		item := item
		go processItem(item)
	}
}

func processItem(item string) {}

// =============================================================================
// COMMAND INJECTION PATTERNS
// =============================================================================

// CmdiShellEasy - go-cmdi-shell-easy
func CmdiShellEasy() {
	exec.Command("ls", "-la", filepath.Clean(dir))
}

// CmdiBashEasy - go-cmdi-bash-easy
func CmdiBashEasy() {
	exec.Command("grep", "-r", pattern, safeDir)
}

// CmdiSprintfMedium - go-cmdi-sprintf-medium
func CmdiSprintfMedium() {
	args := []string{"-u", username}
	exec.Command("id", args...)
}

// =============================================================================
// PATH TRAVERSAL PATTERNS
// =============================================================================

// PathTraversalJoinEasy - go-pathtraversal-join-easy
func PathTraversalJoinEasy() string {
	return filepath.Join(baseDir, filepath.Clean(userPath))
}

// PathTraversalNocheckMedium - go-pathtraversal-nocheck-medium
func PathTraversalNocheckMedium() (string, error) {
	fullPath := filepath.Join(baseDir, filepath.Clean(userPath))
	if !strings.HasPrefix(fullPath, baseDir) {
		return "", errors.New("path traversal attempt")
	}
	return fullPath, nil
}

// =============================================================================
// PERFORMANCE PATTERNS
// =============================================================================

// PerfNPlus1Easy - go-perf-nplus1-easy
func PerfNPlus1Easy() {
	users, _ := db.Query("SELECT * FROM users WHERE id = ANY($1)", userIDs)
	_ = users
}

// PerfPreallocEasy - go-perf-prealloc-easy
func PerfPreallocEasy() {
	results := make([]struct{ Value string }, 0, len(items))
	for _, item := range items {
		results = append(results, struct{ Value string }{item})
	}
	_ = results
}

// PerfStringConcatMedium - go-perf-string-concat-medium
func PerfStringConcatMedium() string {
	var sb strings.Builder
	for _, s := range items {
		sb.WriteString(s)
	}
	result := sb.String()
	return result
}

// =============================================================================
// MAINTAINABILITY PATTERNS
// =============================================================================

// MaintMagicNumberEasy - go-maint-magic-number-easy
func MaintMagicNumberEasy() {
	const maxRetries = 3
	for i := 0; i < maxRetries; i++ {
		if err := op(); err != nil {
			continue
		}
	}
}

// MaintDeepNestingMedium - go-maint-deep-nesting-medium
func MaintDeepNestingMedium() error {
	if !condition1 {
		return errors.New("err1")
	}
	if !condition2 {
		return errors.New("err2")
	}
	return doWork()
}

func doWork() error { return nil }

// =============================================================================
// SSRF PATTERNS
// =============================================================================

// SSRFNoValidateMedium - go-ssrf-novalidate-medium
func SSRFNoValidateMedium() (*http.Response, error) {
	if !isAllowedHost(targetURL) {
		return nil, errors.New("forbidden host")
	}
	resp, _ := http.Get(targetURL)
	return resp, nil
}

func isAllowedHost(url string) bool { return true }

// =============================================================================
// FALSE POSITIVE PATTERNS
// =============================================================================

// FPSQLPrepared - go-fp-sql-prepared
func FPSQLPrepared() {
	table := allowedTables[tableKey]
	db.Query("SELECT * FROM "+table+" WHERE id = $1", id)
}

// FPCmdConstant - go-fp-cmd-constant
func FPCmdConstant() {
	cmd := exec.Command("sh", "-c", "echo hello")
	cmd.Run()
}

// FPNilCheckedElsewhere - go-fp-nil-checked-elsewhere
// Called only when user is non-nil per contract
func FPNilCheckedElsewhere(user *struct{ Name string }) string {
	return user.Name
}

// =============================================================================
// CVE PATTERNS
// =============================================================================

// CVESQLiMoveitStyle - go-cve-sqli-moveit-style
func CVESQLiMoveitStyle() {
	// Safe: parameterized query
	rows, err := db.Query("SELECT * FROM accounts WHERE custID = $1", request.GetParameter("id"))
	_, _ = rows, err
}

// CVECmdiShellshockStyle - go-cve-cmdi-shellshock-style
func CVECmdiShellshockStyle(userAgent string) {
	// Safe: use exec.Command with separate args
	cmd := exec.Command("echo", userAgent)
	output, err := cmd.Output()
	_, _ = output, err
}

// CVELogInjection - go-cve-log-injection
func CVELogInjection(username string) {
	// Safe: log with structured fields
	logger.Info("user login", "username", sanitizeLogInput(username))
}

func sanitizeLogInput(s string) string { return s }

// CVESSRFUnvalidated - go-cve-ssrf-unvalidated
func CVESSRFUnvalidated() (*http.Response, error) {
	// Safe: validate URL against allowlist before request
	if !isAllowedURL(targetURL) {
		return nil, errors.New("URL not allowed")
	}
	resp, err := http.Get(targetURL)
	return resp, err
}

func isAllowedURL(url string) bool { return true }

// CVEPathTraversalFile - go-cve-pathtraversal-file
func CVEPathTraversalFile() ([]byte, error) {
	// Safe: resolve path and validate within base directory
	cleanPath := filepath.Clean(userPath)
	fullPath := filepath.Join(baseDir, cleanPath)
	if !strings.HasPrefix(fullPath, baseDir) {
		return nil, errors.New("path traversal attempt")
	}
	data, err := os.ReadFile(fullPath)
	return data, err
}

// CVEAuthBypass - go-cve-auth-bypass
func CVEAuthBypass(w http.ResponseWriter, r *http.Request) {
	// Safe: verify authentication before processing
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	user, err := getUserData(r.URL.Query().Get("id"))
	_, _ = user, err
}

func isAuthenticated(r *http.Request) bool { return true }
func getUserData(id string) (interface{}, error) { return nil, nil }

// CVEIDOR - go-cve-idor
func CVEIDOR(orderID, currentUserID string) (*struct{ UserID string }, error) {
	// Safe: verify user owns the requested resource
	order, err := getOrder(orderID)
	if order.UserID != currentUserID {
		return nil, errors.New("access denied")
	}
	return order, err
}

func getOrder(id string) (*struct{ UserID string }, error) { return &struct{ UserID string }{}, nil }

// CVERaceTOCTOU - go-cve-race-toctou
func CVERaceTOCTOU(filepath string) ([]byte, error) {
	// Safe: use atomic operation or lock
	mu.Lock()
	defer mu.Unlock()
	if _, err := os.Stat(filepath); err == nil {
		return os.ReadFile(filepath)
	}
	return nil, errors.New("file not found")
}

// CVETimingAttack - go-cve-timing-attack
func CVETimingAttack() bool {
	// Safe: constant-time comparison
	if subtle.ConstantTimeCompare([]byte(providedToken), []byte(expectedToken)) == 1 {
		return true
	}
	return false
}

// CVEOpenRedirect - go-cve-open-redirect
func CVEOpenRedirect(w http.ResponseWriter, r *http.Request) {
	// Safe: validate redirect URL is internal
	redirectURL := r.URL.Query().Get("next")
	if !isInternalURL(redirectURL) {
		redirectURL = "/home"
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func isInternalURL(url string) bool { return true }
