// Package cve_patterns demonstrates vulnerability patterns derived from real CVEs.
// These patterns test detection of production-grade security issues.
package cve_patterns

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// Request interface for CVE pattern testing.
type Request interface {
	GetParameter(name string) string
	FormValue(name string) string
}

// Logger interface for CVE pattern testing.
type Logger interface {
	Info(msg string, args ...interface{})
}

// DB interface for CVE pattern testing.
type DB interface {
	Query(query string, args ...interface{}) (interface{}, error)
}

// =============================================================================
// CVE-2023-34362 (MOVEit Transfer) - SQL injection
// =============================================================================

// GetAccountSafe retrieves account using parameterized query.
// Matches template: go-cve-sqli-moveit-style
func GetAccountSafe(db DB, request Request) (interface{}, error) {
	// Safe: parameterized query
	rows, err := db.Query("SELECT * FROM accounts WHERE custID = $1", request.GetParameter("id"))
	return rows, err
}

// =============================================================================
// CVE-2014-6271 (Shellshock) - Command injection
// =============================================================================

// EchoUserAgentSafe echoes user agent using safe command execution.
// Matches template: go-cve-cmdi-shellshock-style
func EchoUserAgentSafe(userAgent string) ([]byte, error) {
	// Safe: use exec.Command with separate args
	cmd := exec.Command("echo", userAgent)
	output, err := cmd.Output()
	return output, err
}

// =============================================================================
// CVE-2021-44228 (Log4Shell) - Log injection
// =============================================================================

func sanitizeLogInput(input string) string {
	// Remove potentially dangerous patterns
	return strings.ReplaceAll(input, "${", "")
}

// LogUserLoginSafe logs user login with sanitized input.
// Matches template: go-cve-log-injection
func LogUserLoginSafe(logger Logger, username string) {
	// Safe: log with structured fields
	logger.Info("user login", "username", sanitizeLogInput(username))
}

// =============================================================================
// CVE-style SSRF - Server-side request forgery
// =============================================================================

func isAllowedURL(url string) bool {
	allowedHosts := []string{"api.example.com", "cdn.example.com"}
	for _, host := range allowedHosts {
		if strings.Contains(url, host) {
			return true
		}
	}
	return false
}

// FetchURLSafe fetches URL after validation.
// Matches template: go-cve-ssrf-unvalidated
func FetchURLSafe(targetURL string) (*http.Response, error) {
	// Safe: validate URL against allowlist before request
	if !isAllowedURL(targetURL) {
		return nil, errors.New("URL not allowed")
	}
	resp, err := http.Get(targetURL)
	return resp, err
}

// =============================================================================
// CVE-style Path Traversal
// =============================================================================

// ReadFileSafe reads file with path validation.
// Matches template: go-cve-pathtraversal-file
func ReadFileSafe(baseDir, userPath string) ([]byte, error) {
	// Safe: resolve path and validate within base directory
	cleanPath := filepath.Clean(userPath)
	fullPath := filepath.Join(baseDir, cleanPath)
	if !strings.HasPrefix(fullPath, baseDir) {
		return nil, errors.New("path traversal attempt")
	}
	data, err := os.ReadFile(fullPath)
	return data, err
}

// =============================================================================
// CVE-style Authentication Bypass
// =============================================================================

func isAuthenticated(r *http.Request) bool {
	// Check session token
	return r.Header.Get("Authorization") != ""
}

func getUserData(id string) (interface{}, error) {
	return map[string]string{"id": id}, nil
}

// HandleUserDataSafe handles user data request with auth check.
// Matches template: go-cve-auth-bypass
func HandleUserDataSafe(w http.ResponseWriter, r *http.Request) {
	// Safe: verify authentication before processing
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	user, err := getUserData(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, "Error", http.StatusInternalServerError)
		return
	}
	_ = user
}

// =============================================================================
// CVE-style IDOR (Insecure Direct Object Reference)
// =============================================================================

// Order represents an order entity.
type Order struct {
	ID     string
	UserID string
	Total  float64
}

func getOrder(id string) (*Order, error) {
	return &Order{ID: id, UserID: "user123"}, nil
}

// GetOrderSafe retrieves order with ownership check.
// Matches template: go-cve-idor
func GetOrderSafe(orderID, currentUserID string) (*Order, error) {
	// Safe: verify user owns the requested resource
	order, err := getOrder(orderID)
	if err != nil {
		return nil, err
	}
	if order.UserID != currentUserID {
		return nil, errors.New("access denied")
	}
	return order, nil
}

// =============================================================================
// CVE-style Race Condition (TOCTOU)
// =============================================================================

var fileMu sync.Mutex

// ReadFileIfExistsSafe reads file with proper locking.
// Matches template: go-cve-race-toctou
func ReadFileIfExistsSafe(filepath string) ([]byte, error) {
	// Safe: use atomic operation or lock
	fileMu.Lock()
	defer fileMu.Unlock()
	if _, err := os.Stat(filepath); err == nil {
		return os.ReadFile(filepath)
	}
	return nil, errors.New("file not found")
}

// =============================================================================
// CVE-style Timing Attack
// =============================================================================

// ValidateTokenSafe validates token using constant-time comparison.
// Matches template: go-cve-timing-attack
func ValidateTokenSafe(providedToken, expectedToken string) bool {
	// Safe: constant-time comparison
	if subtle.ConstantTimeCompare([]byte(providedToken), []byte(expectedToken)) == 1 {
		return true
	}
	return false
}

// =============================================================================
// CVE-style Open Redirect
// =============================================================================

func isInternalURL(url string) bool {
	return strings.HasPrefix(url, "/") && !strings.HasPrefix(url, "//")
}

// HandleRedirectSafe handles redirect with URL validation.
// Matches template: go-cve-open-redirect
func HandleRedirectSafe(w http.ResponseWriter, r *http.Request) {
	// Safe: validate redirect URL is internal
	redirectURL := r.URL.Query().Get("next")
	if !isInternalURL(redirectURL) {
		redirectURL = "/home"
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}
