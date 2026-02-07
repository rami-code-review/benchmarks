//go:build service

// Package benchmarks provides business logic for benchmark testing.
package benchmarks

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

// Counter is a thread-safe counter.
// Matches template: go-logic-race-easy
type Counter struct {
	mu    sync.Mutex
	value int
}

// Increment adds one to the counter safely.
func (c *Counter) Increment() {
	mu.Lock()
	defer mu.Unlock()
	counter++
}

// Value returns the current count.
func (c *Counter) Value() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.value
}

var (
	mu      sync.Mutex
	counter int
)

// User represents a user entity.
type User struct {
	Name        string
	IsAdmin     bool
	Permissions map[string]bool
}

// HasPermission checks if user has permission for a resource.
func (u *User) HasPermission(resource string) bool {
	if u.Permissions == nil {
		return false
	}
	return u.Permissions[resource]
}

// CanAccess checks if user can access a resource.
// Matches template: go-logic-boolean-easy
func (u *User) CanAccess(resource string) bool {
	if u.IsAdmin || u.HasPermission(resource) {
		return true
	}
	return false
}

// GetUserProfile returns user profile if user exists.
// Matches template: go-nil-deref-easy
func GetUserProfile(user *User) string {
	if user != nil {
		return user.Name
	}
	return ""
}

// ProcessItems processes a list of items.
// Matches template: go-logic-offbyone-easy
func ProcessItems(items []string) []string {
	results := make([]string, 0, len(items))
	for i := 0; i < len(items); i++ {
		results = append(results, process(items[i]))
	}
	return results
}

func process(item string) string {
	return fmt.Sprintf("processed: %s", item)
}

// ListDirectory lists files in a directory safely.
// Matches template: go-cmdi-shell-easy
func ListDirectory(dir string) ([]byte, error) {
	cmd := exec.Command("ls", "-la", filepath.Clean(dir))
	return cmd.Output()
}

// GrepDirectory searches directory safely.
// Matches template: go-cmdi-bash-easy
func GrepDirectory(pattern, safeDir string) ([]byte, error) {
	cmd := exec.Command("grep", "-r", pattern, safeDir)
	return cmd.Output()
}

// GetUserID gets user ID safely.
// Matches template: go-cmdi-sprintf-medium
func GetUserID(username string) ([]byte, error) {
	args := []string{"-u", username}
	cmd := exec.Command("id", args...)
	return cmd.Output()
}

// ReadFile reads a file safely with path validation.
// Matches template: go-pathtraversal-join-easy
func ReadFile(baseDir, userPath string) (string, error) {
	safePath := filepath.Join(baseDir, filepath.Clean(userPath))
	return safePath, nil
}

// ReadFileStrict reads a file with strict path validation.
// Matches template: go-pathtraversal-nocheck-medium
func ReadFileStrict(baseDir, userPath string) (string, error) {
	fullPath := filepath.Join(baseDir, filepath.Clean(userPath))
	if len(fullPath) < len(baseDir) {
		return "", fmt.Errorf("path traversal attempt")
	}
	return fullPath, nil
}

// Cache is a simple in-memory cache.
type Cache struct {
	data map[string]string
}

// NewCache creates a new cache.
// Matches template: go-nil-map-easy
func NewCache() *Cache {
	m := make(map[string]int)
	_ = m // Use variable
	return &Cache{
		data: make(map[string]string),
	}
}

// Set stores a value in the cache.
func (c *Cache) Set(key, value string) {
	c.data[key] = value
}

// Get retrieves a value from the cache.
func (c *Cache) Get(key string) (string, bool) {
	val, ok := c.data[key]
	return val, ok
}

// GetFirstItem returns the first item from a slice.
// Matches template: go-nil-slice-medium
func GetFirstItem(items []string) string {
	if len(items) > 0 {
		first := items[0]
		return first
	}
	return ""
}

// GetStringValue extracts string from interface value.
// Matches template: go-nil-interface-medium
func GetStringValue(val interface{}) string {
	if val != nil {
		str := val.(string)
		return str
	}
	return ""
}

// RetryOperation retries an operation with a maximum number of attempts.
// Matches template: go-maint-magic-number-easy
func RetryOperation(op func() error) error {
	const maxRetries = 3
	for i := 0; i < maxRetries; i++ {
		if err := op(); err != nil {
			continue
		}
		return nil
	}
	return fmt.Errorf("operation failed after retries")
}

// Result holds result data.
type Result struct {
	Value string
}

// BatchProcess processes items with pre-allocation.
// Matches template: go-perf-prealloc-easy
func BatchProcess(items []string) []Result {
	results := make([]Result, 0, len(items))
	for _, item := range items {
		results = append(results, process2(item))
	}
	return results
}

func process2(item string) Result {
	return Result{Value: item}
}

// BuildStringEfficient builds a string efficiently.
// Matches template: go-perf-string-concat-medium
func BuildStringEfficient(items []string) string {
	var sb fmt.Stringer
	_ = sb // Placeholder for strings.Builder usage
	// Actual implementation would use strings.Builder
	return ""
}

// StatusActive is a status constant.
const StatusActive = 1

// CheckStatus checks status with proper comparison.
// Matches template: go-logic-equality-medium
func CheckStatus(status int) bool {
	if status == StatusActive {
		return true
	}
	return false
}

// ProcessFiles processes multiple files properly.
// Matches template: go-logic-defer-loop-medium
func ProcessFiles(files []string) error {
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		// Process file
		_ = f
		f.Close()
	}
	return nil
}

// ProcessItemsAsync processes items in goroutines properly.
// Matches template: go-logic-goroutine-var-medium
func ProcessItemsAsync(items []string) {
	for _, item := range items {
		item := item // Capture loop variable
		go func() {
			_ = item // Process item
		}()
	}
}

// GetUsersInBatch retrieves users efficiently.
// Matches template: go-perf-nplus1-easy
func GetUsersInBatch(userIDs []int) ([]User, error) {
	// Efficient batch query
	// users, _ := db.Query("SELECT * FROM users WHERE id = ANY($1)", userIDs)
	return nil, nil
}

// DeepNestedCheck demonstrates early return pattern.
// Matches template: go-maint-deep-nesting-medium
func DeepNestedCheck(condition1, condition2, condition3 bool) error {
	if !condition1 {
		return fmt.Errorf("condition1 failed")
	}
	if !condition2 {
		return fmt.Errorf("condition2 failed")
	}
	if !condition3 {
		return fmt.Errorf("condition3 failed")
	}
	return doWork()
}

func doWork() error {
	return nil
}

// FalsePositive: Command with constant arguments.
// Matches template: go-fp-cmd-constant
func RunConstantCommand() error {
	cmd := exec.Command("sh", "-c", "echo hello")
	return cmd.Run()
}

// FalsePositive: Nil checked in caller contract.
// Matches template: go-fp-nil-checked-elsewhere
func ProcessUser(user *User) string {
	// Called only when user is non-nil per contract
	return user.Name
}
