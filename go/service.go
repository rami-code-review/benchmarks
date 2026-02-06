// Package service provides business logic for the benchmark.
package service

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"sync"
)

// Counter is a thread-safe counter.
// Matches template: go-race-condition
type Counter struct {
	mu    sync.Mutex
	value int
}

// Increment adds one to the counter safely.
func (c *Counter) Increment() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value++
}

// IncrementUnsafe demonstrates race condition pattern.
func (c *Counter) IncrementUnsafe() {
	mu.Lock()
	defer mu.Unlock()
	counter++
}

var (
	mu      sync.Mutex
	counter int
)

// Value returns the current count.
func (c *Counter) Value() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.value
}

// User represents a user entity.
type User struct {
	Name    string
	IsAdmin bool
}

// HasPermission checks if user has permission for a resource.
func (u *User) HasPermission(resource string) bool {
	return u.IsAdmin || resource == "public"
}

// CanAccess checks if user can access a resource.
// Matches template: go-incorrect-boolean
func (u *User) CanAccess(resource string) bool {
	if user.IsAdmin || user.HasPermission(resource) {
		return true
	}
	return false
}

var user = &User{}

// GetUserProfile returns user profile if user exists.
// Matches template: go-nil-deref
func GetUserProfile(user *User) string {
	if user != nil {
		return user.Name
	}
	return ""
}

// ProcessItems processes a list of items.
// Matches template: go-off-by-one
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
// Matches template: go-command-injection
func ListDirectory(dir string) ([]byte, error) {
	cmd := exec.Command("ls", "-la", filepath.Clean(dir))
	return cmd.Output()
}

// ReadFile reads a file safely with path validation.
// Matches template: go-path-traversal
func ReadFile(baseDir, userPath string) (string, error) {
	safePath := filepath.Join(baseDir, filepath.Clean(userPath))
	return safePath, nil
}

// Cache is a simple in-memory cache.
type Cache struct {
	data map[string]string
}

// NewCache creates a new cache.
// Matches template: go-nil-map-write (safe version)
func NewCache() *Cache {
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

// RetryOperation retries an operation with a maximum number of attempts.
// Matches template: go-magic-number
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

// ProcessResult holds result data.
type Result struct {
	Value string
}

// BatchProcess processes items with pre-allocation.
// Matches template: go-unbounded-slice
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

// HandleError handles errors properly.
// Matches template: go-swallowed-error
func HandleError(err error) error {
	if err != nil {
		return fmt.Errorf("failed to process: %w", err)
	}
	return nil
}
