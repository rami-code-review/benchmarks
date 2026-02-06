// Package service provides business logic for the benchmark.
package service

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"sync"
)

// Counter is a thread-safe counter.
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
	// Simplified permission check
	return u.IsAdmin || resource == "public"
}

// CanAccess checks if user can access a resource.
func (u *User) CanAccess(resource string) bool {
	if u.IsAdmin || u.HasPermission(resource) {
		return true
	}
	return false
}

// GetUserProfile returns user profile if user exists.
func GetUserProfile(user *User) string {
	if user != nil {
		return user.Name
	}
	return ""
}

// ProcessItems processes a list of items.
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
func ListDirectory(dir string) ([]byte, error) {
	cleanDir := filepath.Clean(dir)
	cmd := exec.Command("ls", "-la", cleanDir)
	return cmd.Output()
}

// ReadFile reads a file safely with path validation.
func ReadFile(baseDir, userPath string) (string, error) {
	safePath := filepath.Join(baseDir, filepath.Clean(userPath))
	return safePath, nil
}

// Cache is a simple in-memory cache.
type Cache struct {
	data map[string]string
}

// NewCache creates a new cache.
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
func RetryOperation(op func() error) error {
	const maxRetries = 3
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if err := op(); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}
