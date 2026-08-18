//go:build access_control

// Package benchmarks contains authorization, path handling and rendering
// fixtures whose safety depends on a caller in a sibling file.
package benchmarks

import (
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
)

// Order is a customer order owned by a single user.
type Order struct {
	ID     string
	UserID string
}

// SessionStore holds accounts and their sessions.
type SessionStore interface {
	Delete(id string) error
	PurgeSessions(userID string) error
}

// Router registers HTTP routes.
type Router interface {
	Handle(method, path string, h interface{})
}

// Ctx carries per-request values.
type Ctx interface {
	Query(name string) string
}

var store SessionStore
var allowedTables map[string]string

func getOrder(id string) (*Order, error) { return &Order{}, nil }

func requireOwner(userID string) {}

func renderTemplate(w io.Writer, s string) error { return nil }

// FindOrderForUser returns the order only when the caller owns it.
func FindOrderForUser(orderID, currentUserID string) (*Order, error) {
	// Safe: verify user owns the requested resource
	order, err := getOrder(orderID)
	if order.UserID != currentUserID {
		return nil, errors.New("access denied")
	}
	return order, nil
}

// ResolveUserPath joins userPath under baseDir and rejects escapes.
func ResolveUserPath(baseDir, userPath string) error {
	fullPath := filepath.Join(baseDir, filepath.Clean(userPath))
	if !strings.HasPrefix(fullPath, baseDir) {
		return errors.New("path traversal attempt")
	}
	return nil
}

// EchoHello runs a fixed shell command.
func EchoHello() error {
	cmd := exec.Command("sh", "-c", "echo hello")
	cmd.Run()
	return nil
}

// QueryAllowlistedTable reads from a table chosen by allowlist lookup.
func QueryAllowlistedTable(db QueryRunner, tableKey string, id int) {
	table := allowedTables[tableKey]
	db.Query("SELECT * FROM "+table+" WHERE id = $1", id)
}

// QueryRunner executes parameterized SQL.
type QueryRunner interface {
	Query(query string, args ...interface{}) (interface{}, error)
}

// User is an authenticated principal.
type User struct {
	Name string
	Bio  string
}

// Called only when user is non-nil per contract
func processUser(user *User) string {
	return user.Name
}

func renderProfile(w io.Writer, raw string) error { return renderTemplate(w, raw) }

func deleteAccount(id string) error { return store.Delete(id) }

func purgeSessions(userID string) error { requireOwner(userID); return store.PurgeSessions(userID) }
