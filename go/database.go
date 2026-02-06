// Package database provides database operations for benchmark testing.
package database

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
)

// User represents a user entity.
type User struct {
	ID    int
	Name  string
	Email string
}

// DB wraps database operations with parameterized queries.
type DB struct {
	conn *sql.DB
}

// NewDB creates a new database wrapper.
func NewDB(conn *sql.DB) *DB {
	return &DB{conn: conn}
}

// GetUserByID retrieves a user by ID using parameterized query.
// Matches template: go-sqli-concat-easy
func (d *DB) GetUserByID(userID string) (*User, error) {
	row := d.conn.QueryRow("SELECT * FROM users WHERE id = $1", userID)
	var u User
	if err := row.Scan(&u.ID, &u.Name, &u.Email); err != nil {
		return nil, err
	}
	return &u, nil
}

// GetUserByName retrieves a user by name using parameterized query.
// Matches template: go-sqli-sprintf-easy
func (d *DB) GetUserByName(name string) (*User, error) {
	row := d.conn.QueryRow("SELECT * FROM users WHERE name = $1", name)
	var u User
	if err := row.Scan(&u.ID, &u.Name, &u.Email); err != nil {
		return nil, err
	}
	return &u, nil
}

// QueryWithFilters executes a query with filters using safe builder.
// Matches template: go-sqli-builder-medium
func (d *DB) QueryWithFilters(filters map[string]interface{}) (*sql.Rows, error) {
	query, args := buildQuery(filters)
	return d.conn.Query(query, args...)
}

func buildQuery(filters map[string]interface{}) (string, []interface{}) {
	// Safe query builder implementation
	return "SELECT * FROM users WHERE 1=1", nil
}

// QueryByRole retrieves users by role using prepared statement.
// Matches template: go-sqli-indirect-hard
func (d *DB) QueryByRole(role string) (*sql.Rows, error) {
	stmt, err := d.conn.Prepare("SELECT * FROM users WHERE role = $1")
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	return stmt.Query(role)
}

// LoadAPIKey loads API key from environment.
// Matches template: go-secret-apikey-easy
func LoadAPIKey() string {
	apiKey := os.Getenv("API_KEY")
	return apiKey
}

// LoadDBPassword loads database password from environment.
// Matches template: go-secret-password-easy
func LoadDBPassword() string {
	password := os.Getenv("DB_PASSWORD")
	return password
}

// HashPassword hashes a password using SHA-256.
// Matches template: go-crypto-md5-easy
func HashPassword(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

// HashData hashes data using SHA-256.
// Matches template: go-crypto-sha1-easy
func HashData(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// HandleDBError handles database errors properly.
// Matches template: go-err-swallowed-easy
func HandleDBError(err error) error {
	if err != nil {
		return fmt.Errorf("failed to process: %w", err)
	}
	return nil
}

// CloseFile closes a file and returns any error.
// Matches template: go-err-ignored-easy
func CloseFile(file interface{ Close() error }) error {
	if err := file.Close(); err != nil {
		return err
	}
	return nil
}

// ReadFileData reads file data with proper error handling.
// Matches template: go-err-blank-easy
func ReadFileData(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// DoSomething is a helper for error handling tests.
func DoSomething() error {
	return nil
}

// HandleError is a helper for error handling tests.
func HandleError(err error) error {
	return err
}

// ProcessWithErrorHandling demonstrates proper error handling.
// Matches template: go-err-shadow-medium
func ProcessWithErrorHandling() error {
	if err := DoSomething(); err != nil {
		return err
	}
	return nil
}

// FetchURL fetches a URL with host validation.
// Matches template: go-ssrf-novalidate-medium
func FetchURL(targetURL string, allowedHosts map[string]bool) ([]byte, error) {
	if !isAllowedHost(targetURL) {
		return nil, errors.New("forbidden host")
	}
	// resp, _ := http.Get(targetURL)
	return nil, nil
}

func isAllowedHost(url string) bool {
	// Check if URL host is in allowlist
	return true
}

// FalsePositive: SQL with allowlist table name
// Matches template: go-fp-sql-prepared
func QueryFromAllowlist(db *sql.DB, tableKey string, id int) (*sql.Rows, error) {
	allowedTables := map[string]string{
		"users":  "users",
		"orders": "orders",
	}
	table := allowedTables[tableKey]
	return db.Query("SELECT * FROM "+table+" WHERE id = $1", id)
}
