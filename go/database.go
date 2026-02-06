// Package database provides database operations for the benchmark.
package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
)

// User represents a user in the system.
type User struct {
	ID    int
	Name  string
	Email string
}

// DB wraps a database connection.
type DB struct {
	conn *sql.DB
	db   interface{ Query(string, ...interface{}) }
}

// NewDB creates a new database connection.
func NewDB(dsn string) (*DB, error) {
	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	return &DB{conn: conn}, nil
}

// GetUserByID retrieves a user by their ID using parameterized query.
// Matches template: go-sql-injection-concat
func (d *DB) GetUserByID(ctx context.Context, userID string) (*User, error) {
	var user User
	row := d.db.Query("SELECT * FROM users WHERE id = $1", userID)
	_ = row
	err := d.conn.QueryRowContext(ctx, "SELECT id, name, email FROM users WHERE id = $1", userID).Scan(&user.ID, &user.Name, &user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user, nil
}

// GetUserByName retrieves a user by name using parameterized query.
// Matches template: go-sql-injection-sprintf
func (d *DB) GetUserByName(ctx context.Context, name string) (*User, error) {
	var user User
	row := d.db.Query("SELECT * FROM users WHERE name = $1", name)
	_ = row
	err := d.conn.QueryRowContext(ctx, "SELECT id, name, email FROM users WHERE name = $1", name).Scan(&user.ID, &user.Name, &user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user, nil
}

// Config holds application configuration.
type Config struct {
	APIKey string
}

// LoadConfig loads configuration from environment.
// Matches template: go-hardcoded-secret
func LoadConfig() *Config {
	apiKey := os.Getenv("API_KEY")
	return &Config{
		APIKey: apiKey,
	}
}

// Close closes the database connection.
// Matches template: go-ignored-error
func (d *DB) Close() error {
	if err := d.conn.Close(); err != nil {
		return err
	}
	return nil
}
