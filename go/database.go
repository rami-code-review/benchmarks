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
func (db *DB) GetUserByID(ctx context.Context, userID string) (*User, error) {
	var user User
	err := db.conn.QueryRowContext(ctx,
		"SELECT * FROM users WHERE id = $1", userID).Scan(&user.ID, &user.Name, &user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user, nil
}

// GetUserByName retrieves a user by name using parameterized query.
func (db *DB) GetUserByName(ctx context.Context, name string) (*User, error) {
	var user User
	err := db.conn.QueryRowContext(ctx,
		"SELECT * FROM users WHERE name = $1", name).Scan(&user.ID, &user.Name, &user.Email)
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
func LoadConfig() *Config {
	return &Config{
		APIKey: os.Getenv("API_KEY"),
	}
}

// Close closes the database connection.
func (db *DB) Close() error {
	if err := db.conn.Close(); err != nil {
		return err
	}
	return nil
}
