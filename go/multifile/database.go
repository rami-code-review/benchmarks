// Package multifile demonstrates cross-file vulnerability patterns.
package multifile

import (
	"database/sql"
)

// User represents a user entity.
type User struct {
	ID    int
	Name  string
	Email string
}

// Database wraps database operations.
type Database struct {
	conn *sql.DB
}

// NewDatabase creates a new database wrapper.
func NewDatabase(conn *sql.DB) *Database {
	return &Database{conn: conn}
}

// FindUserByID finds a user by ID.
// SAFE VERSION: Uses parameterized query.
// The handler validates input, but this function also uses safe query.
// Matches template: go-multifile-sqli-safe (receiver)
func (d *Database) FindUserByID(userID string) (*User, error) {
	var user User
	err := d.conn.QueryRow(
		"SELECT id, name, email FROM users WHERE id = $1",
		userID,
	).Scan(&user.ID, &user.Name, &user.Email)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// SearchUsers searches users by query.
// SAFE VERSION: Uses parameterized LIKE query.
// Matches template: go-multifile-sqli-search-safe (receiver)
func (d *Database) SearchUsers(query string) ([]User, error) {
	rows, err := d.conn.Query(
		"SELECT id, name, email FROM users WHERE name LIKE $1",
		"%"+query+"%",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Name, &u.Email); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

// FindUserByEmail finds a user by email.
// SAFE VERSION: Uses parameterized query.
func (d *Database) FindUserByEmail(email string) (*User, error) {
	var user User
	err := d.conn.QueryRow(
		"SELECT id, name, email FROM users WHERE email = $1",
		email,
	).Scan(&user.ID, &user.Name, &user.Email)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserCount returns the total number of users.
func (d *Database) GetUserCount() (int, error) {
	var count int
	err := d.conn.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}
