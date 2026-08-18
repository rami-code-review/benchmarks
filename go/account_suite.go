//go:build account_suite

// Package benchmarks contains the account domain exercised by the account
// test suite: user lifecycle, arithmetic helpers and expiring tokens.
package benchmarks

import (
	"errors"
	"time"
)

// ErrNotFound is returned when an account does not exist.
var ErrNotFound = errors.New("not found")

// User is a registered account.
type User struct {
	ID    string
	Email string
}

// Token is a bearer credential with a fixed lifetime.
type Token struct {
	Value     string
	CreatedAt time.Time
	TTL       time.Duration
}

var accounts = map[string]*User{}

// CreateUser registers a new account for the given email.
func CreateUser(email string) (*User, error) {
	if email == "" {
		return nil, errors.New("email required")
	}
	u := &User{ID: "user-" + email, Email: email}
	accounts[u.ID] = u
	return u, nil
}

// GetUser loads the account with the given id.
func GetUser(id string) (*User, error) {
	u, ok := accounts[id]
	if !ok {
		return nil, ErrNotFound
	}
	return u, nil
}

// DeleteUser removes the account with the given id.
func DeleteUser(id string) error {
	if _, ok := accounts[id]; !ok {
		return ErrNotFound
	}
	delete(accounts, id)
	return nil
}

// Add returns the sum of a and b.
func Add(a, b int) int { return a + b }

// NewToken mints a token created at the given instant with the given lifetime.
func NewToken(value string, created time.Time, ttl time.Duration) *Token {
	return &Token{Value: value, CreatedAt: created, TTL: ttl}
}

// IsExpiredAt reports whether the token has expired by the given instant.
func (t *Token) IsExpiredAt(at time.Time) bool {
	return at.After(t.CreatedAt.Add(t.TTL))
}
