//go:build framework_http

// Package benchmarks contains HTTP handler and outbound-request fixtures.
// Its Handler and User stubs reuse names declared elsewhere in the package,
// so it carries a dedicated build tag.
package benchmarks

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// User is a persisted account record.
type User struct {
	ID    string
	Name  string
	Email string
}

// UserService loads users from the backing store.
type UserService struct {
	client *http.Client
}

// FindByID loads the user with the given id.
func (s *UserService) FindByID(ctx context.Context, id string) (*User, error) {
	return &User{ID: id}, nil
}

// Handler serves the account HTTP API.
type Handler struct {
	userService *UserService
}

var userID string

// GetUser writes the requested user as JSON.
func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, err := h.userService.FindByID(ctx, userID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(user)
}

// RunLongOperation runs the operation under a bounded deadline.
func RunLongOperation(parentCtx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
	defer cancel()
	result, err := longOperation(ctx)
	return result, err
}

// DownloadBody fetches url and returns the response body.
func DownloadBody(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_ = body
	return nil
}

// MirrorBody fetches url and discards the response body.
func MirrorBody(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_ = body
	return nil
}

func longOperation(ctx context.Context) (string, error) { return "", nil }
