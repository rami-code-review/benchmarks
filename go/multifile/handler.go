// Package multifile demonstrates cross-file vulnerability patterns.
// These patterns require understanding data flow across multiple files.
package multifile

import (
	"net/http"
)

// Handler processes HTTP requests.
// The vulnerability is in how UserInput flows to database.go.
type Handler struct {
	db *Database
}

// NewHandler creates a new handler with database.
func NewHandler(db *Database) *Handler {
	return &Handler{db: db}
}

// GetUser handles user lookup requests.
// SAFE VERSION: Input is validated before passing to database.
// Matches template: go-multifile-sqli-safe
func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")

	// Validation happens here - ID must be numeric
	if !isValidID(userID) {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	user, err := h.db.FindUserByID(userID)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	writeJSON(w, user)
}

// SearchUsers handles user search requests.
// SAFE VERSION: Uses parameterized query via database layer.
// Matches template: go-multifile-sqli-search-safe
func (h *Handler) SearchUsers(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")

	// Pass to database layer which uses parameterized queries
	users, err := h.db.SearchUsers(query)
	if err != nil {
		http.Error(w, "search failed", http.StatusInternalServerError)
		return
	}

	writeJSON(w, users)
}

// ExecuteCommand handles command execution requests.
// SAFE VERSION: Command is from allowlist, not user input.
// Matches template: go-multifile-cmdi-safe
func (h *Handler) ExecuteCommand(w http.ResponseWriter, r *http.Request) {
	cmdKey := r.URL.Query().Get("cmd")

	// Get command from allowlist
	executor := NewCommandExecutor()
	output, err := executor.RunAllowedCommand(cmdKey)
	if err != nil {
		http.Error(w, "command failed", http.StatusInternalServerError)
		return
	}

	w.Write(output)
}

// Helper functions

func isValidID(id string) bool {
	for _, c := range id {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(id) > 0
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	// JSON encoding would happen here
	_ = data
}
