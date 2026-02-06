// Package multifile demonstrates cross-file vulnerability patterns.
package multifile

import (
	"errors"
	"os/exec"
)

// CommandExecutor safely executes predefined commands.
type CommandExecutor struct {
	allowedCommands map[string][]string
}

// NewCommandExecutor creates a command executor with allowlist.
func NewCommandExecutor() *CommandExecutor {
	return &CommandExecutor{
		allowedCommands: map[string][]string{
			"list":   {"ls", "-la"},
			"status": {"git", "status"},
			"date":   {"date"},
			"uptime": {"uptime"},
		},
	}
}

// RunAllowedCommand executes a command from the allowlist.
// SAFE VERSION: Only runs predefined commands, not user input.
// Matches template: go-multifile-cmdi-safe (receiver)
func (e *CommandExecutor) RunAllowedCommand(cmdKey string) ([]byte, error) {
	args, ok := e.allowedCommands[cmdKey]
	if !ok {
		return nil, errors.New("command not allowed")
	}

	if len(args) == 0 {
		return nil, errors.New("invalid command")
	}

	cmd := exec.Command(args[0], args[1:]...)
	return cmd.Output()
}

// RunCommand executes an arbitrary command.
// This is a DANGEROUS function that should not be exposed to user input.
// It exists for internal/admin use only.
func (e *CommandExecutor) RunCommand(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.Output()
}

// ValidateCommandKey checks if a command key is in the allowlist.
func (e *CommandExecutor) ValidateCommandKey(key string) bool {
	_, ok := e.allowedCommands[key]
	return ok
}
