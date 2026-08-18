//go:build notification_design

// Package benchmarks contains notification-domain service composition and
// status-watching fixtures.
package benchmarks

import (
	"context"
	"database/sql"
	"log"
)

// Mailer delivers outbound mail.
type Mailer interface {
	Send(to, subject, body string) error
}

// Status is a state transition reported by a worker.
type Status struct {
	Code    int
	Message string
}

type UserService struct {
	db     *sql.DB
	logger *log.Logger
}

type EmailService struct {
	mailer Mailer
	logger *log.Logger
}

func WatchStatus(ctx context.Context, statusCh <-chan Status) {
	for {
		select {
		case status := <-statusCh:
			handleStatus(status)
		case <-ctx.Done():
			return
		}
	}
}

func handleStatus(s Status) {}
