package benchmarks

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/prometheus/client_golang/prometheus"
)

// =============================================================================
// DESIGN ISSUES - LLM-ADVANTAGE PATTERNS
// These patterns require understanding code structure and architectural intent.
// SAST tools score ~0% on these patterns.
// =============================================================================

// -----------------------------------------------------------------------------
// go-design-god-struct-hard: God struct with too many responsibilities
// -----------------------------------------------------------------------------

// SAFE: Single responsibility - separate services
type UserService struct {
	repo UserRepository
}

type OrderService struct {
	repo OrderRepository
}

type EmailService struct {
	client EmailClient
}

// VULNERABLE: God struct doing too much
type AppService struct {
	db           *sql.DB
	cache        *redis.Client
	emailClient  EmailClient
	userRepo     UserRepository
	orderRepo    OrderRepository
	paymentRepo  PaymentRepository
	logger       *log.Logger
	metrics      *prometheus.Registry
	config       *Config
}

// -----------------------------------------------------------------------------
// go-design-missing-abstraction-medium: Copy-paste code that should be a function
// -----------------------------------------------------------------------------

// SAFE: Extracted validation function
func validateAndLogUser(u User) error {
	if u.Email == "" {
		return errors.New("email required")
	}
	log.Printf("Processing user: %s", u.Email)
	return nil
}

func ProcessUserASafe(u User) error {
	if err := validateAndLogUser(u); err != nil {
		return err
	}
	// ... process A
	return nil
}

func ProcessUserBSafe(u User) error {
	if err := validateAndLogUser(u); err != nil {
		return err
	}
	// ... process B
	return nil
}

// VULNERABLE: Duplicated validation logic
func ProcessUserABad(u User) error {
	if u.Email == "" {
		return errors.New("email required")
	}
	log.Printf("Processing user: %s", u.Email)
	// ... process A
	return nil
}

func ProcessUserBBad(u User) error {
	if u.Email == "" {
		return errors.New("email required")
	}
	log.Printf("Processing user: %s", u.Email)
	// ... process B
	return nil
}

// -----------------------------------------------------------------------------
// go-design-wrong-pattern-hard: Polling when should use events/channels
// -----------------------------------------------------------------------------

// SAFE: Event-driven using channels
func WatchStatusSafe(ctx context.Context, statusCh <-chan Status) {
	for {
		select {
		case status := <-statusCh:
			handleStatus(status)
		case <-ctx.Done():
			return
		}
	}
}

// VULNERABLE: Busy polling - wasteful and has latency
func WatchStatusBad(ctx context.Context) {
	for {
		status := checkStatus()
		handleStatus(status)
		time.Sleep(100 * time.Millisecond)
	}
}

// -----------------------------------------------------------------------------
// go-design-wrong-layer-hard: Business logic in wrong layer
// -----------------------------------------------------------------------------

// SAFE: Validation in service layer where it belongs
type UserServiceSafe struct {
	repo *UserRepoSafe
}

func (s *UserServiceSafe) CreateUser(u User) error {
	if u.Age < 18 {
		return errors.New("user must be 18 or older")
	}
	return s.repo.Insert(u)
}

type UserRepoSafe struct {
	db *sql.DB
}

func (r *UserRepoSafe) Insert(u User) error {
	_, err := r.db.Exec("INSERT INTO users (name, age) VALUES ($1, $2)", u.Name, u.Age)
	return err
}

// VULNERABLE: Business logic in repository layer
type UserRepoBad struct {
	db *sql.DB
}

func (r *UserRepoBad) Insert(u User) error {
	// Business logic doesn't belong in repository!
	if u.Age < 18 {
		return errors.New("user must be 18 or older")
	}
	_, err := r.db.Exec("INSERT INTO users (name, age) VALUES ($1, $2)", u.Name, u.Age)
	return err
}

// Helper types
type User struct {
	ID    string
	Name  string
	Email string
	Age   int
}

type Status struct {
	Code    int
	Message string
}

type Config struct{}

type UserRepository interface {
	FindByID(id string) (*User, error)
	Insert(u User) error
}

type OrderRepository interface{}
type PaymentRepository interface{}
type EmailClient interface{}

func handleStatus(s Status)  {}
func checkStatus() Status    { return Status{} }
