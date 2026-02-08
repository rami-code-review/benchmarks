package benchmarks

import (
	"context"
	"io"
	"net/http"
	"sync"
)

// =============================================================================
// ASYNC/CONCURRENCY ISSUES - LLM-ADVANTAGE PATTERNS
// These patterns require understanding execution flow and timing.
// SAST tools score ~5% on these patterns.
// =============================================================================

// -----------------------------------------------------------------------------
// go-goroutine-leak-medium: Goroutine leak - no cancellation
// -----------------------------------------------------------------------------

type Job struct {
	ID   string
	Data []byte
}

// SAFE: Goroutine respects context cancellation
func StartWorkerSafe(ctx context.Context, jobs <-chan Job) {
	go func() {
		for {
			select {
			case job := <-jobs:
				processJob(job)
			case <-ctx.Done():
				return // Clean exit on cancellation
			}
		}
	}()
}

// VULNERABLE: Goroutine never exits if channel never closes
func StartWorkerBad(jobs <-chan Job) {
	go func() {
		for job := range jobs {
			processJob(job)
		}
		// Goroutine never exits if channel never closes!
	}()
}

// -----------------------------------------------------------------------------
// go-channel-deadlock-medium: Potential channel deadlock
// -----------------------------------------------------------------------------

type Item struct {
	ID string
}

type Result struct {
	ItemID string
	Value  int
}

// SAFE: Buffered channel prevents deadlock
func ProcessSafe(items []Item) []Result {
	results := make(chan Result, len(items)) // Buffered

	for _, item := range items {
		go func(it Item) {
			results <- processItem(it)
		}(item)
	}

	var out []Result
	for range items {
		out = append(out, <-results)
	}
	return out
}

// VULNERABLE: Unbuffered channel - deadlock risk
func ProcessBad(items []Item) []Result {
	results := make(chan Result) // Unbuffered - deadlock risk!

	for _, item := range items {
		go func(it Item) {
			results <- processItem(it) // Blocks until read
		}(item)
	}

	// If any goroutine panics before all writes, this blocks forever
	var out []Result
	for range items {
		out = append(out, <-results)
	}
	return out
}

// -----------------------------------------------------------------------------
// go-mutex-copy-hard: Mutex copied - lock state lost
// -----------------------------------------------------------------------------

// SAFE: Pointer receiver preserves mutex state
type SafeCounterGood struct {
	mu    sync.Mutex
	value int
}

func (c *SafeCounterGood) Inc() { // Pointer receiver
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value++
}

// VULNERABLE: Value receiver copies mutex - lock state lost
type SafeCounterBad struct {
	mu    sync.Mutex
	value int
}

func (c SafeCounterBad) Inc() { // Value receiver - mutex copied!
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value++
}

// -----------------------------------------------------------------------------
// go-context-not-propagated-medium: Context not propagated
// -----------------------------------------------------------------------------

type Handler struct {
	userService *UserServiceAsync
}

type UserServiceAsync struct{}

func (s *UserServiceAsync) FindByID(ctx context.Context, id string) (*User, error) {
	return &User{ID: id}, nil
}

// SAFE: Context propagated to downstream calls
func (h *Handler) GetUserSafe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.URL.Query().Get("id")
	user, err := h.userService.FindByID(ctx, userID) // Uses request context
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	_ = user
}

// VULNERABLE: Lost request context - cancellation won't propagate
func (h *Handler) GetUserBad(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	user, err := h.userService.FindByID(context.Background(), userID) // Lost request context!
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	_ = user
}

// -----------------------------------------------------------------------------
// go-http-body-not-closed-easy: HTTP response body not closed
// -----------------------------------------------------------------------------

// SAFE: Response body properly closed
func FetchDataSafe(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// VULNERABLE: Response body not closed - connection leak!
func FetchDataBad(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	// Missing defer resp.Body.Close() - connection leak!

	return io.ReadAll(resp.Body)
}

// Helper functions
func processJob(j Job)         {}
func processItem(i Item) Result { return Result{ItemID: i.ID} }
