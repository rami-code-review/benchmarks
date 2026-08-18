//go:build concurrency_pipeline

// Package benchmarks contains a fan-out worker pipeline used for concurrency
// benchmark fixtures. Its stub types reuse names declared in async_patterns.go,
// so it carries a dedicated build tag.
package benchmarks

import (
	"context"
	"sync"

	"golang.org/x/sync/errgroup"
)

// Item is a unit of pipeline input.
type Item struct {
	ID   string
	Body []byte
}

// Result is the outcome of processing a single Item.
type Result struct {
	ItemID string
	Value  int
}

// Job is a queued unit of background work.
type Job struct {
	ID      string
	Attempt int
}

// Client is a lazily initialised outbound client.
type Client struct {
	endpoint string
}

// Cache is a concurrency-safe in-memory map.
type Cache struct {
	mu   sync.Mutex
	data map[string]interface{}
}

var (
	instance *Client
	once     sync.Once
)

func GetClient() *Client {
	once.Do(func() {
		instance = &Client{}
	})
	return instance
}

// Set stores a value under key.
func (c *Cache) Set(key string, val interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = val
}

// ProcessAll fans each item out to its own goroutine and waits for all of them.
func ProcessAll(items []Item) {
	var wg sync.WaitGroup
	for _, item := range items {
		wg.Add(1)
		go func(it Item) {
			defer wg.Done()
			process(it)
		}(item)
	}
	wg.Wait()
}

// Process collects a result for every item over a buffered channel.
func Process(items []Item) []Result {
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

// StartWorker drains jobs until the context is cancelled.
func StartWorker(ctx context.Context, jobs <-chan Job) {
	go func() {
		for {
			select {
			case job := <-jobs:
				process(job)
			case <-ctx.Done():
				return // Clean exit on cancellation
			}
		}
	}()
}

// AwaitValue returns the first value on ch, or the context error.
func AwaitValue(ctx context.Context, ch <-chan string) (string, error) {
	select {
	case result := <-ch:
		return result, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// FetchAll fetches every url concurrently and fails fast on the first error.
func FetchAll(ctx context.Context, urls []string) error {
	g, ctx := errgroup.WithContext(ctx)
	for _, url := range urls {
		url := url
		g.Go(func() error {
			return fetch(ctx, url)
		})
	}
	return g.Wait()
}

// DispatchItems hands each item to a goroutine by value.
func DispatchItems(items []Item) {
	for _, item := range items {
		go func(it Item) {
			process(it)
		}(item)
	}
}

// TransformAll writes each transformed value back into results by index.
func TransformAll(data []string, results []string) {
	for i, v := range data {
		go func(idx int, val string) {
			results[idx] = transform(val)
		}(i, v)
	}
}

func process(v interface{})                       {}
func processItem(i Item) Result                   { return Result{ItemID: i.ID} }
func transform(s string) string                   { return s }
func fetch(ctx context.Context, url string) error { return nil }
