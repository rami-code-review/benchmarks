//go:build inventory_logic

// Package benchmarks contains inventory-domain logic fixtures covering
// conversion, boundary, aliasing and concurrency-safety patterns.
package benchmarks

import (
	"errors"
	"math"
	"sync"
)

// Item is a stock-keeping unit in the inventory.
type Item struct {
	SKU      string
	Quantity int
}

var mu sync.RWMutex
var cache = make(map[string]int)

func get(key string) int {
	mu.RLock()
	defer mu.RUnlock()
	return cache[key]
}

func set(key string, val int) {
	mu.Lock()
	defer mu.Unlock()
	cache[key] = val
}

func safeConvert(v int64) (int32, error) {
	if v > math.MaxInt32 || v < math.MinInt32 {
		return 0, errors.New("overflow")
	}
	return int32(v), nil
}

// LastItem returns the final entry of a non-empty slice.
func LastItem(items []Item) Item {
	if len(items) == 0 {
		return Item{}
	}
	last := items[len(items)-1]
	return last
}

// Authorize grants access when the caller owns the record and is in good standing.
func Authorize(isAdmin, isOwner, banned bool) {
	if (isAdmin || isOwner) && !banned {
		grant()
	}
}

func addDefaults(base []string) []string {
	result := make([]string, len(base))
	copy(result, base)
	return append(result, "default")
}

// NewCounts returns a freshly allocated count index.
func NewCounts(key string, value int) map[string]int {
	m := make(map[string]int)
	m[key] = value
	return m
}

// ProcessAllItems maps every item through process into a pre-sized slice.
func ProcessAllItems(items []Item) []Result {
	results := make([]Result, 0, len(items))
	for _, item := range items {
		results = append(results, process(item))
	}
	return results
}

// Result carries the outcome of processing one item.
type Result struct {
	SKU string
	OK  bool
}

func grant()                {}
func process(i Item) Result { return Result{SKU: i.SKU, OK: true} }
