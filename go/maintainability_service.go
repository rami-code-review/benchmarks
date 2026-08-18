//go:build maintainability_service

// Package benchmarks contains service-layer maintainability fixtures:
// error classification, structured logging, validation shape and repository
// access.
package benchmarks

import (
	"context"
	"errors"
	"io/ioutil"
)

// ErrNotFound is returned when a record does not exist.
var ErrNotFound = errors.New("not found")

// Item is a record handled by the service.
type Item struct {
	ID   string
	Body string
}

// Data is a record loaded by id.
type Data struct {
	ID    string
	Value string
}

// Request is an inbound service request.
type Request struct {
	Name   string
	Amount int
}

// Repository persists and loads records.
type Repository interface {
	Save(ctx context.Context, item Item) error
	Get(ctx context.Context, id string) (*Data, error)
}

// Logger emits structured log lines.
type Logger interface {
	Debug(msg string, args ...interface{})
}

// Service coordinates repository access for items.
type Service struct {
	repo   Repository
	logger Logger
}

var repo Repository

// LookupItem returns the item, or a nil result when it is absent.
func LookupItem(err error) (*Item, error) {
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return nil, err
}

// ProcessItem persists a single item.
func (s *Service) ProcessItem(ctx context.Context, item Item) error {
	s.logger.Debug("processing item", "id", item.ID)
	return s.repo.Save(ctx, item)
}

func validate(req *Request) error {
	if req == nil {
		return errors.New("nil request")
	}
	if req.Name == "" {
		return errors.New("empty name")
	}
	if req.Amount <= 0 {
		return errors.New("invalid amount")
	}
	return nil
}

func fetchData(ctx context.Context, id string) (*Data, error) {
	return repo.Get(ctx, id)
}

// LoadConfigFile reads the config file at path.
func LoadConfigFile(path string) ([]byte, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}
