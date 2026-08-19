//go:build lg_ferry_timetable

// Package benchmarks contains ferry timetable fixtures: berth capacity
// conversion, sailing pagination and manifest line parsing.
package benchmarks

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// TimetableConfig holds operator-supplied limits for a single ferry route.
type TimetableConfig struct {
	MaxFootPassengers int
	SailingsPerDay    int
}

// Berth describes a loading berth and the capacity declared for it.
type Berth struct {
	Code     string
	Capacity int32
}

// Sailing is one scheduled departure on a route.
type Sailing struct {
	Code      string
	Departure time.Time
	BerthCode string
}

func configureBerth(berth *Berth, cfg TimetableConfig) error {
	if cfg.MaxFootPassengers > math.MaxInt32 || cfg.MaxFootPassengers < 0 {
		return fmt.Errorf("max_foot_passengers %d out of range", cfg.MaxFootPassengers)
	}
	berth.Capacity = int32(cfg.MaxFootPassengers)
	return nil
}

func manifestPages(sailings []Sailing, pageSize int) [][]Sailing {
	if pageSize <= 0 {
		return nil
	}
	var pages [][]Sailing
	for start := 0; start < len(sailings); start += pageSize {
		end := start + pageSize
		if end > len(sailings) {
			end = len(sailings)
		}
		pages = append(pages, sailings[start:end])
	}
	return pages
}

func parseManifestLine(line string) (time.Time, string, error) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return time.Time{}, "", errors.New("manifest line too short")
	}
	stamp, err := time.Parse(time.RFC3339, fields[0])
	if err != nil {
		return time.Time{}, "", fmt.Errorf("manifest timestamp: %w", err)
	}
	return stamp, fields[2], nil
}

func sailingsForBerth(sailings []Sailing, berthCode string) []Sailing {
	out := make([]Sailing, 0, len(sailings))
	for _, s := range sailings {
		if s.BerthCode == berthCode {
			out = append(out, s)
		}
	}
	return out
}
