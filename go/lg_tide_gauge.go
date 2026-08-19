//go:build lg_tide_gauge

// Package benchmarks contains tide gauge fixtures: record parsing, station
// calibration and surge alerting.
package benchmarks

import (
	"errors"
	"strings"
	"time"
)

const gaugeTimeLayout = "2006-01-02T15:04:05Z"

// Reading is one metre-level sample from a gauge station.
type Reading struct {
	Station string
	Metres  float64
	Taken   time.Time
}

// StationOffset is the survey correction applied to a station's readings.
type StationOffset struct {
	Station string
	Metres  float64
}

// Gauge tracks the live surge threshold for one station.
type Gauge struct {
	Station         string
	BaseThreshold   float64
	SurgeAllowance  float64
	Threshold       float64
	LastAlertLevel  string
	ConsecutiveHigh int
}

func readingTimestamp(record string) (time.Time, error) {
	parts := strings.FieldsFunc(record, func(r rune) bool { return r == '\t' || r == ' ' })
	if len(parts) < 2 {
		return time.Time{}, errors.New("gauge record has too few fields")
	}
	return time.Parse(gaugeTimeLayout, parts[0])
}

func applyCalibrations(readings []Reading, offsets []StationOffset) []Reading {
	byStation := make(map[string]float64, len(offsets))
	for _, o := range offsets {
		byStation[o.Station] = o.Metres
	}
	out := make([]Reading, 0, len(readings))
	for _, r := range readings {
		r.Metres += byStation[r.Station]
		out = append(out, r)
	}
	return out
}

func alertLevel(g *Gauge, reading float64) string {
	g.Threshold = g.BaseThreshold + g.SurgeAllowance
	if reading > g.Threshold {
		g.ConsecutiveHigh++
		return "surge"
	}
	g.ConsecutiveHigh = 0
	return "normal"
}

func stationNames(readings []Reading) []string {
	seen := make(map[string]struct{}, len(readings))
	var names []string
	for _, r := range readings {
		if _, ok := seen[r.Station]; ok {
			continue
		}
		seen[r.Station] = struct{}{}
		names = append(names, r.Station)
	}
	return names
}
