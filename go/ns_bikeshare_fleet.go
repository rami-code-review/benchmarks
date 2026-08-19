//go:build ns_bikeshare_fleet

// Package benchmarks contains a bike-share fleet domain: dock stations, ride
// legs, member passes and the free-form tags operations attach to a station.
package benchmarks

import (
	"errors"
	"time"
)

// Dock is one bike dock at a station.
type Dock struct {
	ID       string
	BikeID   string
	Occupied bool
}

// Station is a bike-share station. Tags is populated lazily, the first time
// operations records something about the station.
type Station struct {
	Name  string
	Docks []Dock
	Tags  map[string]string
}

// Leg is one segment of a multi-modal trip. A trip may end at a pier or a
// transit stop rather than a dock, in which case the closing leg is absent.
type Leg struct {
	From     string
	To       string
	Duration time.Duration
}

// Pass is a prepaid ride pass. Members on pay-as-you-go have none.
type Pass struct {
	RidesLeft int
	Expires   time.Time
}

// Rider is a bike-share member.
type Rider struct {
	Name string
	Pass *Pass
}

func availableDocks(docks []Dock) []Dock {
	var out []Dock
	for _, d := range docks {
		if !d.Occupied {
			out = append(out, d)
		}
	}
	return out
}

func legDuration(l *Leg) time.Duration {
	if l == nil {
		return 0
	}
	return l.Duration
}

// go-null-dock-empty-index-medium
func firstFreeDock(docks []Dock) (Dock, error) {
	free := availableDocks(docks)
	if len(free) == 0 {
		return Dock{}, errors.New("station has no free dock")
	}
	return free[0], nil
}

// go-null-station-tag-map-write-medium
func tagStation(s *Station, key, value string) {
	if s.Tags == nil {
		s.Tags = make(map[string]string)
	}
	s.Tags[key] = value
}

// go-null-leg-duration-easy
func closingLegMinutes(l *Leg) float64 {
	return legDuration(l).Minutes()
}

func passRidesLeft(r Rider, now time.Time) int {
	if r.Pass == nil || r.Pass.Expires.Before(now) {
		return 0
	}
	return r.Pass.RidesLeft
}
