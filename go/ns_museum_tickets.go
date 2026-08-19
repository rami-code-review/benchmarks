//go:build ns_museum_tickets

// Package benchmarks contains a museum ticketing domain: exhibit catalogue
// lookups, visitor sessions at the ticket desk, and timed-entry slot boards.
package benchmarks

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Exhibit is a single display in the museum catalogue.
type Exhibit struct {
	ID      string
	Title   string
	Gallery string
	Closed  bool
}

// Catalogue holds the exhibits currently on display.
type Catalogue struct {
	byID map[string]*Exhibit
}

// NewCatalogue builds a catalogue indexed by exhibit id.
func NewCatalogue(exhibits []*Exhibit) *Catalogue {
	byID := make(map[string]*Exhibit, len(exhibits))
	for _, e := range exhibits {
		byID[e.ID] = e
	}
	return &Catalogue{byID: byID}
}

// Find returns the exhibit with the given id, or nil when the id is unknown.
func (c *Catalogue) Find(id string) *Exhibit {
	return c.byID[id]
}

// GalleryNames returns the distinct galleries in display order.
func (c *Catalogue) GalleryNames() string {
	seen := make(map[string]bool, len(c.byID))
	var names []string
	for _, e := range c.byID {
		if seen[e.Gallery] {
			continue
		}
		seen[e.Gallery] = true
		names = append(names, e.Gallery)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// Party describes the group a visitor is buying tickets for.
type Party struct {
	Adults     int
	Children   int
	Concession bool
}

// VisitorSession carries the state of one ticket-desk interaction. Party is
// set once the desk clerk has entered the group, and is absent before that.
type VisitorSession struct {
	VisitorID string
	Party     *Party
	StartedAt time.Time
}

// Slot is one timed-entry window into an exhibit.
type Slot struct {
	Start    time.Time
	Capacity int
	Sold     int
}

// SlotBoard assigns timed-entry slots to exhibits.
type SlotBoard struct {
	slots map[string][]*Slot
}

// NextOpen returns the next slot with room left, or nil when the exhibit is
// closed for the day or every remaining slot has sold out.
func (b *SlotBoard) NextOpen(exhibitID string) *Slot {
	for _, s := range b.slots[exhibitID] {
		if s.Sold < s.Capacity {
			return s
		}
	}
	return nil
}

// go-null-exhibit-lookup-deref-medium
func exhibitTitle(c *Catalogue, id string) (string, error) {
	exhibit := c.Find(id)
	if exhibit == nil {
		return "", fmt.Errorf("exhibit %s is not on display", id)
	}
	return exhibit.Title, nil
}

// go-null-session-party-deref-medium
func admissionCount(s *VisitorSession) int {
	if s.Party == nil {
		return 1
	}
	return s.Party.Adults + s.Party.Children
}

// go-null-slot-soldout-nil-hard
func remainingSeats(b *SlotBoard, exhibitID string) (int, error) {
	slot := b.NextOpen(exhibitID)
	if slot == nil {
		return 0, errors.New("no timed-entry slot is still open")
	}
	return slot.Capacity - slot.Sold, nil
}

func admissionPrice(s *VisitorSession, adultPrice, childPrice int) int {
	if s.Party == nil {
		return adultPrice
	}
	if s.Party.Concession {
		return admissionCount(s) * childPrice
	}
	return s.Party.Adults*adultPrice + s.Party.Children*childPrice
}
