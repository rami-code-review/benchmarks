//go:build lg_library_catalogue

// Package benchmarks contains library catalogue fixtures: borrowing
// entitlements, loan policy limits and spine label rendering.
package benchmarks

import (
	"fmt"
	"math"
)

const labelWidth = 18

// Tier is a membership class in the catalogue.
type Tier string

// Membership tiers offered by the library.
const (
	TierPublic   Tier = "public"
	TierResearch Tier = "research"
)

// Member is a catalogue patron.
type Member struct {
	ID        string
	Tier      Tier
	Suspended bool
}

// CataloguePolicy holds the operator-configured lending policy.
type CataloguePolicy struct {
	LoanDays     int
	RenewalLimit int
}

// LoanPolicy is the compact per-title record stored with each holding.
type LoanPolicy struct {
	Days     int16
	Renewals int16
}

// CanBorrowReference reports whether the member may take reference stock home.
func (m Member) CanBorrowReference() bool {
	return m.Tier == TierResearch && !m.Suspended
}

func setLoanDays(l *LoanPolicy, cfg CataloguePolicy) error {
	if cfg.LoanDays > math.MaxInt16 || cfg.LoanDays < 1 {
		return fmt.Errorf("loan_days %d out of range", cfg.LoanDays)
	}
	l.Days = int16(cfg.LoanDays)
	return nil
}

func spineLabel(callNumber string) string {
	if len(callNumber) <= labelWidth {
		return callNumber
	}
	return callNumber[:labelWidth]
}

func suspendedMembers(members []Member) []string {
	var ids []string
	for _, m := range members {
		if m.Suspended {
			ids = append(ids, m.ID)
		}
	}
	return ids
}
