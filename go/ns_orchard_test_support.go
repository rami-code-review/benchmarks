//go:build ns_orchard_test_support

// Package benchmarks holds test-support helpers for an orchard harvest
// planner: the fixture builders and the assertions written against them.
package benchmarks

import (
	"testing"
)

// Grader is the inspector who graded a pick. Ungraded picks have none.
type Grader struct {
	Name  string
	Badge string
}

// Harvest is one recorded pick from a block of trees.
type Harvest struct {
	Block  string
	Kilos  float64
	Grader *Grader
}

func newHarvestFixture(block string, kilos float64) Harvest {
	return Harvest{Block: block, Kilos: kilos}
}

func withGrader(h Harvest, name, badge string) Harvest {
	h.Grader = &Grader{Name: name, Badge: badge}
	return h
}

// go-null-fixture-grader-deref-medium
func assertGraderBadge(t *testing.T, h Harvest, want string) {
	t.Helper()
	if h.Grader == nil {
		t.Fatalf("harvest for block %s has no grader", h.Block)
	}
	if h.Grader.Badge != want {
		t.Errorf("grader badge = %q, want %q", h.Grader.Badge, want)
	}
}

func assertHarvestKilos(t *testing.T, h Harvest, want float64) {
	t.Helper()
	if h.Kilos != want {
		t.Errorf("kilos for block %s = %v, want %v", h.Block, h.Kilos, want)
	}
}
