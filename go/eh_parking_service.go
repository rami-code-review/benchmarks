//go:build eh_parking

// Package benchmarks contains parking-garage fixtures whose correctness
// depends on permit and bay failures reaching the caller.
package benchmarks

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// ErrPermitMissing reports that no permit is on file for a plate.
var ErrPermitMissing = errors.New("permit not on file")

// Permit is a parking permit issued to one vehicle for one bay.
type Permit struct {
	ID      string
	Plate   string
	Bay     int32
	Expires time.Time
}

// PermitStore persists issued permits.
type PermitStore interface {
	Save(ctx context.Context, p Permit) error
	ByPlate(ctx context.Context, plate string) (Permit, error)
}

// GateLog records gate operational messages.
type GateLog interface {
	Warnf(format string, args ...any)
}

// GarageDesk issues permits and answers bay questions for a single garage.
type GarageDesk struct {
	permits PermitStore
	log     GateLog
}

// IssuePermit persists a permit for the given vehicle.
func (d *GarageDesk) IssuePermit(ctx context.Context, p Permit) error {
	if err := d.permits.Save(ctx, p); err != nil {
		return fmt.Errorf("save permit %s: %w", p.ID, err)
	}
	d.log.Warnf("permit %s issued for bay %d", p.ID, p.Bay)
	return nil
}

// AssignBay turns an operator-entered bay label into a bay number.
func (d *GarageDesk) AssignBay(rawBay string) (int32, error) {
	bay, err := strconv.ParseInt(rawBay, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse bay %q: %w", rawBay, err)
	}
	if bay <= 0 {
		return 0, fmt.Errorf("bay %d is outside the garage", bay)
	}
	return int32(bay), nil
}

// HasValidPermit reports whether the plate holds an unexpired permit. A lookup
// failure is returned so the caller can tell it apart from an absent permit.
func (d *GarageDesk) HasValidPermit(ctx context.Context, plate string, now time.Time) (bool, error) {
	p, err := d.permits.ByPlate(ctx, plate)
	if errors.Is(err, ErrPermitMissing) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("load permit for %s: %w", plate, err)
	}
	return p.Expires.After(now), nil
}

// EvictVehicle expires the permit that pins a vehicle to its bay.
func (d *GarageDesk) EvictVehicle(ctx context.Context, plate string, now time.Time) error {
	p, err := d.permits.ByPlate(ctx, plate)
	if err != nil {
		return fmt.Errorf("evict %s: %w", plate, err)
	}
	p.Expires = now
	return d.permits.Save(ctx, p)
}
