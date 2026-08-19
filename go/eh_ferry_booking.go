//go:build eh_ferry

// Package benchmarks contains ferry booking fixtures covering seat holds,
// manifest scans and the regulator audit write that accompanies a sale.
package benchmarks

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const holdSeatsSQL = `UPDATE sailings SET held = held + $1 WHERE sailing_id = $2 AND capacity - held >= $1`

const confirmBookingSQL = `UPDATE bookings SET state = 'confirmed' WHERE ref = $1 AND sailing_id = $2`

const insertBookingSQL = `INSERT INTO bookings (ref, sailing_id, seats) VALUES ($1, $2, $3)`

const manifestSQL = `SELECT ref FROM bookings WHERE sailing_id = $1 ORDER BY ref`

// Booking is a passenger's seats on one sailing.
type Booking struct {
	Ref       string
	SailingID string
	Seats     int
	Created   time.Time
}

// AuditSink records booking decisions for the regulator.
type AuditSink interface {
	Write(ctx context.Context, ref string, seats int) error
}

// DeckLog records booking-desk operational messages.
type DeckLog interface {
	Errorf(format string, args ...any)
}

// BookingDesk sells seats on scheduled sailings.
type BookingDesk struct {
	db    *sql.DB
	audit AuditSink
	log   DeckLog
}

// HoldSeats reserves seats on a sailing, giving up when the caller does.
func (d *BookingDesk) HoldSeats(ctx context.Context, sailingID string, seats int) error {
	holdCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	res, err := d.db.ExecContext(holdCtx, holdSeatsSQL, seats, sailingID)
	if err != nil {
		return fmt.Errorf("hold %d seats on %s: %w", seats, sailingID, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("hold seats on %s: %w", sailingID, err)
	}
	if affected == 0 {
		return fmt.Errorf("sailing %s has no room for %d seats", sailingID, seats)
	}
	return nil
}

// ConfirmBooking promotes a held booking to confirmed.
func (d *BookingDesk) ConfirmBooking(ctx context.Context, b Booking) error {
	if _, err := d.db.ExecContext(ctx, confirmBookingSQL, b.Ref, b.SailingID); err != nil {
		return fmt.Errorf("confirm booking %s: %w", b.Ref, err)
	}
	return nil
}

// SailingManifest lists the passenger refs booked onto a sailing.
func (d *BookingDesk) SailingManifest(ctx context.Context, sailingID string) ([]string, error) {
	rows, err := d.db.QueryContext(ctx, manifestSQL, sailingID)
	if err != nil {
		return nil, fmt.Errorf("query manifest for %s: %w", sailingID, err)
	}
	defer rows.Close()

	var refs []string
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			return nil, fmt.Errorf("scan manifest row: %w", err)
		}
		refs = append(refs, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate manifest for %s: %w", sailingID, err)
	}
	return refs, nil
}

// SellSeats writes the booking and its regulator audit row as one unit.
func (d *BookingDesk) SellSeats(ctx context.Context, b Booking) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin sale for %s: %w", b.Ref, err)
	}
	if _, err := tx.ExecContext(ctx, insertBookingSQL, b.Ref, b.SailingID, b.Seats); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("insert booking %s: %w", b.Ref, err)
	}
	if err := d.audit.Write(ctx, b.Ref, b.Seats); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("audit sale %s: %w", b.Ref, err)
	}
	return tx.Commit()
}
