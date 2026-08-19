//go:build eh_bookstore

// Package benchmarks contains bookstore order fixtures covering transactional
// writes, catalogue lookups and bulk manifest import.
package benchmarks

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"time"
)

// ErrTitleUnknown reports that a catalogue lookup found no such title.
var ErrTitleUnknown = errors.New("title not in catalogue")

// LedgerEntry is one line of the store's takings ledger.
type LedgerEntry struct {
	OrderID string
	Cents   int64
	Placed  time.Time
}

// Ledger appends money movements for later reconciliation.
type Ledger interface {
	Record(ctx context.Context, e LedgerEntry) (string, error)
}

// Catalogue answers title questions for the storefront.
type Catalogue interface {
	StockCount(ctx context.Context, isbn string) (int, error)
}

// Tx is a storage transaction over the orders table.
type Tx interface {
	InsertOrder(ctx context.Context, orderID string, cents int64) error
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// ShelfLog records shop-floor operational messages.
type ShelfLog interface {
	Infof(format string, args ...any)
}

// OrderDesk places customer orders against the ledger and the catalogue.
type OrderDesk struct {
	ledger    Ledger
	catalogue Catalogue
	log       ShelfLog
}

// RecordSale appends a completed sale to the takings ledger.
func (d *OrderDesk) RecordSale(ctx context.Context, e LedgerEntry) error {
	ref, err := d.ledger.Record(ctx, e)
	if err != nil {
		return fmt.Errorf("record sale %s: %w", e.OrderID, err)
	}
	d.log.Infof("sale %s recorded as %s", e.OrderID, ref)
	return nil
}

// ReserveCopies holds copies for a pending order, bounded by the caller's deadline.
func (d *OrderDesk) ReserveCopies(ctx context.Context, isbn string, want int) error {
	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	count, err := d.catalogue.StockCount(lookupCtx, isbn)
	if err != nil {
		return fmt.Errorf("reserve %d copies of %s: %w", want, isbn, err)
	}
	if count < want {
		return fmt.Errorf("only %d copies of %s on the shelf", count, isbn)
	}
	return nil
}

// InStock reports whether the catalogue still holds copies of a title. A lookup
// failure is distinct from a title that is genuinely sold out.
func (d *OrderDesk) InStock(ctx context.Context, isbn string) (bool, error) {
	count, err := d.catalogue.StockCount(ctx, isbn)
	if errors.Is(err, ErrTitleUnknown) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("stock count for %s: %w", isbn, err)
	}
	return count > 0, nil
}

// PlaceOrder writes the order row and its ledger entry as one unit.
func (d *OrderDesk) PlaceOrder(ctx context.Context, tx Tx, orderID string, cents int64) error {
	if err := tx.InsertOrder(ctx, orderID, cents); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("insert order %s: %w", orderID, err)
	}
	if _, err := d.ledger.Record(ctx, LedgerEntry{OrderID: orderID, Cents: cents}); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("ledger entry for %s: %w", orderID, err)
	}
	return tx.Commit(ctx)
}

// ImportManifests reads each supplier manifest and returns every ISBN listed.
func ImportManifests(paths []string) ([]string, error) {
	var isbns []string
	for _, path := range paths {
		rows, err := readManifest(path)
		if err != nil {
			return nil, fmt.Errorf("read manifest %s: %w", path, err)
		}
		isbns = append(isbns, rows...)
	}
	return isbns, nil
}

func readManifest(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(records))
	for _, rec := range records {
		if len(rec) > 0 {
			out = append(out, rec[0])
		}
	}
	return out, nil
}
