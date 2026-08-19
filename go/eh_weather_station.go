//go:build eh_weather

// Package benchmarks contains weather-station fixtures covering HTTP response
// handling, station queries and reading serialization.
package benchmarks

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const activeStationsSQL = `SELECT station_id FROM observations WHERE taken_at >= $1 GROUP BY station_id`

const latestReadingSQL = `SELECT station_id, celsius, taken_at FROM observations WHERE station_id = $1 ORDER BY taken_at DESC LIMIT 1`

// Reading is one observation taken at a station.
type Reading struct {
	StationID string    `json:"station_id"`
	Celsius   float64   `json:"celsius"`
	TakenAt   time.Time `json:"taken_at"`
}

// StationLog records station-side operational messages.
type StationLog interface {
	Errorf(format string, args ...any)
}

// StationAPI serves readings over HTTP and reads them from storage.
type StationAPI struct {
	db     *sql.DB
	client *http.Client
	log    StationLog
}

// WriteReading serializes a reading onto the response.
func (a *StationAPI) WriteReading(w http.ResponseWriter, r Reading) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(r); err != nil {
		a.log.Errorf("encode reading for %s: %v", r.StationID, err)
	}
}

// ActiveStations lists the stations that reported inside the window.
func (a *StationAPI) ActiveStations(ctx context.Context, since time.Time) ([]string, error) {
	rows, err := a.db.QueryContext(ctx, activeStationsSQL, since)
	if err != nil {
		return nil, fmt.Errorf("query active stations: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan active station: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// LoadReading returns the most recent reading for a station.
func (a *StationAPI) LoadReading(ctx context.Context, stationID string) (Reading, error) {
	var r Reading
	err := a.db.QueryRowContext(ctx, latestReadingSQL, stationID).Scan(&r.StationID, &r.Celsius, &r.TakenAt)
	if err != nil {
		return Reading{}, fmt.Errorf("latest reading for station %s: %w", stationID, err)
	}
	return r, nil
}

// FetchForecasts retrieves one forecast document per station URL.
func (a *StationAPI) FetchForecasts(ctx context.Context, urls []string) ([][]byte, error) {
	docs := make([][]byte, 0, len(urls))
	for _, url := range urls {
		doc, err := a.fetchOne(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("fetch forecast %s: %w", url, err)
		}
		docs = append(docs, doc)
	}
	return docs, nil
}

func (a *StationAPI) fetchOne(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("forecast %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
