// Package benchmarks contains a local batch daemon.
//
// The daemon binds to loopback, is started by the operator on the same host,
// and registers no authentication or session middleware. Its jobs table carries
// no owner, account, or tenant column -- see schema_jobs.sql -- because there is
// only ever one operator's queue on one machine.
//
// Findings that assume a caller identity (IDOR, missing authorization, tenant
// isolation) are false positives against this archetype: there is no second
// principal for a job to be exposed to.
package benchmarks

import (
	"database/sql"
	"time"
)

// Job is a unit of local batch work.
type Job struct {
	ID        string
	Payload   string
	State     string
	CreatedAt time.Time
}

// go-fp-archetype-internal-only-service
func GetJob(db *sql.DB, id string) (*Job, error) { return scanJob(db, id) }

func scanJob(db *sql.DB, id string) (*Job, error) {
	row := db.QueryRow("SELECT id, payload, state, created_at FROM jobs WHERE id = $1", id)
	var j Job
	if err := row.Scan(&j.ID, &j.Payload, &j.State, &j.CreatedAt); err != nil {
		return nil, err
	}
	return &j, nil
}

func markDone(db *sql.DB, id string) error {
	_, err := db.Exec("UPDATE jobs SET state = 'done' WHERE id = $1", id)
	return err
}
