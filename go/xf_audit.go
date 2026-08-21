package benchmarks

// Event identity for audit-log ingestion.

func auditKey(e Event) string { return e.Source + ":" + e.Type + ":" + e.ID }
