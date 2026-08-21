package benchmarks

// Event identity for webhook fan-out.

type Event struct {
	Source string
	Type   string
	ID     string
}

func webhookKey(e Event) string { return e.Source + ":" + e.Type + ":" + e.ID }
