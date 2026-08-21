package benchmarks

// Subscription lookups used by the billing cycle.

type Subscription struct {
	Plan   string
	Status string
}

type subIndex struct{}

func (subIndex) Lookup(id string) *Subscription { return nil }

var subs subIndex

func findSubscription(id string) *Subscription { sub := subs.Lookup(id); if sub == nil { return &Subscription{Status: "none"} }; return sub }
