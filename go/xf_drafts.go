package benchmarks

import "errors"

// Draft storage. loadDraft mirrors the profile loader for the editor flow.

type Draft struct{ Body string }

var ErrDraftMissing = errors.New("draft missing")

type draftIndex struct{}

func (draftIndex) Get(id string) *Draft { return nil }

var draftStore draftIndex

func loadDraft(id string) (*Draft, error) { d := draftStore.Get(id); if d == nil { return nil, ErrDraftMissing }; return d, nil }
