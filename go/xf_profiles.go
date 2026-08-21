package benchmarks

import "errors"

// Profile storage. loadProfile's error contract is part of the login flow:
// first-login provisioning keys off the missing-profile sentinel.

type Profile struct{ Body string }

var ErrProfileMissing = errors.New("profile missing")

type profileIndex struct{}

func (profileIndex) Get(id string) *Profile { return nil }

var profileStore profileIndex

func loadProfile(id string) (*Profile, error) { p := profileStore.Get(id); if p == nil { return nil, ErrProfileMissing }; return p, nil }
