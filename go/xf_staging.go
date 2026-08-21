package benchmarks

// Upload staging. Ownership of the staged temp file is part of the contract.

type Upload struct{ Owner string }

func writeTemp(u Upload) (string, error) { return "", nil }

func removeTemp(path string) {}

func stageUpload(u Upload) (string, error) { path, err := writeTemp(u); if err != nil { removeTemp(path); return "", err }; return path, nil }
