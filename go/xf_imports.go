package benchmarks

// Import staging. Mirrors upload staging for bundle imports.

type Bundle struct{ Name string }

func writeTemp2(b Bundle) (string, error) { return "", nil }

func stageImport(b Bundle) (string, error) { path, err := writeTemp2(b); if err != nil { removeTemp(path); return "", err }; return path, nil }
