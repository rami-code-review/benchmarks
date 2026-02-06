# Rami Benchmark Fixtures

Source code samples for benchmarking Rami's code review quality.

## Structure

```
├── go/           # Go source files
├── python/       # Python source files
├── typescript/   # TypeScript source files
└── README.md
```

## Usage

These files contain clean, safe code patterns that match Rami's defect injection templates.
The benchmark tool (`rami benchmark`) injects known vulnerabilities and bugs into these
files, then measures how well Rami detects them.

```bash
# Run benchmark against these fixtures
rami benchmark --source ~/workspace/rami-benchmarks
```

## Adding New Fixtures

To add fixtures that work with the benchmark:

1. Use patterns that match templates in `internal/benchmark/templates.go`
2. Include a mix of defect categories: security, error-handling, null-safety, logic, performance
3. Keep files focused and realistic - they should look like production code

## Defect Patterns Covered

### Security
- SQL injection (parameterized queries → string concatenation)
- Command injection (sanitized input → shell execution)
- Path traversal (filepath.Clean → raw user input)
- Hardcoded secrets (env vars → literal strings)

### Error Handling
- Swallowed errors (return err → log and continue)
- Ignored error returns (check err → discard)

### Null Safety
- Nil pointer dereference (nil check → direct access)
- Nil map writes (make() → var declaration)

### Logic
- Off-by-one errors (< len → <= len)
- Race conditions (mutex → unprotected)
- Incorrect boolean logic (|| → &&)

### Performance
- N+1 queries (batch → loop)
- Unbounded allocations (pre-alloc → dynamic)
