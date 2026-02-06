# Rami Benchmark Fixtures

Source code samples for benchmarking Rami's code review quality.

## Structure

```
├── go/
│   ├── database.go    # Database operations (SQL injection, secrets, error handling)
│   └── service.go     # Business logic (race conditions, nil safety, loops)
├── python/
│   └── database.py    # Python patterns (SQL injection, mutable defaults, exceptions)
├── typescript/
│   └── components.tsx # React components (XSS, null safety, optional chaining)
└── README.md
```

## Usage

These files contain clean, safe code patterns that match Rami's defect injection templates.
The benchmark tool (`rami benchmark`) injects known vulnerabilities and bugs into these
files, then measures how well Rami detects them.

```bash
# Run benchmark against these fixtures
rami benchmark --source ~/workspace/rami-benchmarks --local
```

## How It Works

1. The benchmark tool reads source files from this repository
2. Finds patterns matching `OriginalCode` in `internal/benchmark/templates.go`
3. Replaces them with `DefectiveCode` (vulnerable/buggy versions)
4. Runs Rami's code review on the mutated code
5. Scores findings against known ground truth using LLM-as-Judge
6. Reports precision, recall, and F1 metrics

## Template Coverage

| Language   | Templates | Categories |
|------------|-----------|------------|
| Go         | 14        | security, error-handling, null-safety, logic, performance, maintainability |
| Python     | 4         | security, error-handling, logic, performance |
| TypeScript | 2         | security, null-safety |

## Adding New Fixtures

To add fixtures that work with the benchmark:

1. Check available templates in `rami-code-review/internal/benchmark/templates.go`
2. Add source files containing the **exact** `OriginalCode` patterns (trimmed lines must match)
3. The benchmark tool will automatically detect and inject defects

## Defect Patterns Covered

### Security
- SQL injection (parameterized queries → string concatenation)
- Command injection (sanitized input → shell execution)
- Path traversal (filepath.Clean → raw user input)
- Hardcoded secrets (env vars → literal strings)
- XSS (textContent → innerHTML)

### Error Handling
- Swallowed errors (return err → log and continue)
- Ignored error returns (check err → discard)
- Bare except (specific exception → catch all)

### Null Safety
- Nil pointer dereference (nil check → direct access)
- Nil map writes (make() → var declaration)
- Missing optional chaining (user?.profile → user.profile)

### Logic
- Off-by-one errors (< len → <= len)
- Race conditions (mutex protected → unprotected)
- Incorrect boolean logic (|| → &&)
- Mutable default arguments (None default → list default)

### Performance
- N+1 queries (batch → loop)
- Unbounded allocations (pre-alloc → dynamic growth)
- String concatenation in loops (join → +=)

### Maintainability
- Magic numbers (named constant → literal)
