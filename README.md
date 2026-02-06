# Rami Benchmark Fixtures

Source code samples for benchmarking Rami's code review quality. Based on OWASP Benchmark methodology with balanced true positive/false positive test cases.

## Structure

```
├── go/
│   ├── database.go    # Database ops (SQL injection, secrets, crypto, error handling, SSRF)
│   └── service.go     # Business logic (race conditions, nil safety, loops, command injection)
├── python/
│   └── database.py    # Python patterns (SQL injection, deserialization, mutable defaults)
├── typescript/
│   └── components.tsx # React components (XSS, null safety, command injection)
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
7. **False positive tests** verify Rami doesn't flag safe patterns

## Template Coverage

| Language   | Templates | Categories |
|------------|-----------|------------|
| Go         | 38        | security, error-handling, null-safety, logic, performance, maintainability |
| Python     | 16        | security, error-handling, null-safety, logic, performance |
| TypeScript | 16        | security, error-handling, null-safety, logic |

**Total: 70+ templates** including 5 false positive test cases.

## Difficulty Tiers

| Tier   | Description | Examples |
|--------|-------------|----------|
| Easy   | Single-line patterns | Direct SQL concatenation, hardcoded secrets |
| Medium | Multi-line context | Builder patterns, error shadowing |
| Hard   | Cross-function | Indirect injection via variable, caller contracts |

## Defect Patterns Covered (CWE References)

### Security

**SQL Injection (CWE-89)**
- String concatenation, fmt.Sprintf, f-strings, template literals
- Builder pattern injection, indirect via variable assignment

**Command Injection (CWE-78)**
- Shell execution (sh -c, bash -c, shell=True)
- os.system, child_process.exec, spawn with shell

**Path Traversal (CWE-22)**
- Unsanitized filepath.Join, missing base directory validation
- os.path.join without basename extraction

**XSS (CWE-79)**
- innerHTML, dangerouslySetInnerHTML, document.write, eval

**Hardcoded Secrets (CWE-798)**
- API keys, passwords, tokens in source code

**Insecure Deserialization (CWE-502)**
- pickle.loads, yaml.load without safe_load

**Weak Cryptography (CWE-327/328)**
- MD5, SHA1 for password hashing

**SSRF (CWE-918)**
- Unvalidated URL fetching, requests to user-provided URLs

### Error Handling (CWE-755)

- Swallowed errors (log but don't return)
- Ignored error returns (discard with `_`)
- Error shadowing in inner scope
- Bare except catching SystemExit
- Empty catch blocks

### Null Safety (CWE-476)

- Nil pointer dereference
- Nil map writes (panic)
- Nil slice indexing
- Type assertion on nil interface
- Missing optional chaining
- Unsafe non-null assertion (!.)

### Logic Errors

- Off-by-one in loop bounds
- Race conditions on shared variables
- Incorrect boolean operators (|| vs &&)
- Assignment instead of comparison
- Defer in loop (resource leak)
- Loop variable captured by goroutine
- Mutable default arguments (Python)
- `is` vs `==` for value comparison
- Loose equality (== vs ===)

### Performance

- N+1 queries in loops
- Missing slice pre-allocation
- String concatenation in loops
- Loop instead of list comprehension

### Maintainability

- Magic numbers without constants
- Deeply nested conditionals

## False Positive Tests

Templates where `OriginalCode == DefectiveCode` test that Rami does NOT flag correct patterns:

| ID | Pattern | Why It's Safe |
|----|---------|---------------|
| go-fp-sql-prepared | SQL with dynamic table from allowlist | Table name from validated map, not user input |
| go-fp-cmd-constant | Shell command with constant string | No user input in command |
| go-fp-nil-checked-elsewhere | Nil access per caller contract | Nil check is in calling function |
| py-fp-format-sanitized | f-string with validated enum | Column name from allowlist |
| ts-fp-innerhtml-sanitized | innerHTML after DOMPurify | Properly sanitized before use |

## Adding New Fixtures

1. Check available templates in `rami-code-review/internal/benchmark/templates.go`
2. Add source files containing the **exact** `OriginalCode` patterns (trimmed lines must match)
3. The benchmark tool will automatically detect and inject defects
4. For false positive tests, include the "safe but suspicious" pattern
