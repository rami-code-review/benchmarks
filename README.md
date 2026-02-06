# Rami Benchmark Fixtures

Source code samples for benchmarking Rami's code review quality. Based on OWASP Benchmark methodology with balanced true positive/false positive test cases.

## Structure

```
├── go/
│   ├── database.go       # Database ops (SQL injection, secrets, crypto, error handling)
│   ├── service.go        # Business logic (race conditions, nil safety, loops)
│   ├── cve_patterns.go   # CVE-derived vulnerability patterns
│   └── multifile/        # Multi-file context-dependent scenarios
│       ├── handler.go
│       ├── database.go
│       └── executor.go
├── python/
│   ├── database.py       # Python patterns (SQL injection, deserialization)
│   ├── cve_patterns.py   # CVE-derived vulnerability patterns
│   └── multifile/        # Multi-file context-dependent scenarios
│       ├── views.py
│       ├── models.py
│       └── validators.py
├── typescript/
│   ├── components.tsx    # React components (XSS, null safety)
│   ├── cve_patterns.ts   # CVE-derived vulnerability patterns
│   └── multifile/        # Multi-file context-dependent scenarios
│       ├── api.ts
│       ├── service.ts
│       └── validators.ts
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
| Go         | 50+       | security, error-handling, null-safety, logic, performance, CVE patterns |
| Python     | 22+       | security, error-handling, null-safety, logic, CVE patterns |
| TypeScript | 21+       | security, error-handling, null-safety, logic, CVE patterns |

**Total: 93+ templates** including:
- 5 false positive test cases
- 8 multi-file context-dependent scenarios
- 15 CVE-derived real-world patterns

## Difficulty Tiers

| Tier   | Description | Examples |
|--------|-------------|----------|
| Easy   | Single-line patterns | Direct SQL concatenation, hardcoded secrets |
| Medium | Multi-line context | Builder patterns, error shadowing |
| Hard   | Cross-function | Indirect injection via variable, caller contracts |
| Expert | Multi-file/CVE | Data flow across files, real-world vulnerability patterns |

## Defect Patterns Covered (CWE References)

### Security

**SQL Injection (CWE-89)**
- String concatenation, fmt.Sprintf, f-strings, template literals
- Builder pattern injection, indirect via variable assignment
- Multi-file data flow scenarios

**Command Injection (CWE-78)**
- Shell execution (sh -c, bash -c, shell=True)
- os.system, child_process.exec, spawn with shell
- Shellshock-style patterns (CVE-2014-6271)

**Path Traversal (CWE-22)**
- Unsanitized filepath.Join, missing base directory validation
- os.path.join without basename extraction
- Archive extraction without validation (CVE-2024-3094 style)

**XSS (CWE-79)**
- innerHTML, dangerouslySetInnerHTML, document.write, eval
- Reflected XSS via URL parameters (CVE-2023-24488 style)

**Hardcoded Secrets (CWE-798)**
- API keys, passwords, tokens in source code

**Insecure Deserialization (CWE-502)**
- pickle.loads, yaml.load without safe_load
- Jackson-databind style patterns (CVE-2024-22855)

**Weak Cryptography (CWE-327/328)**
- MD5, SHA1 for password hashing

**SSRF (CWE-918)**
- Unvalidated URL fetching, requests to user-provided URLs

**XXE (CWE-611)**
- XML parsing with external entities enabled

### Authentication & Authorization

**Authentication Bypass**
- Missing auth checks on sensitive endpoints

**IDOR (CWE-639)**
- Resource access without ownership verification

**Mass Assignment**
- Direct request body to model without filtering

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
- TOCTOU race conditions (CVE style)
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

## CVE-Derived Patterns

Real-world vulnerability patterns inspired by actual CVEs:

| CVE | Pattern | Description |
|-----|---------|-------------|
| CVE-2023-34362 | MOVEit SQL injection | Request parameter in WHERE clause |
| CVE-2014-6271 | Shellshock | User input in shell command |
| CVE-2021-44228 | Log4Shell style | User input in log messages |
| CVE-2024-3094 | XZ Utils | Unsafe archive extraction |
| CVE-2024-22855 | Jackson-databind | Unsafe YAML deserialization |
| CVE-2023-24488 | Citrix XSS | Reflected XSS via URL param |
| Various | SSRF | Unvalidated URL requests |
| Various | Path Traversal | File access via user path |
| Various | Auth Bypass | Missing authentication checks |
| Various | IDOR | Missing ownership verification |
| Various | Mass Assignment | Unfiltered object assignment |
| Various | TOCTOU | Time-of-check to time-of-use |
| Various | Timing Attack | Non-constant time comparison |
| Various | Open Redirect | Unvalidated redirect URL |
| Various | Prototype Pollution | Unsafe object merge |

## Multi-File Scenarios

Context-dependent patterns that require understanding data flow across files:

| Scenario | Files | Pattern |
|----------|-------|---------|
| Go SQL Injection | handler.go → database.go | Input validation → parameterized query |
| Go Command Injection | handler.go → executor.go | User input → allowlist execution |
| Python SQL Injection | views.py → models.py | Validation → repository query |
| Python Path Traversal | views.py → validators.py | File request → path validation |
| TypeScript SQL Injection | api.ts → service.ts | API validation → DB query |
| TypeScript XSS | api.ts | Content rendering with sanitization |

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
5. For multi-file scenarios, ensure data flow is traceable across files
