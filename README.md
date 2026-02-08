# Rami Benchmark Fixtures

Source code samples for benchmarking Rami's code review quality. Based on OWASP Benchmark methodology with balanced true positive/false positive test cases.

## Structure

```
├── go/                    # 61 templates
│   ├── patterns.go        # Main pattern fixtures
│   ├── database.go        # Database ops (SQL injection, secrets, crypto)
│   ├── service.go         # Business logic (race conditions, nil safety)
│   ├── cve_patterns.go    # CVE-derived vulnerability patterns
│   ├── design_patterns.go # LLM-advantage: architecture/design issues
│   ├── async_patterns.go  # LLM-advantage: concurrency patterns
│   └── multifile/         # Multi-file context-dependent scenarios
├── python/                # 71 templates
│   ├── patterns.py        # Main patterns + Django/Flask/FastAPI
│   ├── database.py        # Database patterns
│   ├── cve_patterns.py    # CVE-derived patterns
│   ├── test_quality.py    # LLM-advantage: test code quality issues
│   └── multifile/         # Multi-file scenarios
├── typescript/            # 65 templates
│   ├── patterns.ts        # Main patterns + React/Next.js
│   ├── components.tsx     # React components (XSS, null safety)
│   ├── cve_patterns.ts    # CVE-derived patterns
│   ├── framework_patterns.ts # LLM-advantage: React/Express misuse
│   └── multifile/         # Multi-file scenarios
├── java/                  # 61 templates
│   ├── patterns.java      # Main patterns (Spring, JDBC, JPA)
│   └── cve_patterns.java  # Log4Shell, Struts, Spring4Shell
├── javascript/            # 39 templates
│   └── patterns.js        # Prototype pollution, eval, DOM XSS, NoSQL
├── csharp/                # 40 templates
│   └── patterns.cs        # ASP.NET, Entity Framework, SqlCommand
├── rust/                  # 33 templates
│   └── patterns.rs        # Unsafe blocks, memory safety, concurrency
├── expectedresults.csv    # OWASP-style ground truth (346 entries)
├── LICENSE                # Apache-2.0
└── README.md
```

## Overview

These files contain clean, safe code patterns that match Rami's defect injection templates.
The benchmark system injects known vulnerabilities and bugs into these files, then measures
how well Rami detects them.

## Template Coverage

| Language   | Templates | Categories |
|------------|-----------|------------|
| Python     | 71        | Django/Flask/FastAPI, SSTI, pickle, asyncio, test quality |
| TypeScript | 65        | React/Next.js, Prisma/TypeORM, Express middleware, framework misuse |
| Java       | 61        | SQL injection, command injection, deserialization, XSS, Log4Shell, Spring4Shell |
| Go         | 61        | security, error-handling, null-safety, logic, design patterns, async |
| C#         | 40        | ASP.NET, Entity Framework, BinaryFormatter, SqlCommand |
| JavaScript | 39        | prototype pollution, eval injection, DOM XSS, NoSQL injection |
| Rust       | 33        | unsafe blocks, memory safety, concurrency, FFI |

**Total: 370 templates** including:
- 37 LLM-advantage templates (design, test quality, framework, async)
- 21 false positive test cases (safe patterns that shouldn't trigger)
- 10+ multi-file context-dependent scenarios
- 25+ CVE-derived real-world patterns

## Difficulty Tiers

| Tier   | Description | Examples |
|--------|-------------|----------|
| Easy   | Single-line patterns | Direct SQL concatenation, hardcoded secrets |
| Medium | Multi-line context | Builder patterns, error shadowing |
| Hard   | Cross-function | Indirect injection via variable, caller contracts |
| Expert | Multi-file/CVE | Data flow across files, real-world vulnerability patterns |

## LLM-Advantage Categories

These categories differentiate LLM code review from traditional SAST tools (which score 0-10% on these patterns):

| Category | SAST Score | Description | Examples |
|----------|------------|-------------|----------|
| Design | ~0% | Architecture/design issues | God objects, circular dependencies, wrong patterns |
| Test Quality | ~0% | Test code issues | No assertions, mocking SUT, flaky tests, misleading names |
| Framework | ~10% | Framework misuse | React hooks violations, Express middleware errors, Django N+1 |
| Async | ~5% | Async/concurrency reasoning | Goroutine leaks, race conditions, fire-and-forget promises |

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

## Expected Results (Ground Truth)

The `expectedresults.csv` file contains OWASP-style ground truth for all templates:

```csv
filename,test_id,cwe,category,expected,difficulty,language
go/patterns.go,go-sqli-concat-easy,CWE-89,sql-injection,FN,easy,go
java/patterns.java,java-log4shell-lookup,CWE-917,logging,TP,hard,java
```

- **expected=TP** (True Positive): Rami should detect this vulnerability
- **expected=FN** (False Negative): Defect injected, Rami should find it
- **expected=FP** (False Positive): Safe code, Rami should NOT flag it

## Adding New Fixtures

1. Check available templates in `rami-code-review/internal/benchmark/templates.go`
2. Add source files containing the **exact** `OriginalCode` patterns (trimmed lines must match)
3. The benchmark tool will automatically detect and inject defects
4. For false positive tests, include the "safe but suspicious" pattern
5. For multi-file scenarios, ensure data flow is traceable across files
6. Update `expectedresults.csv` with the new test case ground truth

## License

Apache-2.0. See [LICENSE](LICENSE) for details.
