# Rami Benchmark Fixtures

Clean, safe source files that [Rami](https://rami.reviews) injects known defects into to measure its own code-review quality.

## Why this repository is public

The benchmark runner is part of Rami's hosted service and is not distributed, so you cannot clone this and reproduce a score.

What you *can* do is read the test set. Every defect Rami grades itself against is here, in plain source, with its ground truth in `expectedresults.csv`. A benchmark is only as honest as the cases it runs, and those are the easiest thing for a vendor to quietly stack. Publishing them means our quality claims can be inspected rather than believed.

## How it works

A defect template is an `OriginalCode` → `DefectiveCode` pair. The runner finds the original snippet in these files, swaps in the defective version to synthesize a pull request, asks Rami to review it, and scores the findings against what it injected.

Some templates are the reverse: `OriginalCode == DefectiveCode`, safe code that looks suspicious. Those measure false positives — whether Rami stays quiet when nothing is wrong.

## Coverage

484 templates across 11 languages.

| Language | Templates |
|---|---|
| TypeScript | 97 |
| Go | 95 |
| Python | 91 |
| Java | 72 |
| C# | 39 |
| JavaScript | 38 |
| Rust | 35 |
| Shell | 8 |
| Terraform | 4 |
| YAML | 3 |
| Dockerfile | 2 |

Defects span security (SQL/command injection, XSS, path traversal, SSRF, weak crypto, hardcoded secrets), error handling, null safety, logic, performance, and maintainability, with CWE identifiers recorded per case. Roughly two dozen are derived from real CVEs — Log4Shell, Shellshock, MOVEit, XZ Utils among them.

Beyond what static analysis reaches, a subset targets judgment: architectural design, test quality, framework misuse, async and concurrency reasoning. Traditional SAST tools score near zero on these; they are the reason an LLM reviewer exists.

Difficulty runs from single-line patterns through cross-function data flow to multi-file scenarios where the defect is only visible if you follow a value between files.

## Layout

```
go/  python/  typescript/  java/  javascript/  csharp/  rust/
shell/  infra/                    # shell scripts, Dockerfile, Terraform, Kubernetes
expectedresults.csv               # ground truth: file, test id, CWE, category, difficulty
```

## Versioning

Tagged as `vYYYYMMDD-N` (e.g. `v20260812-1`). A benchmark result is only meaningful next to the corpus tag it ran against — the corpus grows, so scores from different tags are not comparable.

## License

Apache-2.0. See [LICENSE](LICENSE).
