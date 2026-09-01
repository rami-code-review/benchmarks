# Rami Benchmark Fixtures

Clean, safe source files that [Rami](https://rami.reviews) injects known defects into to measure its own code-review quality.

## Why this repository is public

The tooling that consumes these fixtures is part of Rami's hosted service and is not distributed, so you cannot clone this and reproduce a score.

What you *can* do is check the test set. A benchmark is only as honest as the cases it runs, and those are the easiest thing for a vendor to quietly stack — with a corpus of trivial one-token mutations, a high score means nothing. So both halves are here: the safe source in the language directories, and every defect injected into it in `corpus.json`.

## How it works

Each case pairs a safe snippet with a defective variant of it. Rami locates the safe snippet in these files, substitutes the defect, synthesizes a pull request from the result, reviews it, and scores what it found against what it planted.

Other cases invert that: the code stays correct, or is rewritten into a different correct form, and the expected result is silence. Those measure false positives.

## Checking the corpus yourself

`corpus.json` carries all 586 cases — every one, unfiltered — each with the exact code before and after:

```json
{
  "id": "sh-unsafe-rm-high",
  "language": "shell",
  "category": "security",
  "severity": "High",
  "difficulty": "medium",
  "description": "Unquoted, unguarded rm -rf: an empty or unset $BUILD_DIR expands to 'rm -rf /dist'",
  "safe_code": "rm -rf \"${BUILD_DIR:?}/dist\"",
  "defective_code": "rm -rf $BUILD_DIR/dist",
  "expects_no_finding": false
}
```

`safe_code` appears verbatim in the fixture file for that language, so you can find it, apply the substitution by hand, and see the pull request Rami was asked to review. From there you can judge whether a case is a real defect or a token swap, whether the difficulty labels are honest, and how much of the corpus is made of the easy kind.

62 of the 586 are the opposite test, flagged `expects_no_finding`: the code stays correct and the expected result is silence. Their diffs are ordinary refactors — a local extracted, a body reflowed — with nothing in them that hints at the answer, so a reviewer has to read the code to stay quiet.

**What this does not establish.** That a published number came from this corpus, and that the scoring was fair. Both need the runner, which is not distributed. Read the cases and decide what a score against them would be worth — that judgment is the point, and it is the part we can hand you.

For a stronger check, point Rami at your own repository and read the review.

## Coverage

586 cases across 11 languages, every one of which runs.

| Language | Cases |
|---|---|
| Go | 146 |
| TypeScript | 133 |
| Python | 101 |
| Java | 72 |
| C# | 39 |
| JavaScript | 38 |
| Rust | 34 |
| Shell | 12 |
| Terraform | 6 |
| YAML | 3 |
| Dockerfile | 2 |

Defects span security (SQL/command injection, XSS, path traversal, SSRF, weak crypto, hardcoded secrets), error handling, null safety, logic, performance, and maintainability, with CWE identifiers recorded per case. Roughly two dozen are derived from real CVEs — Log4Shell, Shellshock, MOVEit, XZ Utils among them.

The mix is weighted toward what breaks real code rather than what reads well in a security syllabus: a discarded error return, a context that defeats cancellation, a `defer` inside a loop, a non-null assertion on a match that returns null, a fresh object built during render. Those are the shapes that get written and later fixed, so they are the shapes a reviewer has to catch.

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
