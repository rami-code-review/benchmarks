# Claude Instructions for rami-benchmarks

This repository is **fixtures only** — clean source files plus ground truth. The runner, the defect templates, and the scorer all live in `rami-code-review` (`internal/benchmark/`). Nothing here executes.

## The invariant that breaks silently

A template injects by finding its `OriginalCode` string in a fixture file. **The trimmed line must match exactly.** Reformat a fixture, and its template stops matching — the benchmark reports a lower template count and scores fine. Nothing fails.

Before committing a fixture change, confirm the templates still match:

```
rami benchmark --source <path-to-this-repo> --dry-run --language <lang>
```

`--dry-run` runs injection only, no LLM calls, and prints per-language match rates. Anything below 100% for a language you touched means a fixture drifted from its template.

History: shell and infra fixtures sat on unmerged branches for two months while 17 templates matched 0%. Every run silently skipped two review domains. The dry-run is what surfaces that.

## Adding fixtures

1. Read the templates in `rami-code-review/internal/benchmark/templates.go` first — fixtures exist to satisfy templates, not the reverse. A fixture with no template is dead weight.
2. Add source containing the exact `OriginalCode` snippet.
3. Append the ground truth row to `expectedresults.csv`: `filename,test_id,cwe,category,expected,difficulty,language`. `expected` is `TP` (should be flagged), `FN` (defect injected, must be found), or `FP` (safe, must not be flagged).
4. Verify with `--dry-run`.

For false-positive templates, the fixture must be genuinely safe *and* superficially alarming. A safe pattern nothing would flag tests nothing.

For multi-file scenarios, the data flow has to be traceable across files — that is the property under test.

## Versioning

Tag as `vYYYYMMDD-N` after a content change. Benchmark runs record the corpus tag; results across different tags are not comparable, and the recorded tag is how a stored result stays interpretable later.

## Git identity

Commits use the repo owner's global git identity. A repo-local `user.name`/`user.email` override was in force from 2026-02 through 2026-08 and the history has been rewritten to remove it — do not reintroduce a local identity config.

## Scope

Fixtures, `expectedresults.csv`, and this file. Do not add tooling, CI, or scripts here; that belongs in `rami-code-review`.
