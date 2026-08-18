# Claude Instructions for rami-benchmarks

**This repository is public.** Fixtures and ground truth only — no tooling, no scripts, no CI. Do not describe how the fixtures are consumed, name internal paths or commands, or record operational history here. That belongs in the private repo.

## Editing fixtures

Fixture files are matched against by exact content. **Never reformat, re-indent, or "clean up" a fixture file** — a formatting change silently detaches it from what consumes it, and nothing here will fail to tell you.

Change fixture code only when adding a case or correcting one that is genuinely wrong.

## Adding a case

1. Add source containing the pattern, in the appropriate language directory.
2. Append its ground-truth row to `expectedresults.csv`:
   `filename,test_id,cwe,category,expected,difficulty,language`
   where `expected` is `TP`, `FN`, or `FP`.

A false-positive case must be genuinely safe *and* superficially alarming. Safe code that nothing would flag tests nothing.

A multi-file case must keep its data flow traceable across files — that is the property under test.

## Versioning

Tag `vYYYYMMDD-N` after any content change. Results are only comparable within a tag.

## Git identity

Use the repo owner's global git identity. Never set a repo-local `user.name` or `user.email`.
