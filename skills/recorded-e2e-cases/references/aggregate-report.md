# Aggregate Replay Report

Use this reference when one recording source was replayed through several
sessions and therefore contains multiple `.replay/replay-report.json` files.

## Command

Call the repository-provided command from `PATH` with only the recording case
source root:

```bash
traffic-replay-aggregate \
  --case-source /path/to/recordings/<run-id>/<rule-or-collection> \
  --output /path/to/aggregate-report.json
```

The command recursively finds standard replay reports, including a report
nested under an individual case directory. It ignores `failed`, `staging`,
`.partial`, and `.truncated` trees. Do not enumerate report paths, copy reports,
or implement report parsing in the target repository.

## Coverage

The command discovers every published case containing `request.json` plus
`expected-response.json` (or tolerated `expected_response.json`) under the same
case source. It reports:

- `published_cases`: all valid published cases in the source
- `reported_cases`: unique cases present in discovered replay reports
- `unreported_cases`: published cases absent from every replay report
- `case_statuses`: reported `pending`, `active`, and `ended` counts

Each unreported case includes its directory and whether `dependencies.jsonl`
exists. Treat it as unreported evidence only. The aggregate tool cannot decide
whether it was intentionally excluded, lacks a business dependency, or was
never selected; the target E2E workflow must classify that from artifacts.

`complete: true` means every published case appears in a report and every
reported case ended. An ended case is not by itself proof that the target
project's response assertion passed.

## Dependency Counts

The aggregate sums the recorder-owned MySQL, HTTP, Redis, Memcached, and Kafka
matched, unmatched, unsupported, unsafe, unused-case, and unused-bootstrap
counters. `dirty` follows the raw recorder report semantics. Target-specific
noise policies or test-runner results remain outside this report and must not
be silently folded into its numbers.

Use `--fail-on-incomplete` when full published-case coverage is required. Use
`--fail-on-dirty` when the selected workflow requires strict raw dependency
cleanliness. The output is written before either gate returns a non-zero exit
status so the diagnostic artifact remains available.

## Validation

Fail instead of guessing when:

- the input is not a supported standard replay report version
- a published case is incomplete
- case ids are duplicated
- a report references a case not published under the supplied source
- a report or its declared `case_dir` escapes the supplied source

The command does not parse Cargo, Go, pytest, or other target-project output.
