# Aggregate Replay Report

Use this reference for every collection/run source, multi-case selection, or
recording source replayed through several reports/sessions. The only allowed
exemption is one published case replayed in exactly one session/report; record
that exact reason as `not_applicable_single_case_single_session`.

## Command

Call the repository-provided command from `PATH` with only the recording case
source root:

```bash
traffic-replay-aggregate \
  --case-source /path/to/recordings/<run-id>/<rule-or-collection> \
  --case-id <selected-case-id> \
  --session-id <final-session-id> \
  --output /path/to/aggregate-report.json \
  --fail-on-incomplete \
  --fail-on-dirty
```

Repeat `--case-id` and `--session-id` for the exact completion set. The command
recursively finds standard reports, including retained reports under
`.replay/sessions/`. It ignores `failed`, `staging`, `.partial`, and
`.truncated` trees. Do not enumerate report paths, copy reports, or implement
report parsing in the target repository.

## Coverage

The supplied root defines the publishing boundary of the completion claim, and
the repeated `--case-id` values define the exact in-scope subset. Do not omit
`--case-id` and then claim an intentionally replayed subset passed. The command
discovers every published case containing `request.json` plus
`expected-response.json` (or tolerated `expected_response.json`) under the same
case source, validates every selected id, and reports:

- `published_cases`: valid selected cases, or all valid cases without filters
- `reported_cases`: unique selected cases present in the selected reports
- `unreported_cases`: in-scope published cases absent from selected reports
- `case_statuses`: reported `pending`, `active`, and `ended` counts

Each unreported case includes its directory and whether `dependencies.jsonl`
exists. Treat it as unreported evidence only. The aggregate tool cannot decide
whether it was intentionally excluded, lacks a business dependency, or was
never selected; the target E2E workflow must classify that from artifacts.

`complete: true` means every in-scope published case appears in a report, every
reported case ended, and every selected version-five report was finalized.
Retained reports that overlap the same case require exact session selection;
the session filter is applied before case-set validation so unrelated historical
attempts cannot satisfy or invalidate the selected evidence. The aggregate
command never guesses which attempt is final. An ended case is not by itself
proof that the target project's response assertion passed.

## Dependency Counts

The aggregate sums the recorder-owned MySQL, HTTP, Redis, Memcached, and Kafka
matched, unmatched, unsupported, unsafe, unused-case, and unused-bootstrap
counters. `dirty` follows the raw recorder report semantics. Target-specific
noise policies or test-runner results remain outside this report and must not
be silently folded into its numbers.

Version five replay reports retain only a bounded prefix of successful event
details. The aggregate MUST use their explicit success counters, not the
retained array lengths. Dirty and unused arrays remain complete evidence.

Completion runs MUST use both `--fail-on-incomplete` and `--fail-on-dirty`.
The output is written before either gate returns a non-zero exit status so the
diagnostic artifact remains available. A diagnostic report produced by a
failing invocation is not passing evidence.

## Validation

Fail instead of guessing when:

- the input is not a supported standard replay report version
- a published case is incomplete
- case ids are duplicated
- a report references a case not published under the supplied source
- a report or its declared `case_dir` escapes the supplied source

The command does not parse Cargo, Go, pytest, or other target-project output.
