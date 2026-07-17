# Replay-Verified API Excludes

Use this gate only after a full E2E round has finalized and its global aggregate
and response assertions exist. `traffic-e2e-run run` invokes it once per API
from the same terminal round. Focused `run-api` attempts MUST NOT invoke it.

## Ownership

Keep N in target `recorder.toml` because reaching N changes the next recording
scope:

```toml
[http_gateway.verified_excludes]
consecutive_successes = 3
# BEGIN AI-MANAGED VERIFIED API EXCLUDES
apis = [
]
# END AI-MANAGED VERIFIED API EXCLUDES
```

MUST NOT put this threshold or exclusion list in `replay.yaml`. Replay policy
owns dynamic dependency matching only.

## Required Evidence

The runner creates a target-local JSON assertion report from the final
assertion path:

```json
{
  "version": 1,
  "case_source": "/absolute/canonical/case-source",
  "expected_response": "assertions_only",
  "cases": [
    { "case_id": "case-1", "passed": true }
  ]
}
```

The assertion report and final recorder aggregate MUST cover the same complete
set returned by canonical API grouping. The aggregate MUST be complete and
clean, and every included replay report MUST contain validated assertion-only
replay-policy evidence with zero unused applicable rules. The target runner
MUST NOT use `expected-response.json` outside final assertions.

The recorder command reads each matching request's `timestamp`, orders cases,
and counts only the trailing consecutive `passed: true` results. A latest
failure resets the count. It independently verifies every matching case is
present, so selected-case omission cannot satisfy N.

## Gate

The standard runner persists the JSON ensure report after both evidence views
exist. The equivalent low-level diagnostic command is:

```bash
traffic-recorder-config verified-excludes ensure \
  --config config/recorder.toml \
  --rule <recording-rule> \
  --method <METHOD> \
  --pattern '<exact-path-or-segment-pattern>' \
  --aggregate-report <aggregate.json> \
  --assertion-report <assertions.json> \
  --format json
```

- `below_threshold`: retain the recorder-computed threshold/count; no config
  write occurs and migration completion is not blocked.
- `applied`: require the embedded apply report and a verification plan with
  `changed: false`.
- `already_present`: the initial plan already proves no diff.
- incomplete/dirty/mismatched evidence or an assertion-only violation fails
  the command and is blocked.
- missing managed config is
  `not_applicable_missing_verified_excludes_config`, never generic skipped.

MUST NOT parse `eligible` and choose whether to call `apply` in AI logic,
shell, or target-language code. `ensure` owns plan, threshold decision, atomic
apply, and final convergence verification. Keep `plan` and `apply` only for
human diagnostics.

An applied entry is keyed by recording rule, method, and exact or
whole-segment-`*` path pattern. It takes effect after the recorder reloads the
updated config; matching requests use `fallback_upstream` and create no case.
Version one is add-only and never deletes exclusions automatically.
