# Traffic E2E Replay-Verified API Excludes

Use this gate only after a terminal API attempt has finalized and its aggregate
and response assertions exist. `traffic-e2e run` and focused `run-api`
invoke it only for APIs whose runner-owned streaks meet both effective
thresholds.

## Ownership

Keep the API verification policy in target `.traffic-e2e/e2e.yaml`:

```yaml
api_verification:
  consecutive_successful_runs: 3
  successful_cases: 3
  overrides:
    GET /api/widgets/*:
      consecutive_successful_runs: 5
      successful_cases: 200
```

`successful_cases` counts canonical cases covered by the same trailing
successful distinct published runs. Replaying one run does not advance either
threshold. The top-level values are defaults; a canonical
`METHOD path_pattern` override replaces both thresholds for that exact API.
Keep only the verified API list in `.traffic-e2e/recorder.toml`:

```toml
[http_gateway.verified_excludes]
# BEGIN AI-MANAGED VERIFIED API EXCLUDES
apis = [
]
# END AI-MANAGED VERIFIED API EXCLUDES
```

MUST NOT put this policy or exclusion list in `.traffic-e2e/replay.yaml`. Replay
policy owns dynamic dependency matching only.

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
replay-policy evidence with zero unused applicable rules. The `traffic-e2e`
runner uses `expected-response.json` only for final assertions. Under version
two, the target facade MUST NOT read it.

The runner owns cumulative successful-run and covered-case streaks. An API's
unsuccessful final contribution in a distinct run resets both; retry attempts
within that run replace its contribution. The recorder command independently
verifies that every current matching case is present and passed, so
selected-case omission cannot satisfy the gate.

## Gate

The standard runner persists the JSON ensure report after both evidence views
exist. The equivalent low-level diagnostic command is:

```bash
traffic-e2e diagnose recorder-config \
  --config .traffic-e2e/recorder.toml \
  verified-excludes ensure \
  --rule <recording-rule> \
  --method <METHOD> \
  --pattern '<exact-or-recorder-path-pattern>' \
  --aggregate-report <aggregate.json> \
  --assertion-report <assertions.json> \
  --consecutive-successful-runs <actual-runs> \
  --consecutive-successful-cases <actual-cases> \
  --required-consecutive-successful-runs <required-runs> \
  --required-successful-cases <required-cases> \
  --format json
```

- `below_threshold`: retain the runner-supplied threshold/count evidence; no
  config write occurs.
- `applied`: require the embedded apply report and a verification plan with
  `changed: false`.
- `already_present`: the initial plan already proves no diff.
- incomplete/dirty/mismatched evidence or an assertion-only violation fails
  the command and is blocked.
- missing managed config is
  `not_applicable_missing_verified_excludes_config`, never generic skipped.

MUST NOT parse `eligible` and choose whether to call `apply` in AI logic,
shell, or target-language code. The runner owns counters and calls `ensure`;
`ensure` validates the supplied gate, owns atomic apply, and verifies final
convergence. Keep `plan` and `apply` only for human diagnostics.

An applied entry is keyed by recording rule, method, and path pattern. Exact
paths, whole-segment `*`, and a final `**` catch-all are supported with the same
semantics as canonical API groups: `*` matches one non-empty segment and a final
`**` matches one or more remaining segments. It takes effect after the recorder
reloads the updated config; matching requests use `fallback_upstream` and
create no case. The managed operation is add-only and never deletes exclusions
automatically.
