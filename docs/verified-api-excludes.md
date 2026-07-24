# Verified API Excludes

Use verified API excludes to stop recording an API only after enough trailing
rounds and case executions have passed both dependency replay and target
response assertions.

Verification policy belongs in the target traffic E2E configuration:

```yaml
api_verification:
  consecutive_successful_runs: 3
  successful_cases: 3
  overrides:
    GET /api/widgets/*:
      consecutive_successful_runs: 5
      successful_cases: 200
```

`successful_cases` is the minimum number of case executions covered by the
same trailing successful rounds. The top-level values are defaults; an exact
`METHOD path_pattern` override replaces both values for that API. A failed API
round resets both streaks.
The recorder configuration stores only APIs that already reached this gate:

```toml
[http_gateway.verified_excludes]
# BEGIN AI-MANAGED VERIFIED API EXCLUDES
apis = [
]
# END AI-MANAGED VERIFIED API EXCLUDES
```

Do not put verification policy or API exclusions in `.traffic-e2e/replay.yaml`.
Replay policy owns dynamic dependency matching only.

## Success Evidence

For one exact `rule + method + path_pattern`, the recorder-owned command
requires two artifacts covering the same complete case set:

- a `traffic-e2e diagnose replay-aggregate` report with `version: 1` that is
  complete and clean;
  every included replay report must carry validated `assertions_only` replay
  policy evidence with no unused applicable rule;
- a target-owned response assertion report in this format:

```json
{
  "version": 1,
  "case_source": "/absolute/path/to/the/case-source",
  "expected_response": "assertions_only",
  "cases": [
    { "case_id": "case-1", "passed": true },
    { "case_id": "case-2", "passed": true },
    { "case_id": "case-3", "passed": true }
  ]
}
```

The target runner must generate this report from its final assertion path. It
must not generate actual responses, dependency mocks, inputs, branches,
caches, or side effects from `expected-response.json`.

The command discovers every published case under the aggregate `case_source`
whose recorded `matched_rule`, method, and URI match the candidate. Both
reports must cover exactly that set and every current assertion must pass.
Dirty or incomplete replay never qualifies. The traffic E2E runner supplies the
cumulative streak counters from its run index; the recorder does not maintain a
competing threshold.

## Ensure

After both final evidence artifacts exist, run one deterministic command:

```bash
traffic-e2e diagnose recorder-config \
  --config ../target/.traffic-e2e/recorder.toml \
  verified-excludes ensure \
  --rule record-api \
  --method GET \
  --pattern '/api/users/*' \
  --aggregate-report ../target/.traffic-e2e/run-reports/run.json \
  --assertion-report ../target/.traffic-e2e/run-reports/assertions.json \
  --consecutive-successful-runs 3 \
  --consecutive-successful-cases 9 \
  --required-consecutive-successful-runs 3 \
  --required-successful-cases 3 \
  --format json
```

`traffic-e2e` calls this operation automatically only after updating its
runner-owned counters. The low-level command above is for diagnostics and
requires those counters explicitly.

The command returns `below_threshold` without writing, `already_present` when
the exact entry exists, or `applied` after it atomically updates the managed
block and reruns the plan to prove there is no remaining diff. Dirty,
incomplete, mismatched, or non-assertion-only evidence fails instead of being
treated as below threshold. The JSON output embeds the initial plan, apply
result, and verification result when applicable.

`plan` and `apply` remain available for diagnostics. Normal automation must
call `ensure`; the AI supplies the source-resolved `rule + method +
path_pattern` and evidence paths but does not decide eligibility or whether to
apply.

The command only adds entries inside the explicit managed block, validates the
entire TOML, rejects config or evidence artifacts changed after planning, and
replaces the config atomically. It does not modify recordings. Exact paths,
whole-segment `*`, and a final `**` catch-all are supported. `*` matches one
non-empty segment; a final `**` matches one or more remaining segments. The
entry also references its original recording rule, so that rule's host, header,
and path-prefix scope still applies.

An applied entry takes effect when the recorder next loads the updated config.
Matching requests use the configured fallback strategy and do not create new
cases. Removing or temporarily disabling an exclusion is a separate reviewed
operation; the managed operation never deletes entries automatically.
