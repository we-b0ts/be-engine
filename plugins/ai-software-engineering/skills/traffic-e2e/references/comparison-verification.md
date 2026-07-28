# Comparison Recording Verification

Use this reference only after the selected target behavior passes genuine
dependency replay E2E. Comparison recording is a second verification phase
against frontend traffic; it does not replace replay evidence.

## Contents

- Runtime boundary
- Artifacts and command
- Required diagnosis
- Evidence-backed policy feedback
- Completion

## Runtime Boundary

Run the genuine source and candidate services normally. Neither
`record-comparison` nor `compare` may enable the fixed recording user,
DNS/iptables interception, fake-IP routing, MITM, dependency replay, or any
other isolation workflow.

When the target repository provides `scripts/start-recording-comparison`, use
that script as the normal entrypoint. Do not reconstruct its source startup,
candidate startup, recording, signal forwarding, finalization, or cleanup
lifecycle in the task. The script and direct `record-comparison` command default
to 60 seconds. AI and automated invocations must explicitly pass
`--duration-seconds 60` or another positive integer.

When `recording.encrypt_request_headers` is nonempty, comparison recording
requires the same `TRAFFIC_E2E_ENCRYPTION_KEY_B64` contract as standard
recording. The repository wrapper preserves it only for the host
`record-comparison` process and never prints it or injects it into source,
candidate, Breeze, or other services. Missing or invalid key material must
fail before the comparison run directory is created.

For Platform repositories, the wrapper starts one Breeze instance and connects
both source and candidate containers to it. It accepts
`--brz-no-fallback <true|false>`, defaults it to `true`, and consumes it
locally; never forward this wrapper-only option to `traffic-e2e
record-comparison`. When enabled, the repository's
`scripts/brz-no-fallback.sh` applies the application-side fallback switches
after the relevant application control endpoint is ready. These fixed Breeze
transport switches do not authorize disabling caches, changing business
fallback, or modifying any other source feature switch.

Use repeatable `--api 'METHOD /path-or-pattern'` arguments when the affected
scope is known. These selectors apply only to that invocation, are intersected
with the configured HTTP rules, define the selected cases' API grouping, and
are recorded in the run summary. Do not edit recorder TOML or create a
plan/apply step for this temporary scope.

Comparison recording accepts only explicitly configured `GET`, `HEAD`, and
`OPTIONS` rules. A non-read method is a configuration error because forwarding
one request to both services could duplicate a side effect.

The default recording sends the request once to the source baseline and once
to the candidate:

```text
source baseline -> candidate
```

Set `[comparison_recording].baseline_recheck = true` or pass the enable-only
`record-comparison --baseline-recheck` flag only when an additional source
observation is useful. The recorder then preserves this order:

```text
source before -> candidate -> source after
```

The frontend receives the first source response without waiting for the
candidate or source recheck. The optional recheck increases source traffic and
is diagnostic evidence, not proof that the source is deterministic.

## Artifacts And Command

One published case contains:

```text
request.json
expected-response.json        # source before
response.json                 # candidate
expected-response-after.json  # optional source after
```

The recorder normalizes each captured response body according to its own HTTP
`Content-Encoding` before writing these artifacts. A compressed source response
and an uncompressed candidate response are therefore compared by decoded body
semantics; their transport encodings do not need to match. A truncated body,
unsupported content encoding, or decoding failure makes the case unevaluable
instead of falling back to compressed-byte comparison.

After clean finalization, run:

```bash
traffic-e2e compare \
  <comparison-recording-run> \
  --policy <target>/.traffic-e2e/verification.yaml
```

The command is file-only. It applies only `response_rules`; dependency replay
rules are ignored. Preserve the generated `comparison-report.json` and the
policy fingerprint used to produce it. The report groups cases by canonical
`METHOD + api_pattern` and publishes `apis_total`, `apis_passed`, and
`apis_failed`; an API passes only when all of its comparison cases pass.

## Required Diagnosis

Classify every non-passing case from artifacts and source ownership. Never
change code or policy from a scalar mismatch alone.

1. **Candidate implementation difference.** The report compares
   source-before/candidate differences with source-before/source-after changes.
   Any candidate difference not covered by a source change at the same JSON
   Pointer or overlapping parent/child location remains in
   `candidate_only_pointers` and classifies the case as
   `candidate_difference`. An unrelated source change never hides it. Inspect
   source and candidate code, configuration, dependency wiring, and response
   construction. Return a source-contract violation as `target_behavior`;
   after the calling orchestrator repairs it, pass replay E2E again before
   making a new comparison recording. If the API has no valid standard E2E
   case, capture a standard recording and establish a passing replay contract
   before prescribing implementation from comparison artifacts.
2. **Source change between observations.** `source_change` is an observed
   comparison condition, not a root cause or exemption. Use it only when every
   candidate difference is covered by a source-before/source-after difference
   at the same response location. The report must retain
   `source_change_pointers`; a source-only change is diagnostic when the
   candidate otherwise matches and does not make the case fail. For a
   classified source change, report one representative case with API, case ID,
   Pointer, difference kind, redacted source-before/source-after examples, and
   confirmation that `candidate_only_pointers` is empty. Resolve ownership and
   timing, then record again in a quiet or snapshot-consistent window or use a
   domain-specific comparison strategy. Keep the operation `action_required`;
   do not call it `incomplete`, attribute it to candidate code, or add a
   blanket exemption.
3. **Intentional non-determinism.** Only after source review proves that an
   exact scalar is generated from current time, duration, random/UUID/nonce
   behavior, or that an array has no business ordering, use an evidence-backed
   `dynamic` or `unordered` response rule. Apply it to the shared verification
   policy, rerun replay E2E for the affected API, and create a new comparison
   report. Process-local cache state is target behavior, not intentional
   non-determinism; cache hit, miss, staleness, refresh, warmup, or missing
   implementation must never be exempted.

Useful interpretation of the optional source recheck:

- no source-after artifact: `candidate_difference` identifies a mismatch but
  provides no source-stability evidence; inspect source ownership and timing
  before attributing it;
- source-before equals source-after, candidate differs: stronger candidate
  difference evidence, but still inspect code and environment;
- source-before differs from source-after at an unrelated location: retain the
  candidate-only difference and diagnose target behavior;
- source-before differs from source-after at every candidate-difference
  location: field-scoped `source_change`, still not a cause or exemption;
- all three differ at the same location: keep the field inconclusive until
  ownership and mechanism are proven;
- source-before equals source-after by chance: still possible for random or
  periodic fields, so source semantics remain required.

An applicable response rule is unused for a comparison case only when neither
the candidate leg nor the optional source-recheck leg exercises it. One leg
remaining exact does not make a rule stale when the other leg uses it. A rule
unused by both legs is `policy_mismatch`, not source change or candidate
behavior. Preserve this diagnostic alongside any independent candidate
difference, remove or replace the stale rule through evidence-backed policy
feedback, rerun affected replay E2E, and create a new comparison recording.

## Evidence-Backed Policy Feedback

After diagnosis proves an existing supported rule is correct:

```bash
traffic-e2e config replay apply response-rule \
  --target-root <target> \
  --kind dynamic \
  --dynamic-mechanism uuid \
  --source-evidence 'src/token.rs:issue_token UUID generation' \
  --source-example '<redacted UUID from source>' \
  --target-example '<redacted UUID from target>' \
  --api 'GET /api/resource/token' \
  --json-pointer /content \
  --comparison-report <comparison-recording-run>/comparison-report.json
```

Use `--kind unordered` only for a proven order-insensitive array. The operation
must remain additive, narrow, and backed by the current policy fingerprint.
Never use response rules for ordinary mutable business data, missing fields,
wrong types, status differences, dependency/configuration defects,
process-local cache differences, or broad subtrees. Do not exempt a whole
scalar containing stable structure when only one component is dynamic.

## Completion

Comparison verification is complete only when the recording finalized cleanly,
every published case was evaluated, no case remains classified
`source_change`, `policy_mismatch`, or `unevaluable`, every affected API and
candidate comparison passes under the reviewed policy, and the latest
candidate code still passes the affected replay E2E scope. A source-only change
recorded as diagnostics does not invalidate an otherwise exact candidate
match. This comparison report is the validation-success authority. It is
current evidence, not a permanent API-verified state. After every code or
policy change, use a new comparison recording; never overwrite or reinterpret
the old candidate response as fresh evidence.
