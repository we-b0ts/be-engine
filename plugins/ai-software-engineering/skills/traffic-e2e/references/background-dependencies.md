# Background Dependency Classification

Use when process-owned traffic is mixed into cases or must replay local state.

## Ownership Model

Classify by causality, not by timing alone:

- `runtime_state`: process work whose responses build response-driving local state;
- `independent`: process work unrelated to selected responses and side effects.

Apply `runtime_state` during response repair when evidence proves Replay must
serve it for target-local state. Classify `independent` only after responses
pass. Timing, a shared host, or an unused exchange is not ownership proof.

## Replay Scope

New recordings have two dependency scopes:

```text
<case>/dependencies.jsonl
<run>/global-dependencies.jsonl
```

Global contains startup and rule-matched dependencies. Exchanges are consumed
once; repeated scheduler cycles need repeated records. Replay prefers Case,
then Global.

Recorder adds:

```text
global_dependency_reason = bootstrap_window | background_rule
global_dependency_phase = bootstrap | runtime
global_dependency_matched_by = bootstrap_window | <rule-name>
```

Bootstrap rule matches use `reason=background_rule`, `phase=bootstrap`.
Unruled ready-time idle traffic stays only in `traffic.jsonl`. Replay has no
legacy bootstrap fallback.

## Supported Rules

The current narrow rule types are:

- exact HTTP authority, method, and path prefix with
  `response_role=independent`;
- Breeze-backed Memcached `get` with `response_role=runtime_state`, one exact
  resolved resource identity, and a bounded numeric key series
  `<start..end><separator><suffix>`.

Recorder counts completed replay-safe Memcached matches from process startup.
After HTTP ready, each applied rule must reach `end - start + 1` within
`initial_load_timeout_ms`; no rule means no wait. Count has no ordering or
deduplication. Replay does not wait for target-local initialization; repair
target startup or readiness when that causes a response difference.

Supply the logical resource to `plan|apply`. The tool requires one compatible
`mc` descriptor, persists its stable identity without the dynamic port, and
resolves the port at startup; it never creates descriptors. Runtime uses port
only as a coarse filter, then exact `get` and bounded key-series matching.

## Evidence-Gated Commands

Preview before applying:

```bash
traffic-e2e config recorder plan background-dependencies \
  --target-root . \
  --protocol memcached \
  --name planet-video-cache-warm \
  --breeze-resource user-video \
  --command get \
  --key-start 0 \
  --key-end 4095 \
  --key-separator . \
  --key-suffix pl_video \
  --initial-load-timeout-ms 30000 \
  --replay-report <finalized-replay-report.json> \
  --source-revision <lowercase-git-revision> \
  --evidence '<file>:<symbol> scheduled local-cache warm'
```

`apply` uses the same arguments. Planning requires a finalized replay report,
matching unused case exchanges, immutable case dependency records, a unique
Breeze descriptor, replay-safe keys and responses, and no same-port `get`
traffic reported as unmatched, unsupported, or unsafe. Apply rechecks the
config, report, case evidence, and descriptor port before its atomic write.
The timeout defaults to 30000 ms and starts when the source HTTP ready probe
succeeds; timeout is a Recorder readiness failure.

After any rule change, create a new standard recording. Never reclassify or
edit an existing artifact.
