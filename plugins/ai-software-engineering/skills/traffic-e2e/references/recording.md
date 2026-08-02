# Managed Recording

Use traffic-e2e-owned lifecycle commands. Always pass a unique UTC run ID, a
positive duration, and the narrow repeatable API scope. Retain the exact
finalized manifest returned by the command; never select a run by recency.

## Command

```bash
traffic-e2e record --target-root <target> \
  --run-id <YYYYMMDDHHMMSS> --duration-seconds 60 \
  --brz-no-fallback true --api '<METHOD path>'
```

Project config supplies the existing source container and optional Breeze
container. traffic-e2e selects the runtime internally and owns source,
Recorder, optional Breeze, readiness, finalization, signals, and cleanup. For
Platform Java/Tomcat it builds its capture-only source adapter. Do not generate
or invoke repository recording wrappers.

The fixed adapter may only establish Platform transport interception. It must
not alter source business code, caches, feature switches, or response behavior.

Use `--case-limit` only as an invocation-local bound. Do not edit recorder
scope for a temporary API selection.

When request-header encryption is configured,
`TRAFFIC_E2E_ENCRYPTION_KEY_B64` must decode to exactly 32 bytes. Keep it only
in the Recorder/record-comparison process environment; never print it, commit
it, or inject it into source, target, Breeze, commands, or policy.

## Recorder Rules

Change Recorder behavior only through supported evidence-gated commands such
as `traffic-e2e config recorder plan|apply`. Use Breeze resource capture only
after tracing a response-driving source hostname to a unique snapshot
descriptor. Use background attribution only after proving process ownership
and response causality. Every applied Recorder rule requires a new recording.

## Acceptance

Trust the finalized recording manifest and command exit status. A valid run is
completed, contains no failed cases/errors, and publishes canonical requests,
expected responses, semantic dependencies, and summaries for selected cases.
An empty semantic dependency stream can be valid explicit evidence; missing,
partial, truncated, unsafe, or failed artifacts are not.

Do not inspect every case or large report. Use `prepare` and managed E2E to
consume finalized cases. Use protocol/debug artifacts only for a proven
traffic-e2e system investigation.
