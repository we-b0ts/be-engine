# Managed Recording

Use traffic-e2e-owned lifecycle commands. Always pass a unique UTC run ID, a
positive duration, and the narrow repeatable API scope. Retain the exact
finalized manifest returned by the command; never select a run by recency.

## Command

```bash
traffic-e2e record --target-root <target> \
  --run-id <YYYYMMDDHHMMSS> --duration-seconds 60 \
  --api '<METHOD path>'
```

For a short-lived recording performed directly in an existing host or
container environment, without Docker lifecycle management, start Source
through traffic-e2e:

```bash
traffic-e2e record-source --target-root <target> \
  --run-id <YYYYMMDDHHMMSS> --duration-seconds 60 \
  --api '<METHOD path>' -- <source-command> [args...]
```

`record-source` starts Recorder listeners first, then launches Source as the
fixed numeric identity `998:998` in the current network namespace. Source must
listen on the configured `http_gateway.matched_upstream` port, which must be
different from the recording gateway listen port. The command projects the
Recorder CA through common SDK trust variables and a Java truststore when
`keytool` is available. It stops Source after Recorder finalization and does
not provide post-recording passthrough. Omit `--api` to retain the configured
full recording scope for the complete duration.

This mode requires root or non-interactive sudo, `setpriv`, and the same
network capabilities required by local interception. It writes only to
`<target>/.traffic-e2e/local/artifacts/recordings/<run-id>` and rejects legacy
or custom artifact roots so backend-rewrite can consume the run directly.

Project config supplies the ignored initialization-owned source snapshot and
the configured startup inputs. traffic-e2e selects the runtime internally and
owns the adapted source, Recorder, readiness, finalization,
signals, and cleanup. It builds the capture-only source adaptor from the exact
snapshotted image. Do not generate or invoke repository recording wrappers.

The engine does not provision a Breeze sidecar or install Java class patches.
Application-specific source adaptation belongs to the reviewed recording
Dockerfile and explicit startup inputs. SDK and response rewrite policies are
independent of that startup contract.

The managed runtime retains a target-scoped adaptor image. Every managed run
loads the immutable image ID, effective environment, command, security
settings, and supported mounts from `.traffic-e2e/local/source/`; it never
reconnects to the initialization Pod. A missing adaptor or one labeled for
another source image or build-contract revision triggers a build/refresh.
Run-private build state and the temporary exact-image alias are removed during
cleanup. Do not retag or substitute the adaptor image.

The fixed adapter may only establish Platform transport interception. It must
not alter source business code, caches, feature switches, or response behavior.

Use `--per-api-case-limit` only as an invocation-local per-pattern bound. Do not edit recorder
scope for a temporary API selection. With explicit `--api` selectors, the
duration is an upper bound: Recorder finalizes normally when every selected API
reaches the bound. Without `--api`, Recorder observes the complete duration so
low-frequency APIs can still be discovered.

HTTP and Motan primary requests share one process-wide active-case slot. Only
one case across both protocols may own process dependencies at a time; an
overlapping matched request follows its gateway's configured non-admitted
response path and does not create another case.

When request-header encryption is configured, managed operations create and
reuse the mode-0600 project key at
`.traffic-e2e/local/secrets/traffic-e2e-enc.sec`; the AI does not provide it.
An explicit `TRAFFIC_E2E_ENCRYPTION_KEY_B64` is accepted only to initialize an
absent managed key and must decode to exactly 32 bytes. Never print or commit
the key, or inject it into source, target, commands, or policy.

## Recorder Rules

Change Recorder behavior only through supported evidence-gated commands such
as `traffic-e2e config recorder plan|apply`. Use Breeze resource capture only
after tracing a response-driving source hostname to a unique snapshot
descriptor. Use background attribution only after proving process ownership
and response causality. Every applied Recorder rule requires a new recording.

HTTP JSON responses that publish later IP URLs can use `http_response_rewrite`
rules with request authority/method/path and JSON `pointers`. No per-service
plugin is needed. In backend rewrite workflows, use the coordinator's
`unrecorded-ip` preflight and returned `recorder-capture plan-http-response`
command with source consumption proof. Apply requires fresh recording; never
patch old JSONL. Standard recording does not install Replay's outbound REJECT
policy, so rejection counters do not detect successful direct-IP recording
bypasses.

## Acceptance

Trust the finalized recording manifest and command exit status. A valid run is
completed, contains no failed cases/errors, and publishes canonical requests,
expected responses, semantic dependencies, and summaries for selected cases.
An empty semantic dependency stream can be valid explicit evidence; missing,
partial, truncated, unsafe, or failed artifacts are not.

Do not inspect every case or large report. Use `prepare` and managed E2E to
consume finalized cases. Use protocol/debug artifacts only for a proven
traffic-e2e system investigation.
