# Platform Standard Recording

Use this reference after [platform-runtime.md](platform-runtime.md) when
generating or validating `scripts/start-recording`.

## Contents

- Wrapper contract
- Lifecycle
- Validation

## Wrapper Contract

Implement `scripts/start-recording` from the inspected source and Breeze
parameters. Different Platform services may use different images, environment,
`NAME_CONF`, Breeze service pools, mounts, or root bootstrap commands; preserve
that evidence instead of forcing one universal Docker command.

Copy `assets/recording/brz-no-fallback.sh` unchanged to
`scripts/brz-no-fallback.sh`. Do not inline, reconstruct, or depend on a
host-installed copy of this script.

The generated script must accept:

```bash
./scripts/start-recording
./scripts/start-recording --run-id YYYYMMDDHHMMSS
./scripts/start-recording --duration-seconds <positive-integer>
./scripts/start-recording --brz-no-fallback <true|false>
./scripts/start-recording --api 'GET /api/widgets/*'
./scripts/start-recording --case-limit <positive-integer>
```

Default `brz_no_fallback` to `true`. Accept only the literal values `true` and
`false`. Default `duration_seconds` to `60` when omitted. AI and automated
invocations must explicitly pass `--duration-seconds 60` or another positive
integer. When provided, require `--run-id` to be a valid 14-digit UTC
timestamp. Reject missing option values, invalid values, or duplicate options
before changing runtime state, allow all options to combine, accept repeatable
canonical `--api` selectors, accept one optional positive `--case-limit`, and
pass the run ID, API selectors, and case limit through unchanged to
`traffic-e2e record`.

Require `TRAFFIC_E2E_ENCRYPTION_KEY_B64` during the same argument validation
and verify, without printing decoded bytes, that it is strict Base64 for
exactly 32 bytes. Pass it to the Recorder container with an explicit
`--env TRAFFIC_E2E_ENCRYPTION_KEY_B64`; do not pass it to Anchor, Breeze, or
the source. Recorder independently repeats key validation, and the wrapper
must preserve its startup failure and never log the value.

Before starting containers, capture `artifact_owner="$(id -u):$(id -g)"` in
the host wrapper and add `--artifact-owner "$artifact_owner"` to the Recorder
arguments. Do not expose a wrapper override, derive the value inside the root
container, use numeric `998:998`, or normalize ownership with a post-run
"newest directory" scan. Recorder owns the exact run path and must recursively
assign that tree after its writers flush and final metadata is persisted.

Require `nc` and an executable repository copy of the asset during argument
validation. When `brz_no_fallback` is true, run the repository's
`scripts/brz-no-fallback.sh` immediately after source port `880` becomes
available. The fixed script changes only Breeze Mesh transport fallback; it
does not authorize disabling application caches, business fallback, or other
feature switches. When false, do not execute it.

## Lifecycle

Use this fixed lifecycle:

1. validate arguments and the encryption-key environment, capture the host
   artifact owner, and create ignored runtime directories;
2. build the source adapter with `--network none`;
3. prepare stable private recording bind sources and normalize the three
   shared Breeze directories to `998:998`;
4. start Anchor and Recorder, then run `recording wait-listeners`;
5. prepare the source truststore;
6. start Breeze with its genuine Vintage configuration and wait for Breeze;
7. start the source with `MESH_CONNECT_HOST=breeze.recording`;
8. wait for source port `880`, verify the genuine Java process is `998:998`,
   then run `scripts/brz-no-fallback.sh` when `brz_no_fallback` is true;
9. run `traffic-e2e recording wait-ready`; this already waits through the
   configured post-ready settle interval, so do not add another shell sleep;
10. record for the selected duration;
11. send `SIGINT` to Recorder, wait for drain, finalization, and exact-run
    artifact ownership assignment, preserve diagnostics, and remove only
    containers created by this invocation.

Run both Recorder wait commands through `docker exec` inside the Recorder
container, using the container's control-socket path. They default to
300-second timeouts. Do not access the bind-mounted socket from the host or
parse `recorder.toml` in shell. Do not reject startup merely because a host
port probe reports another listener; let actual component startup expose
conflicts.

Use strict shell behavior, deterministic project-prefixed container names,
stage-aware idempotent cleanup, and `exec` in launchers. Never use `kill -9` as
the normal Recorder shutdown path.

## Validation

- Run `bash -n` for `scripts/start-recording` and
  `scripts/brz-no-fallback.sh`.
- Verify that the script fails before creating containers or artifacts when
  `TRAFFIC_E2E_ENCRYPTION_KEY_B64` is absent, malformed, or decodes to a length
  other than 32 bytes.
- With a valid unlogged key, run
  `./scripts/start-recording --duration-seconds 1 --case-limit 1`.
- Require finalized standard recording metadata with no Recorder startup or
  shutdown error, then require the complete exact run tree to have the
  invoking host UID/GID and remain writable for runner-owned artifacts.

This validates ready-to-record standard recording state. It does not require a
business request or a published recording case.
