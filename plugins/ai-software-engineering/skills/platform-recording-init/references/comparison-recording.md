# Platform Comparison Recording

Use this reference after [platform-runtime.md](platform-runtime.md) when
generating or validating the comparison candidate facade and
`scripts/start-recording-comparison`.

## Contents

- Candidate facade
- Wrapper contract
- Lifecycle and isolation
- Offline verification
- Validation

## Candidate Facade

Initialization happens before the target implementation exists. Generate a
source-controlled, extensible `scripts/<project>-cli` facade with at least
these initialization-time lifecycle commands:

```text
start
status
stop
```

Initially, `start` must launch an owned fixed-response HTTP mock on port `8081`.
Every request path returns the configured readiness status `404` and this exact
body:

```json
{"code":"COMPARISON_RECORDING_CANDIDATE_NOT_IMPLEMENTED","msg":"fixed mock response"}
```

`status` must validate the owned PID and listening port. `stop` must be
idempotent and stop only the process owned by this repository. This list is a
minimum, not an exclusive command set. When genuine target startup becomes
available, replace the mock implementation behind this facade, preserve the
`start`/`status`/`stop` lifecycle semantics used by comparison recording, and
add the `e2e`, `test`, and `check` commands required by the standard traffic
E2E target facade.

This initializer owns only the facade scaffold and fixed mock. Do not plan or
implement future dependency wiring by parsing replay sessions, dependency
JSONL, recorded commands, keys, or target ports. The backend rewrite workflow
must review and replace the scaffold when genuine target startup becomes
available; Breeze-managed wiring then follows the
[`breeze-sdk` skill](../../breeze-sdk/SKILL.md). The facade may forward generic
Breeze topology settings, but it must not enumerate resources, call a
descriptor resolver, or inject descriptor-derived ports.

## Wrapper Contract

Generate `scripts/start-recording-comparison` with these accepted forms:

```bash
./scripts/start-recording-comparison
./scripts/start-recording-comparison --run-id YYYYMMDDHHMMSS
./scripts/start-recording-comparison --duration-seconds <positive-integer>
./scripts/start-recording-comparison --baseline-recheck
./scripts/start-recording-comparison --brz-no-fallback <true|false>
./scripts/start-recording-comparison --api 'GET /api/widgets/*'
```

Default the duration to `60` seconds when omitted. AI and automated invocations
must explicitly pass `--duration-seconds 60` or another positive integer.
Default `brz_no_fallback` to `true` and accept only literal `true` or `false`.
When provided, require `--run-id` to be a valid 14-digit UTC timestamp. Allow
every option to combine, reject missing option values, invalid values, or
duplicate options before changing runtime state, and accept repeatable
canonical `--api` selectors. Consume `--brz-no-fallback` in the wrapper; pass
the run ID, duration, baseline recheck, and API selectors through unchanged to
`traffic-e2e record-comparison`.

Require `TRAFFIC_E2E_ENCRYPTION_KEY_B64` during the same argument validation
and verify, without printing decoded bytes, that it is strict Base64 for
exactly 32 bytes. Preserve it for the host
`traffic-e2e record-comparison` process. If the command is launched through
`sudo` or another environment boundary, forward only this named variable
explicitly. Never pass it to the source, candidate, or Breeze, and never print
it. `record-comparison` independently repeats key validation before creating
its run directory.

## Lifecycle And Isolation

Start exactly one Breeze container for comparison and connect both the genuine
source container and candidate container to that same instance with their
normal dependency configuration. Do not start a Breeze per application.
`brz-no-fallback.sh` controls application-side fallback behavior, so when the
option is true, execute the mounted repository script against the source and
against every candidate runtime that exposes the Platform mesh control
endpoint after each becomes ready. Treat a required but unreachable control
endpoint as startup failure. This fixed script changes only Breeze Mesh
transport fallback; it does not authorize disabling caches, business fallback,
or other feature switches. When false, skip those commands.

Use this lifecycle:

1. validate arguments and the encryption-key environment, then create ignored
   runtime directories;
2. create the comparison network topology and start one genuine inspected
   Breeze instance without Recorder dependency interception;
3. start the genuine inspected source as the baseline and connect it to the
   shared Breeze;
4. invoke `scripts/<project>-cli stop` to remove only a stale owned candidate,
   configure the candidate's generic descriptor policy as `RequireExisting`,
   then invoke `start`, connect the candidate to the same Breeze, and require
   `status` to succeed; the source establishes descriptors and the candidate
   SDK resolves them internally;
5. when `brz_no_fallback` is true, apply `scripts/brz-no-fallback.sh` to each
   applicable ready application container;
6. run `traffic-e2e record-comparison --config
   .traffic-e2e/recorder.toml`, passing through `--run-id`,
   `--duration-seconds`, every `--api`, and the enable-only
   `--baseline-recheck` flag when set;
7. forward termination to `traffic-e2e`, allow it to finalize artifacts, then
   stop only the owned candidate, source, shared Breeze, and network resources;
   and
8. preserve the `record-comparison` exit status.

Do not invoke `scripts/start-recording`: that workflow intentionally installs
dependency interception, while comparison recording must execute each
service's original dependency behavior. Do not enable the fixed recording
user, DNS/iptables interception, fake-IP routing, MITM, replay, or any other
isolation for `record-comparison`.

Comparison rules may contain only `GET`, `HEAD`, and `OPTIONS`; configuration
must fail before startup for every other method. Keep
`comparison_recording.baseline_recheck = false` during initialization. A later
verification run may explicitly pass `--baseline-recheck` to capture
source-before, candidate, and source-after in that order when source-time drift
evidence is needed. The initialized verification policy independently defaults
`comparison.source_match` to `before`; a later traffic verification task may
select `before_or_after`, which requires the recheck artifact for every case.

## Offline Verification

After a run with frontend cases finalizes, verify it offline:

```bash
traffic-e2e compare \
  .traffic-e2e/artifacts/comparison-recordings/<run-id> \
  --policy .traffic-e2e/verification.yaml
```

This command is file-only and must not enable isolation. It writes
`comparison-report.json` by default and reuses only the target verification
policy's response rules. A changed optional source recheck is reported as
`source_change` only for candidate differences at the same response location;
unrelated candidate differences remain candidate behavior. Source change is
inconclusive evidence, not a cause or exemption. Use `--comparison-report` with
`traffic-e2e config replay plan|apply response-rule` when reviewed online
evidence proves that another dynamic or unordered field should be exempted.
Use `traffic-e2e config comparison plan|apply response-rule` only for a
source-proven comparison-only strategy.

## Validation

- Run `bash -n` for `scripts/start-recording-comparison` and
  `scripts/<project>-cli`.
- Verify that the script fails before creating containers or artifacts when
  `TRAFFIC_E2E_ENCRYPTION_KEY_B64` is absent, malformed, or decodes to a length
  other than 32 bytes.
- With a valid unlogged key, run
  `./scripts/start-recording-comparison --duration-seconds 1`.
- Prove the source and candidate reused exactly one Breeze instance, require
  both upstreams to become ready, and require a finalized
  `comparison-recording-run.json`.

This validates ready-to-record comparison state. It does not require frontend
traffic or a published comparison recording case.
