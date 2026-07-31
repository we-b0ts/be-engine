# Target Integration For Traffic E2E

Traffic E2E must exercise the target's normal behavior and genuine dependency
clients. The replay boundary intercepts or routes emitted traffic; the target
must not replace dependencies with recordings, fixtures, mocks, or in-process
fakes.

## Contents

- Normal runtime
- Standard project facade
- Identity and staging
- Runtime input materialization
- Generated state boundary

## Normal Runtime

Keep a normal startup path that does not load recordings. Follow the target
repository's existing configuration, environment precedence, dependency
wiring, logging, and command conventions. Preserve direct source startup inputs
through an equivalent authoritative target input.

When the source loads a value from a database, cache, configuration service,
secret service, or another runtime dependency, keep the genuine dependency path
and let recorder-owned replay provide the result. Do not infer such a value from
a recorded downstream request and turn it into an environment variable.

Target product code, E2E code, test support, commands, and normal config MUST
NOT read `dependencies.jsonl`, Global dependency files, or dependency
fixtures. Under replay-policy version two, the target facade MUST NOT read
`expected-response.json`; it writes actual response evidence and the runner
owns comparison.

## Standard Project Facade

For the standard runner, expose one thin source-controlled executable at
`scripts/<project>-cli` that delegates to repository-native commands and
propagates exit status. It provides:

- `start`: normal target startup without loading recordings;
- `stop`: idempotent cleanup of only the target-owned process;
- `status`: running, readiness, port, PID, and diagnostic status;
- `test`: ordinary unit and component tests;
- `e2e --case-dir <path> --actual-response <path>`: execute the active request
  through the genuine target path and write the runner-named actual response;
- `check`: repository format, lint, static analysis, and test gates.

The facade does not start or finalize replay, select cases, call replay-control,
aggregate reports, update runner state, choose an interception UID, read
recorded dependencies to produce results, read the expected response, or decide
whether assertions passed. Its E2E exit code proves request execution and
capture only.

For Breeze-managed target resources, the facade may forward one generic
descriptor policy selected by its caller and generic Breeze topology settings.
It must not infer the policy from runner state, enumerate resources, invoke a
descriptor resolver per resource, resolve descriptor ports, or export
descriptor-derived `host:port` values. The target's `brz-*` resource packages
own logical identity, descriptor-library use, and client construction.

For a case with encrypted request headers, the runner passes a private
short-lived case view whose `request.json` already contains authenticated
plaintext header values. The facade reads that file exactly like an ordinary
case. It must not read `TRAFFIC_E2E_ENCRYPTION_KEY_B64`, decrypt envelopes,
modify the canonical recording, or retain the temporary case view.

## Identity And Staging

Intercepted recording and replay are limited to the fixed `trp-record` user.
The dependency-producing target must run as that identity. Build, recorder,
replay, and lifecycle control may remain under the developer account.

For a prebuilt in-process target, prefer:

```bash
traffic-e2e target exec \
  --env-file .traffic-e2e/runtime/.env \
  --copy-env APP_CONFIG=.traffic-e2e/runtime/config/application.yaml \
  --path-env CASE_DIR=path/to/readable/case-group \
  --write-dir logs \
  -- path/to/prebuilt-target
```

The helper stages the executable and selected read-only inputs, creates a
private writable work directory, sanitizes inherited environment, verifies the
fixed identity, and cleans up. It never accepts a user or UID option. Keep
replay lifecycle commands in the outer developer-owned process.

If a container target shares an anchored network namespace with supporting
containers, keep dependency-producing execution identity and interception
scope explicit. Sharing a namespace does not authorize recording unrelated
support-container traffic. When the target cannot satisfy the fixed identity or
supported routing boundary, return `target_environment/action_required` or
`replay_capability_gap/action_required` with an acceptance check instead of
widening interception.

## Runtime Input Materialization

Use the Git-ignored `.traffic-e2e/runtime/` directory only for source-proven
runtime inputs allowed below: process environment, startup arguments,
machine-local configuration, or a complete authoritative configuration or
SDK-owned snapshot root already present in the source container. Use
`.traffic-e2e/runtime/config/` only for the smallest complete allowed root.
Never copy one selected file or selected subset. Preserve the directory
relationships required by the source loader.

Treat an artifact as a snapshot only when the source SDK or loader creates and
loads it during its normal lifecycle using a source-defined path and format. A
one-off dump, export, decryption, or diagnostic artifact is not a snapshot,
regardless of its name or location.

Never populate it by dumping, decrypting, extracting, or translating
source-process memory, remote responses, logs, or debug output. A constant
present in the source repository or pinned compiled artifact may be inspected,
decompiled when necessary, and migrated directly into target source code. For
remote-backed configuration, discovery, registry, or secrets, the target must
implement the source SDK's initialization, retrieval, refresh, fallback, and
any source-defined snapshot loading. It must not invent a snapshot when the
source SDK keeps that state only in memory. Use `.traffic-e2e/runtime/.env` for
materialized environment variables. Other source-proven machine-local runtime
dependencies may use purpose-named child directories when needed.

Initialize only the runtime root; create its contents only when source evidence
requires them. The target facade passes these paths through normal startup
inputs; product code must not hard-code the traffic-e2e directory.

Use this precedence unless the target repository defines a stricter
equivalent:

1. explicitly supplied process environment;
2. `.traffic-e2e/runtime/.env`;
3. ordinary local application environment;
4. committed non-sensitive defaults.

Record variable names and provenance without printing values. Target runtime
receives ordinary environment values and source-compatible configuration; it
never parses recording files to materialize them. Never commit
`.traffic-e2e/runtime/`.

## Generated State Boundary

The target root must ignore `.traffic-e2e/local/`. Verify it with
`git check-ignore` before runner state is created. The runner exclusively owns
active attempts, sessions, reports, snapshots, logs, current pointers, and
temporary files under that directory. AI and target scripts MUST NOT create,
edit, merge, repair, copy, stage, commit, or force-add them.

`.traffic-e2e/replay-progress.yaml` and
`.traffic-e2e/comparison-progress.yaml` are runner-generated concise project
reports and may be committed when the repository workflow requires it. They
share one schema but have separate stage owners. Never hand-edit, merge, or
reconstruct their counters. Local evidence, progress, and target exit codes
each have distinct authority; delivery status remains outside runner evidence.
