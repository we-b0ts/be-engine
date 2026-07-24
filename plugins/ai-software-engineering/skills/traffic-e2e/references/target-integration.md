# Target Integration For Traffic E2E

Traffic E2E must exercise the target's normal behavior and genuine dependency
clients. The replay boundary intercepts or routes emitted traffic; the target
must not replace dependencies with recordings, fixtures, mocks, or in-process
fakes.

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
NOT read `dependencies.jsonl`, bootstrap dependency files, or dependency
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

## Identity And Staging

Intercepted recording and replay are limited to the fixed `trp-record` user.
The dependency-producing target must run as that identity. Build, recorder,
replay, and lifecycle control may remain under the developer account.

For a prebuilt in-process target, prefer:

```bash
traffic-e2e target exec \
  --env-file path/to/local.env \
  --copy-env APP_CONFIG=path/to/e2e.yaml \
  --path-env CASE_DIR=path/to/readable/case-group \
  --write-dir logs \
  -- path/to/prebuilt-target
```

The helper stages the executable and selected read-only inputs, creates a
private writable work directory, sanitizes inherited environment, verifies the
fixed identity, and cleans up. It never accepts a user or UID option. Keep
replay lifecycle commands in the outer developer-owned process.

If a container target shares a dedicated network namespace with supporting
containers, keep dependency-producing execution identity and interception
scope explicit. Sharing a namespace does not authorize recording unrelated
support-container traffic. When the target cannot satisfy the fixed identity or
supported routing boundary, report the replay blocked instead of widening
interception.

## Environment Materialization

Generate a Git-ignored `.traffic-e2e/.env` only for values proven to come
directly from source process environment, startup arguments, or machine-local
configuration. Use this precedence unless the target repository defines a
stricter equivalent:

1. explicitly supplied process environment;
2. `.traffic-e2e/.env`;
3. ordinary local application environment;
4. committed non-sensitive defaults.

Record variable names and provenance without printing values. Target runtime
receives ordinary environment values; it never parses recording files to
materialize them.

## Generated State Boundary

The target root must ignore `.traffic-e2e/local/`. Verify it with
`git check-ignore` before runner state is created. The runner exclusively owns
active attempts, sessions, reports, snapshots, logs, current pointers, and
temporary files under that directory. AI and target scripts MUST NOT create,
edit, merge, repair, copy, stage, commit, or force-add them.

`.traffic-e2e/e2e-progress.yaml` is a runner-generated concise project report
and may be committed when the repository workflow requires it. Never hand-edit
or reconstruct its counters. Local evidence, progress, and target exit codes
each have distinct authority; delivery status remains outside runner evidence.
