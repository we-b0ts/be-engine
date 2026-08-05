# One-Time Project Initialization

Use this reference only when the caller explicitly asks to initialize an
uninitialized target repository. Initialization is a manual, one-time setup;
ordinary `next`, `status`, worker dispatch, and resumed rewrite sessions must
not read this reference or rerun initialization.

## Generate The Repository Contract

Run from the target repository, or bind it with global `--target-root`:

```bash
backend-rewrite init \
  --source-container <existing-source-container> \
  [--breeze[=<container>]] \
  [--http-gateway-port 17171]
```

`--breeze` selects the conventional existing container named `breeze`;
provide a value only for a non-standard name. Source and Breeze containers
need to be inspectable, not running.

The recording port is the Recorder HTTP gateway that accepts selected source
traffic. It is distinct from the source service port and target replay port.
Defaults are:

- HTTP recording gateway `17171`;
- source service `8080`;
- target service `8081`;
- readiness `/healthz` with final status `404`; and
- upstream DNS `10.10.10.11:53`.

Use `--source-http-port`, `--target-port`, `--readiness-path`,
`--readiness-status`, or `--upstream-dns` only when the inspected application
contract proves a different value.

The command atomically creates exactly these source-controlled files:

```text
.traffic-e2e/project.yaml
.traffic-e2e/recorder.toml
.traffic-e2e/verification.yaml
```

It also idempotently adds `/.traffic-e2e/local/` to `.gitignore`. It refuses
the whole initialization when any generated file already exists, and it does
not start containers, record traffic, create runtime evidence, or create
`.traffic-e2e/local/boot`.

## Provide The Target CLI Interface

The same initialization task must create an executable mock or empty CLI
scaffold with this stable interface:

```text
scripts/<project>-cli start --e2e \
  --boot-dir .traffic-e2e/local/boot --port <target-port>
scripts/<project>-cli stop
```

Even an empty or mock scaffold must parse and accept both
`--boot-dir <path>` and `--port <port>` on `start --e2e`. It does not need to
inspect or populate the boot directory during initialization. When the real
target startup is implemented, it must use the exact supplied directory and
port rather than replacing them with repository-local defaults.

Initialization does not require this scaffold to compile or launch the real
target. It may be an explicitly unimplemented entrypoint or start a stable
mock/fallback service. When target execution is first required, complete the
implementation behind the unchanged interface: compile once, forward the
exact boot directory and port, launch the normal target, and keep `stop`
idempotent and limited to target-owned processes. Dedicated API workers add
source-compatible business behavior later.

The CLI owns only product startup and shutdown. It must not read recorded
cases, expected responses, Replay sessions, reports, or coordinator state.
The coordinator owns source adaptation, recording, shared dependencies,
target invocation, Replay, comparison, and cleanup.

If the target depends on Breeze, `start --e2e` means the CLI does not launch
Breeze. Source and target use the coordinator-managed shared Breeze lifecycle;
there is no separate target Breeze instance.

Use `.traffic-e2e/local/boot` only for source-compatible runtime inputs proved
necessary by startup. Keep credentials and generated trust material below the
ignored `.traffic-e2e/local/` tree and do not commit them.

## Initialization Completion

Do not report initialization complete until all of the following are true:

- the initialization command succeeded and all three generated configuration
  files exist;
- the repository `.gitignore` contains the root-scoped
  `/.traffic-e2e/local/` entry;
- `scripts/<project>-cli` exists, is executable, and exposes the exact
  `start --e2e` and `stop` interface above;
- the implementation behind that interface may remain empty or mock; no
  compile, launch, or recorded API behavior is required during initialization;
  and
- the initialization changes contain no generated runtime data, credentials,
  recordings, or `.traffic-e2e/local/` content.

Initialization ends after these repository requirements are delivered. It
does not start the target, validate traffic, record, Replay, compare, or invoke
or advance the `backend-rewrite next` workflow.

## Optional Initialization PR

After initialization is complete, explicitly ask the user whether they want
to create or confirm a `dev-migration` branch and deliver the initialization
changes through a PR targeting that branch. Do not create a branch, commit,
push, or PR without that confirmation.

If the user confirms:

1. Use the repository's intended pre-initialization migration baseline for
   `dev-migration`. If that baseline is ambiguous, ask the user instead of
   guessing. Reuse an existing local or `origin/dev-migration` branch when
   present; never replace or move it silently.
2. Keep the initialization changes on a separate feature branch. The source
   branch must not be `dev-migration`.
3. Commit only the three generated configuration files, the root-scoped
   `.gitignore` update, the mock/empty `scripts/<project>-cli`, and any minimal
   target scaffold required by that CLI. Exclude unrelated work and all
   `.traffic-e2e/local/` content.
4. Push the necessary branches and create a PR whose target branch is
   `dev-migration`. Report the branch names and PR URL to the user.

If the user declines, stop after initialization and leave Git delivery to the
user. This optional delivery does not start or advance the rewrite workflow.
