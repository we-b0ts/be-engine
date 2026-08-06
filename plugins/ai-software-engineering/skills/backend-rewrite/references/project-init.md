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

## Generate The Recording Source Adaptor

The same initialization task must inspect the configured source container and
create this additional source-controlled build contract:

```text
.traffic-e2e/Dockerfile.recording
```

When Breeze is enabled, also create:

```text
.traffic-e2e/MeshConnectUtil.class
```

Generate `Dockerfile.recording` from the inspected source image and its actual
application launch contract. Preserve the proved application command and
working directory behind an explicit adaptor entrypoint; never assume the
source image entrypoint interprets `RUN_COMMAND` or another conventional
environment variable. The resulting source application process must run as
`trp-record` with numeric UID/GID `998:998`. Fail initialization on an
incompatible identity collision or when the real application command cannot be
determined. Declare `ARG SOURCE_IMAGE` before `FROM` and use
`FROM ${SOURCE_IMAGE}` so the managed runtime can bind the build to the exact
image ID inspected from the configured source container.

The adapted source must retain its port `880` listener while running as
`998:998`. Because `880` is a privileged port, resolve the real Java executable
behind any symlink and grant only that executable
`cap_net_bind_service=+ep`; do not run the application as root or make the
container privileged. A capability-bearing Java executable enters secure
loader mode, so add its resolved `libjli.so` directory to the system dynamic
loader configuration and run `ldconfig` during the image build. Fail the build
unless `getcap` confirms the expected capability.

When Breeze is enabled, copy the bundled
[`MeshConnectUtil.class`](../assets/MeshConnectUtil.class) byte-for-byte to
`.traffic-e2e/MeshConnectUtil.class`; its SHA-256 is
`5539b2940b2ab7ffdc02b9aec58565ed034fa29ae5043aa741e8857ee42ae58f`.
In `Dockerfile.recording`, require exactly one `breeze-sdk-core-*.jar` below
`/data1`, replace
`com/weibo/api/datamesh/common/utils/MeshConnectUtil.class` in that JAR with
the bundled Java 8 class, extract it again, and compare it byte-for-byte with
the input asset. Do not compile a per-project Java source file or silently
choose among multiple Breeze SDK JARs. Do not generate, copy, or execute
`apply-breeze-sdk-patch`; replacing and verifying the bundled class is the
complete patch operation. At runtime set
`MESH_CONNECT_HOST=breeze.recording` so the patched SDK connects to the managed
Breeze container instead of source-local loopback.

Include the ability to use a runtime-mounted Java truststore, but do not embed
a Recorder CA, private key, credential, recording, or machine-local container
state in the image. The current source-adaptor contract supports Java
applications: retain `keytool`, `/bin/sh`, and `java` in the adaptor so the
managed runtime can construct Java trust and execute its bundled Java 8 HTTPS
probe through the same JKS used by the source application. Do not require a
compiler or curl in the source adaptor solely for preflight.

After creating `Dockerfile.recording`, the target AI must build it during
initialization and tag the resulting image as
`traffic-e2e/<project>-recording:cache`, where `<project>` is the lowercase,
normalized target repository directory name. Bind `SOURCE_IMAGE` to the exact
image ID inspected from the configured source container. This target-specific
build happens before `backend-rewrite init preflight`; the preflight requires
and reuses the image and must not build it again.

Later managed recording reuses the tag whenever it exists. If the local image
is missing, the managed runtime builds it once from the same Dockerfile and
continues. Do not fingerprint the source image or Dockerfile, check whether the
cached image is stale, or rebuild an existing tag during ordinary recording;
the target AI reruns the initialization build when an intentional refresh is
required.

The Dockerfile alone owns optional assets such as `MeshConnectUtil.class`,
including their presence and validation; the generic managed runtime must not
name, inspect, or validate those assets. It must not synthesize another
project-specific Dockerfile or include `.traffic-e2e/local/` in the build
context.

Do not create a Breeze Dockerfile or image in the target repository. When
Breeze is enabled, the managed runtime uses the fixed
`registry.api.demo.test/weibo_rd_if/breeze:v0.1.21-e2e` image and starts it with
the inspected Breeze container's runtime arguments.

## Complete A Recording Preflight

After the target AI has built the named source adaptor image, complete one
disposable recording preflight before reporting initialization complete:

```bash
backend-rewrite init preflight \
  --api '<METHOD path-or-pattern>' \
  --duration-seconds 60
```

Run the command from the target repository after the generated configuration,
`Dockerfile.recording`, `traffic-e2e/<project>-recording:cache`, and target CLI
scaffold exist. Provide the same
`TRAFFIC_E2E_ENCRYPTION_KEY_B64` required by managed recording. The command
defaults each selected API to one admitted case and opens a bounded recording
window; while it is running, send one deterministic
controlled business request to the configured HTTP gateway port. The system
independently sends an HTTPS background probe from the running source adaptor
container. The business request must match the selected API. The command does
not invent its path, request body, or business input because those values must
come from the inspected source contract.

1. Start Recorder first so it creates its runtime CA, then create a Java
   truststore from that public certificate without copying the CA private key
   into either image.
2. When Breeze is enabled, start the fixed Breeze image with the inspected
   Breeze runtime arguments.
3. Start the source adaptor with the inspected source runtime inputs, the
   generated truststore mounted read-only, and the explicit adaptor entrypoint.
4. Verify the source application process runs as UID/GID `998:998`, its port
   `880` listener is reachable without root or privileged-container execution,
   Breeze is ready when enabled, the source readiness contract passes, and
   Recorder admits cases.
5. After source readiness, have the managed runtime execute a Java HTTPS
   request inside the source adaptor container against `https://demo.test/`.
   It must use the mounted JKS through the container's `JAVA_TOOL_OPTIONS`, the
   same trust path as the source application. The CA is local trust input and
   is not transmitted to the remote server. In preflight only, retain full
   run-level `traffic.jsonl` events without changing the repository recorder
   configuration. The probe command's exit status is diagnostic only.
6. After the command reports
   `phase = "preflight-business-input-required"`, admit the controlled request
   matching the configured HTTP gateway rule,
   using the rule's declared method without a separate read-only-method
   restriction. Finalize the disposable run and require a clean manifest with
   at least one published case and its source response.
7. Await the preflight command's final result. Do not infer success from the
   probe command's exit status or response alone. Only `status = "passed"` is
   authoritative: the system must find any successful HTTPS exchange in the
   run-level traffic log or case/global dependency evidence as well as the
   cleanly published business case. The exchange may come from the automatic
   `demo.test` probe or existing source traffic; the controlled business request
   itself does not need to produce outbound HTTPS.

Run this through the same managed recording machinery used by backend-rewrite
for normal source recording, including Recorder, network isolation, the source
adaptor, optional Breeze, CA creation, readiness, finalization, and cleanup.
Keep its run identity and artifacts in a dedicated preflight area below
`.traffic-e2e/local/preflight/<run-id>/`; never publish them as the workflow's
standard recording, Replay, or comparison evidence. Success output reports
`status = "passed"`, the isolated manifest, `published_cases`, and
`https_interception_verified = true`. The command fails when no complete case
is recorded or the required HTTPS background probe was not intercepted
successfully. It streams the run-level traffic log and case/global dependency
evidence only until that HTTPS witness is found and imposes no total-file-size
limit; these files commonly reach multiple gigabytes. The preflight does not start the
target, initialize API inventory, or advance coordinator workflow state. Do
not invoke
`backend-rewrite next` to manufacture this check. If image construction, source
identity, readiness, CA truststore setup, request admission, case publication,
finalization, or cleanup fails, initialization is incomplete.

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
Initialization owns the reviewed recording-image contracts and their one-time
preflight. The coordinator later owns runtime recording, shared dependencies,
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
- `Dockerfile.recording` exists, and the adaptor builds successfully without
  runtime secrets or generated trust material as
  `traffic-e2e/<project>-recording:cache`;
- when Breeze is enabled, `.traffic-e2e/MeshConnectUtil.class` exactly matches
  the bundled asset, and its replacement in the source Breeze SDK JAR is
  verified byte-for-byte;
- the repository `.gitignore` contains the root-scoped
  `/.traffic-e2e/local/` entry;
- `scripts/<project>-cli` exists, is executable, and exposes the exact
  `start --e2e` and `stop` interface above;
- the implementation behind that interface may remain empty or mock; no
  target compile, launch, or business implementation is required during
  initialization;
- the disposable recording preflight passed with the adapted source process
  running as `998:998`, CA truststore setup completed, the independent
  HTTPS background interception verified, and one cleanly published case;
  and
- the initialization changes contain no generated runtime data, credentials,
  recordings, or `.traffic-e2e/local/` content.

Initialization ends after these repository requirements are delivered. It
does not start the target, Replay, compare, or invoke or advance the
`backend-rewrite next` workflow. Its disposable source recording exists only to
validate the initialized recording environment.

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
3. Commit only the three generated configuration files,
   `Dockerfile.recording`, the Breeze-only `.traffic-e2e/MeshConnectUtil.class`
   when applicable, the root-scoped `.gitignore` update, the mock/empty
   `scripts/<project>-cli`, and any minimal target scaffold required by that
   CLI. Exclude unrelated work and all `.traffic-e2e/local/` content.
4. Push the necessary branches and create a PR whose target branch is
   `dev-migration`. Report the branch names and PR URL to the user.

If the user declines, stop after initialization and leave Git delivery to the
user. This optional delivery does not start or advance the rewrite workflow.
