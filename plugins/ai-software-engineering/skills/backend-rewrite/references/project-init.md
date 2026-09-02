# One-Time Project Initialization

Use this reference only when the caller explicitly asks to initialize an
uninitialized target repository. Initialization is a manual, one-time setup;
ordinary `next`, `status`, worker dispatch, and resumed rewrite sessions must
not read this reference or rerun initialization.

## Discover Startup Inputs First

Before running initialization, inspect the source container, its launch
arguments and working directory, and the source startup code. Record only the
inputs required to reproduce startup:

- configuration files or directories read during startup, including general
  environment files used by Node, Python, shell launchers, frameworks, or the
  application itself (`.env`, `.env.production`, `.flaskenv`, `env.conf`, and
  similar files); resolve each path against the source working directory and
  pass its normalized absolute container path through `--startup-mount`;
- application-owned environment variable names required at startup; pass each
  name through `--startup-env`; and
- directories the process must write at runtime, such as logs, caches, PID or
  temporary state directories. Ensure those paths exist and are writable by
  `998:998` in both `Dockerfile.recording` and `Dockerfile.e2e`. Declare durable
  output paths under `target.runtime_outputs` when traffic-e2e should retain
  them after the container stops.

`--startup-env` is a variable-name selector, not an env-file path. traffic-e2e
reads the selected values from the source container's `Config.Env`, stores them
only in the ignored startup snapshot, creates a mode-0600 runtime env file, and
passes it to Docker with `--env-file`. Values originally supplied by
`docker run --env-file` are already present in `Config.Env`; Docker inspection
cannot recover, and does not need, the original host file path. Any environment
configuration that must remain a file is a startup filesystem input: declare it
with `--startup-mount`, and traffic-e2e snapshots and mounts it back at the same
absolute path. Never commit either form of secret input.

## Generate The Repository Contract

Run from the target repository, or bind it with global `--target-root`:

```bash
backend-rewrite init \
  --source-container <existing-source-container> \
  [--breeze[=<container>]] \
  [--startup-mount /absolute/path/to/config] \
  [--startup-mount /absolute/path/.env] \
  [--startup-env <APPLICATION_ENV_NAME>] \
  [--target-port-env <PORT_ENV_NAME>] \
  [--http-gateway-port 4080]
```

`--breeze` selects the conventional existing container named `breeze`;
provide a value only for a non-standard name. Source and Breeze containers
need to be inspectable, not running.

Do not declare or persist a source language. During every managed recording,
traffic-e2e tests the completed source adaptor image in a disposable,
network-disabled container as `998:998`, overriding its entrypoint to run only
`java -version`. It grants only `NET_BIND_SERVICE` so the contract's
capability-bearing Java executable remains runnable, but it does not start the
business entrypoint or mount business data. A successful probe selects the
fixed Java 8 truststore probe; otherwise the system-owned network probe is used.

The recording port is the Recorder HTTP gateway that accepts selected source
traffic. It is distinct from the native HTTP service port.
Defaults are:

- HTTP recording gateway `4080`;
- recorder native HTTP upstream `http://127.0.0.1:8080`;
- readiness `/healthz` with final status `404`; and
- upstream DNS `10.10.10.11:53`.

Only `--http-gateway-port` is exposed for port selection during initialization.
For a non-standard native service port, update
`http_gateway.matched_upstream` in the generated recorder configuration; the
target uses that same port in its isolated runtime namespace.

The command atomically creates these required source-controlled configuration
files:

```text
.traffic-e2e/project.yaml
.traffic-e2e/source-traffic-policy.yaml
.traffic-e2e/verification.yaml
```

`project.yaml` uses schema version 14 and combines project settings with the
static recorder configuration. `source-traffic-policy.yaml` is wholly managed by
the coordinator and contains HTTP feedback, Breeze capture resources, and
process-owned dependency rules. The startup declaration and matching
snapshot are immutable initialization outputs. Normal rewrite sessions must not
replace, refresh, or migrate them. A repository with obsolete, missing, stale,
or damaged startup inputs requires the explicit administrator repair:

```bash
backend-rewrite-admin --target-root <target> \
  startup recapture --confirm-replace
backend-rewrite --target-root <target> init preflight
```

The admin command reads the complete startup declaration already stored in
`project.yaml`, requires the configured source container to be stopped, and
atomically replaces the local snapshot only after capture succeeds. Preflight
validates the repaired contract; it never recaptures inputs itself.

In the same one-time operation it creates the target template described below,
unless a complete root Cargo target already exists, and creates
`.traffic-e2e/Dockerfile.e2e` only when absent. The initializer also creates or
safely extends the root `.gitignore` and `.dockerignore` with its canonical
local-state, Rust build, recording, data, credential, and environment-file
exclusions. It refuses the whole initialization when any required configuration
file already exists, and it does not start containers, record traffic, or
create runtime evidence. It captures the declared startup inputs below
`.traffic-e2e/local/startup/` from the configured stopped source container.

## Generate The Recording Source Adaptor

The same initialization task must inspect the configured source container and
create this additional source-controlled build contract:

```text
.traffic-e2e/Dockerfile.recording
```

When Breeze is enabled, also create:

```text
.traffic-e2e/MeshConnectUtil.class
.traffic-e2e/CommonSwitcher.class
```

Generate `Dockerfile.recording` from the inspected source image and its actual
application launch contract. Preserve the proved application entrypoint,
command, arguments, and working directory directly; never assume the source
image entrypoint interprets `RUN_COMMAND` or another conventional environment
variable. The resulting source application process must run as
`trp-record` with numeric UID/GID `998:998`. Fail initialization on an
incompatible identity collision or when the real application command cannot be
determined. Declare `ARG SOURCE_IMAGE` before `FROM` and use
`FROM ${SOURCE_IMAGE}` so the managed runtime can bind the build to the exact
image ID inspected from the configured source container.

For every image-local runtime-writable path discovered before initialization,
create the directory in `Dockerfile.recording` and assign it to `998:998` before
restoring the final application user. Do not recursively change ownership of
configuration or credential trees. Exact writable source mounts are recreated
by the managed runtime and do not need image-layer content.

The adapted source must retain its port `880` listener while running as
`998:998`. Because `880` is a privileged port, grant
`cap_net_bind_service=+ep` only to the real source executable; do not run the
application as root or make the container privileged. For Java, resolve the
real Java executable behind any symlink. A capability-bearing Java executable
enters secure loader mode, so add its resolved `libjli.so` directory to the
system dynamic loader configuration and run `ldconfig` during the image build.
Fail the build unless `getcap` confirms the expected capability.

When Breeze is enabled, copy the bundled Java 8 classes byte-for-byte:

- [`MeshConnectUtil.class`](../assets/MeshConnectUtil.class), SHA-256
  `5088b125c7eacc637240241c8a5f5dc7816b08328e3aa5f9f234b248ffc0be63`;
- [`CommonSwitcher.class`](../assets/CommonSwitcher.class), SHA-256
  `9f9df4dbf45122e558293a93379742f50db8e629d1459dfc8cad0b801ede707e`.

In `Dockerfile.recording`, require exactly one `breeze-sdk-core-*.jar` below
`/data1`. Replace the corresponding classes at
`com/weibo/api/datamesh/common/utils/MeshConnectUtil.class` and
`com/weibo/api/datamesh/common/switcher/CommonSwitcher.class`.
Extract both again and compare them byte-for-byte with the input assets.
Do not compile per-project Java source or silently choose among multiple
Breeze SDK JARs. At runtime set
`MESH_CONNECT_HOST=breeze.recording` so the patched SDK connects to the managed
Breeze container instead of source-local loopback. A non-blank
`MESH_CONNECT_HOST` is also the explicit managed-recording TCP selection: the
patched helper must ignore `mesh.unix.domain.socket.enable` in that mode.
Without this precedence, source traffic can disappear into an unobservable
Unix domain socket while Replay correctly expects the target's TCP
`breeze.recording:<resource-port>` dependency.

The SDK patch is intentionally narrower than a switch task. It preserves the
source values of `mesh.switcher`, pool, resource, namespace, and method
switches. When those values select Mesh under managed recording, it disables
automatic degrade and exception fallback to the source TCP client. A selected
but uninitialized Mesh client retains the SDK's original behavior; startup and
preflight diagnostics are responsible for detecting unavailable Breeze. When
source switches select TCP, source behavior remains TCP. Preserve the inspected
source entrypoint and command exactly; do not add a wrapper, invoke the source
control port, or inject a fallback-control environment variable.

Do not embed a Recorder CA, private key, credential, recording, or
machine-local container state in the image. When Java is part of the source
runtime, retain `keytool`, `/bin/sh`, and `java` and support a runtime-mounted
Java truststore; the managed runtime constructs Java trust and executes its
system-supplied Java 8 HTTPS probe through the same truststore used by the
source application. `HttpsProbe.class` is embedded in traffic-e2e and staged
below ignored local runtime state only during preflight; the target AI must not
create, copy, or commit it. Do not require a compiler or curl in the source
adaptor solely for preflight. For non-Java sources, do not add Java or curl
solely for probing; the system-owned network probe image performs the recording
probe.

After creating `Dockerfile.recording`, run `backend-rewrite init preflight` to
build the target-scoped source adaptor. The managed build tags the image as
`traffic-e2e/<project>-recording:cache`, where `<project>` is the lowercase,
normalized target repository directory name, and binds `SOURCE_IMAGE` through a
temporary local alias of the exact image ID inspected from the configured source
container. Do not substitute a manual image build for this managed build.

The configured source container is the persistent runtime inspection source.
Keep that container present and stopped after initialization; managed preflight,
recording, and comparison inspect it but never start, stop, remove, or replace
it. A missing adaptor image or one labeled for another source image triggers a
build/refresh from the same Dockerfile. A changed top-level adaptor build
context does the same. Reuse an adaptor only when its source-image and build
contract labels match the current inputs.

The Dockerfile alone owns optional Breeze class assets, including their
presence and byte-for-byte validation; the generic managed runtime must not
inspect or copy those assets. It must not synthesize another project-specific
Dockerfile or include `.traffic-e2e/local/` in the build context.

Do not create a Breeze Dockerfile or image in the target repository. When
Breeze is enabled, the managed runtime uses the fixed
`registry.api.demo.test/weibo_rd_if/breeze:v0.1.21-e2e` image and starts it with
the inspected Breeze container's runtime arguments.

## Complete The Initialization Preflight

After the generated target files and `Dockerfile.recording` are ready, invoke
the single coordinator-owned initialization preflight:

```bash
backend-rewrite init preflight \
  --duration-seconds 60
```

The configured source container remains stopped; the command builds and runs
only disposable managed containers. Provide the same
`TRAFFIC_E2E_ENCRYPTION_KEY_B64` required by normal managed recording. Do not
pass `--api`, send business traffic, create another validation command, or run
`backend-rewrite next` for this check.

The command owns four ordered phases:

1. `target_image` builds the exact target image and validates its pinned build,
   platform, user, entrypoint, cache, and secret-exclusion contracts.
2. `recording` starts the managed source adaptor, verifies Recorder trust and
   optional Breeze DNS, sends the system HTTPS probe, then automatically records
   exactly one `GET` for the configured readiness path with a finalized source
   response.
3. `replay_network` starts Replay from that disposable recording, consumes the
   recorded HTTPS dependency, rejects an unrecorded endpoint, and verifies that
   direct external egress is blocked.
4. `target_runtime` starts the exact phase-one image inside the recording-derived
   Replay namespace and verifies readiness, `0.0.0.0` listening, UID/GID
   `998:998`, startup inputs, bounded diagnostics, clean `SIGTERM`, and cleanup.

Artifacts stay below `.traffic-e2e/local/preflight/<run-id>/` and never enter
the rewrite API inventory or normal recording evidence. The readiness response
body is not compared with source business behavior. Treat only overall
`status = "passed"` with all four phase results as success; any phase or cleanup
failure leaves initialization incomplete.

## Analyze Source Startup Reference Evidence

During the same one-time initialization, analyze one complete startup lifecycle
of the disposable recording source adaptor. Use the source startup code, the
runtime inputs inspected from the configured source container, bounded source
container logs, and observed process traffic together. The analysis is
reference evidence for the first rewrite, not coordinator state or migration
acceptance evidence.

Cover only these source-runtime concerns:

- every configuration input loaded during startup, including complete local
  configuration roots, environment or argument selectors, and remote
  configuration access through Vintage or equivalent SDKs;
- each Vintage dependency and access visible from source initialization,
  refresh, fallback, logs, or observed traffic, without recording sensitive
  values;
- startup and post-readiness process activity, summarized by protocol,
  destination domain, port, lifecycle phase, and observed access count; and
- each local cache initialized, warmed, loaded, refreshed, or consulted by
  startup/background work, together with its proved loader dependency and
  readiness relationship when available.

Distinguish at least pre-readiness, controlled-request, and post-readiness
background observations. Counts and log frequency are triage evidence only;
they do not by themselves prove process ownership, cache causality, or a
required target implementation. Correlate them with source startup and cache
code before recording a conclusion.

Confirm that the mounts, environment names, and writable directories discovered
before initialization cover the observed startup behavior. Do not add selected
keys, generated SDK snapshots, caches, decrypted output, remote responses, logs,
or process memory to startup inputs. Keep credentials out of commands and
summaries and never commit the local startup snapshot.

Write a concise, redacted summary of the configuration, Vintage,
background-traffic, and local-cache findings to
`.traffic-e2e/local/block.md`. Do not copy raw logs or build a permanent
architecture document. The first rewrite session must read the complete
summary. It may then delete each entry once it has fully understood the
finding, implemented the required behavior, or proved the finding irrelevant;
delete the file when no entries remain and retain no resolved history.

This analysis must not implement target configuration loading, a Vintage
client, background tasks, local caches, API handlers, or any other migrated
product behavior. Initialization only discovers and transports source runtime
facts; rewrite workers implement behavior later when their evidence requires
it.

## Provide The Target Container Contract

The repository initialization command creates one source-controlled, runnable
Rust target template together with the three repository configuration files:

```text
Cargo.toml
Cargo.lock
src/main.rs
.traffic-e2e/Dockerfile.e2e
.gitignore
.dockerignore
```

This happens only during the one-time initialization command. The generated
`Cargo.toml` pins `brz-logs` to `tag = "v0.0.1"` with its `metrics` feature and
declares the public dependencies used by the bootstrap server. The generated
`src/main.rs` binds `0.0.0.0`, honors the configured application-owned target
port environment, satisfies the configured readiness path and status, stays in
the foreground, and shuts down on `SIGTERM`; every other path returns 404. It
does not implement business behavior.

The template exists only to make initialization runnable. After initialization,
the target AI owns the generated `Cargo.toml`, `Cargo.lock`, `src/main.rs`, and
`.traffic-e2e/Dockerfile.e2e`; it may replace the bootstrap implementation while
preserving the target build, startup, readiness, identity, and shutdown
contracts below.

Never overwrite existing target source or build files. Generate the Cargo
template only when `Cargo.toml`, `Cargo.lock`, and `src/main.rs` are all absent;
otherwise require all three to exist as regular files. Generate
`.traffic-e2e/Dockerfile.e2e` only when it is absent and preserve an existing
regular file. Create `.gitignore` and `.dockerignore` when absent; when either
already exists, preserve its contents and append only missing canonical rules.
Report every newly created file and whether either ignore file changed in the
initialization result. The target AI does not need to reproduce those rules
from this document.

The target image's OCI entrypoint is the target launch contract used by
traffic-e2e. traffic-e2e owns `docker build`, `docker run`, readiness,
`docker stop`, and `docker rm`.

The target AI invokes `backend-rewrite init preflight` for the build and static
image contract, then consumes coordinator-owned Replay results for the runtime
contract; direct Docker commands, AI narration, and self-reported checks are
never evidence.

### Build One Reproducible Target Image

The generated `.traffic-e2e/Dockerfile.e2e` is the canonical starting point.
When adapting it to an existing workspace, preserve these contracts:

- a BuildKit multi-stage build using the pinned traffic-e2e Rust builder and
  runtime images already present in the generated file;
- repository-root context, `cargo build --locked --release`, shared Cargo
  registry/Git caches, and one project-specific `/build/target` cache;
- `--mount=type=ssh,required=true`, known-host setup, and the fixed
  `git ls-remote` check for the private Breeze `v0.0.1` tag;
- a final stage containing only the release binary and explicit runtime assets,
  with a non-empty entrypoint, no default command arguments, and final
  `USER 998:998`; and
- no external `# syntax=` frontend, credentials, source tree, build cache,
  generated trust, recordings, or traffic-e2e binary in the final image.

Before preflight, expose an SSH agent containing an identity authorized for
`git.intra.demo.test`; for example, run `ssh-add ~/.ssh/id_ed25519` and verify
`SSH_AUTH_SOCK` is set. traffic-e2e validates the agent and automatically passes
`--ssh default`. The key remains a build-time mount and is never copied into an
image.

traffic-e2e owns the build from the repository root, the local
`traffic-e2e/<project>-target:cache` tag, immutable image-ID resolution, cache
reuse, and use of the same image ID for a validation round. Do not substitute a
host-built binary or a manually started target container.

### Run The Normal Target Process

The image entrypoint must directly execute the current target implementation as
one foreground process. traffic-e2e passes no application CLI arguments. Each
declared startup path is mounted read-only at the same absolute path used by
the source. Each declared environment name receives the value frozen from the
source container. For example:

```text
/data1/weibo/confs -> /data1/weibo/confs (read-only)
WEIBO_CONF_PATH=<source Docker Config.Env value>
```

If the source application obtains its config path or listen port from a native
environment variable, declare only that application-owned name. Use
`target.startup.port_environment` for the variable that receives
the native HTTP port resolved from recorder `http_gateway.matched_upstream`.
If the source uses an in-program default such as
`/data1/weibo/confs`, declare the mount and keep the same default; the engine
does not invent or rewrite an environment variable. Target product code must
not depend on generic `TRAFFIC_E2E_*` variables. Never derive inputs from
recordings, reports, source-process memory, or remote responses. Keep
credentials and generated trust below `.traffic-e2e/local/` and never copy
them into an image layer.

Create every image-local runtime-writable directory discovered during startup
inspection in `Dockerfile.e2e` with ownership `998:998`; the generated log
directory is only the bootstrap example. Use declared writable startup mounts
or `target.runtime_outputs` for paths supplied by traffic-e2e at runtime, and do
not bake their contents into the image.

The entrypoint must remain attached to the target process and handle `SIGTERM`
with bounded graceful shutdown. A Rust target uses `brz-logs` for application
logs as specified in [logs.md](logs.md); it does not duplicate those events to
stdout or stderr. Bootstrap failures before logging initializes may use
stderr. The image must create the configured log directory and make it writable
by UID 998; do not mount or copy source log content into it. The entrypoint must
not daemonize, write a PID file, run a build, or manage its own container.
traffic-e2e starts the container with `--user 998:998`, verifies that identity,
joins it to the run-owned network namespace, probes readiness from
the recorder-owned native HTTP port, and owns stop/removal. UID, network
namespace, mounts, and stop timeout are container-runtime inputs; the target
entrypoint must not parse or override them.

Initialization may provide an explicit source-controlled mock implementation
when genuine product startup is not implemented yet. The mock is the current
image entrypoint, not a fallback selected after a real startup failure. It must
honor the same declared mounts and application-owned environment, verify that
required mounts exist and are readable, bind `0.0.0.0` on the configured port,
satisfy the configured readiness path/status, stay in the foreground, emit
bounded lifecycle diagnostics through the target logging contract, and exit
cleanly on `SIGTERM`. A bootstrap-only mock that has no product logger yet may
use stdout or stderr. It must not emulate
business responses, dependencies, Replay, or Comparison. Replace it through
ordinary product implementation later without changing the container
contract. A mock that passes a real Replay proves only launch integration; it
is never API compatibility or workflow-completion evidence.

Replay and Comparison deliberately use different network policies around the
same immutable target image. Replay permits only coordinator-managed Replay
dependencies and must not provide a real external-network fallback. Comparison
uses the normal dependency network so candidate behavior can be observed
against the live source. The target image must not detect the phase and alter
business behavior.

When Breeze is configured, traffic-e2e mounts the managed
`/data1/breeze/socks` and `/data1/breeze/snapshot` paths and owns the shared
Breeze lifecycle. The target must use its normal Breeze client configuration;
it must not start Breeze or declare extra Breeze mounts.

For Replay only, when recorded traffic requires the target's directly emitted
TLS clients, traffic-e2e mounts the public Replay CA at
`/traffic-e2e/trust/replay-ca.pem`. When the project declares
`target.startup.replay_ca_environment`, traffic-e2e sets that application-owned
variable to this path. The target must add this public certificate to the
normal root set of every such TLS client, without replacing the normal roots,
disabling certificate verification, or receiving a private key. If the
declared variable is present and the certificate cannot be loaded, target
startup must fail. If the target emits no TLS dependency traffic, no
Replay-specific CA code is required.

Target code and configuration must never read cases, expected responses,
dependency recordings, Replay sessions, reports, coordinator state, or request
header encryption keys.

## Initialization Completion

Do not report initialization complete until all of the following are true:

- the initialization command succeeded, all three generated configuration
  files exist, and the root Cargo target template exists or an existing
  complete Cargo target was preserved;
- `Dockerfile.recording` exists, and the adaptor builds successfully without
  runtime secrets or generated trust material as
  `traffic-e2e/<project>-recording:cache`, bound to the configured source
  container's immutable image ID;
- when Breeze is enabled, `.traffic-e2e/MeshConnectUtil.class`
  and `.traffic-e2e/CommonSwitcher.class` exactly match the bundled assets; both
  replacements in the source Breeze SDK JAR are verified byte-for-byte,
  and the inspected source entrypoint and command remain unchanged;
- the initializer-created or extended `.gitignore` and `.dockerignore` retain
  their canonical local-state, build-output, recording, data, credential, and
  environment exclusions;
- `.traffic-e2e/Dockerfile.e2e` exists, uses the pinned builder and target
  runtime, and the system reports that it built successfully from the target
  repository root as `traffic-e2e/<project>-target:cache`;
- the built target image defaults to `998:998`, contains its executable OCI
  entrypoint, and contains no source, build cache, credential, generated trust,
  recording, or `.traffic-e2e/local/` content;
- the system reports `target_image.status = "passed"` for the startup snapshot,
  target build, and static image contract, including the immutable image ID,
  `linux/amd64`, default UID/GID `998:998`, OCI entrypoint, and environment
  constraints;
- the disposable recording preflight passed with the adapted source process
  running as `998:998`, system-owned Java probe execution and truststore setup
  completed when applicable, exactly one `demo.test` probe published as a
  Global dependency, exactly one cleanly published readiness case with its
  finalized source response, and, when Breeze is enabled, a successful
  `breeze.recording` lookup observed in `recording-network.json`;
- the disposable Replay network preflight consumed that Global probe through
  its assigned fake IP, rejected payload sent to unrecorded `example.com:443`
  with canonical endpoint evidence, rejected direct external egress for UID `998`, and
  completed cleanup;
- `target_runtime.status = "passed"` proves the same immutable target image
  satisfied readiness, identity, startup input, listener, graceful shutdown,
  and cleanup checks inside the recording-derived Replay namespace;
- one disposable source-adaptor startup was analyzed for configuration and
  Vintage access, background destinations and counts, and local-cache loading
  or refresh behavior, with temporary findings summarized only in the ignored
  `.traffic-e2e/local/block.md`; and
- the initialization changes contain no generated runtime data, credentials,
  recordings, or `.traffic-e2e/local/` content.

Initialization ends after these repository requirements are delivered. It
does not compare business behavior or invoke or advance the `backend-rewrite
next` workflow. Its disposable readiness recording, Replay network probes, and
target readiness run validate only the initialized recording and runtime
contracts; they are not API-compatibility evidence.

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
   `Dockerfile.recording`, the Breeze-only `.traffic-e2e/MeshConnectUtil.class`,
   and `.traffic-e2e/CommonSwitcher.class` when applicable,
   the generated or preserved root `Cargo.toml`, `Cargo.lock`, and
   `src/main.rs`, `.traffic-e2e/Dockerfile.e2e`, and the generated or extended
   root `.gitignore` and `.dockerignore`. Exclude unrelated work and all
   `.traffic-e2e/local/` content.
4. Push the necessary branches and create a PR whose target branch is
   `dev-migration`. Report the branch names and PR URL to the user.

If the user declines, stop after initialization and leave Git delivery to the
user. This optional delivery does not start or advance the rewrite workflow.
