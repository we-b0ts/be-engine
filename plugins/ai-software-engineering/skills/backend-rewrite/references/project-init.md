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
  [--startup-mount /data1/weibo/confs] \
  [--startup-env WEIBO_CONF_PATH] \
  [--target-port-env PORT] \
  [--replay-ca-env SSL_CERT_FILE] \
  [--http-gateway-port 17171]
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

- HTTP recording gateway `17171`;
- recorder native HTTP upstream `http://127.0.0.1:8080`;
- readiness `/healthz` with final status `404`; and
- upstream DNS `10.10.10.11:53`.

Only `--http-gateway-port` is exposed for port selection during initialization.
For a non-standard native service port, update
`http_gateway.matched_upstream` in the generated recorder configuration; the
target uses that same port in its isolated runtime namespace.

The command atomically creates exactly these source-controlled files:

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

It also idempotently adds `/.traffic-e2e/local/` to `.gitignore`. It refuses
the whole initialization when any generated file already exists, and it does
not start containers, record traffic, or create runtime evidence. It captures
the declared startup inputs below `.traffic-e2e/local/startup/` from the
configured stopped source container.

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

After both repository image contracts are ready, invoke the single
coordinator-owned initialization preflight before reporting initialization
complete:

```bash
backend-rewrite init preflight \
  --api '<METHOD path-or-pattern>' \
  --duration-seconds 60
```

Do not create another target-validation command. `backend-rewrite init
preflight` owns three ordered phases: `target_image`, defined below,
`recording`, and `replay_network`. Run it from the target repository after the
generated configuration, `Dockerfile.recording`,
`.traffic-e2e/Dockerfile.e2e`, and `.dockerignore` exist. The recording phase
builds the adaptor image when it is absent or bound to another source image.
The configured source container must remain stopped. Provide the
same `TRAFFIC_E2E_ENCRYPTION_KEY_B64` required by managed recording. The command
defaults each selected API to one admitted case and opens a bounded recording
window; while it is running, send one deterministic
controlled business request to the configured HTTP gateway port. The system
independently sends one exact HTTPS probe. The business request must match the
selected API. The command does
not invent its path, request body, or business input because those values must
come from the inspected source contract.

1. Start Recorder first so it creates its runtime CA. When Java was detected,
   create a Java truststore from that public certificate without copying the CA
   private key into either image.
2. When Breeze is enabled, start the fixed Breeze image with the inspected
   Breeze runtime arguments.
3. Start the source adaptor with runtime inputs inspected from the configured,
   stopped source container and its preserved entrypoint. Mount the
   generated truststore read-only only when the system detected Java.
4. Verify the source entrypoint runs as UID/GID `998:998`, Breeze is ready when
   enabled, the configured source readiness contract passes, and Recorder
   admits cases. Do not wait for or send commands to source port `880`.
5. When Breeze is enabled, resolve `breeze.recording` explicitly inside the
   source adaptor as UID/GID `998:998` after Recorder is ready. Require a
   non-empty IPv4 result, then after finalization require
   `recording-network.json` to contain the canonical `breeze.recording` DNS
   observation. A local hosts-file result or another DNS path that Recorder did
   not observe does not pass initialization.
6. After source readiness, send exactly one GET to `https://demo.test/`. When
   the system detected Java, execute the bundled Java 8 class inside the source
   adaptor and require it to
   use the mounted Java truststore through `JAVA_TOOL_OPTIONS`, the same trust
   path as the source application. Otherwise execute the pinned
   `traffic-e2e-network-probe:0.0.1` image as `998:998` in the Recorder
   anchor namespace with the public Recorder CA mounted read-only. Probe
   failure fails the phase; never fall back from the Java probe to the generic
   probe because doing so would mask a Java truststore defect.
7. After the command reports
   `phase = "preflight-business-input-required"`, admit the controlled request
   matching the configured HTTP gateway rule,
   using the rule's declared method without a separate read-only-method
   restriction. Finalize the disposable run and require a clean manifest with
   at least one published case and its source response.
8. Require Recorder to publish exactly that successful `demo.test` exchange
   once in `global-dependencies.jsonl` with
   `global_dependency_reason = "preflight_probe"`, runtime phase, and
   `java_truststore` or `system_network` attribution. Do not enable full
   `traffic.jsonl`, accept an arbitrary HTTPS exchange, or synthesize Global
   evidence from another file.
   If the selected business case reaches its limit while this probe is still
   starting, `--preflight-probe` keeps Recorder listeners available for one
   fixed 15-second grace period before case-limit shutdown. This grace does not
   wait for probe evidence and the Java probe command itself is bounded to 10
   seconds, so a broken source container cannot hold shutdown indefinitely.
9. Start a disposable real Replay session over the recording run. In a
   Replay-owned host network namespace, run the fixed network probe image as
   `998:998`: require `demo.test` to resolve to its assigned fake IP, return the
   recorded response, and consume one Global HTTP exchange; require
   `example.com:443` to be absent from recorded Replay targets, have its
   connection rejected, and appear exactly once in `unrecorded_targets` with
   the canonical unrecorded-endpoint reason; and require a direct real-IP
   egress attempt to be rejected. This phase does not start the target or
   activate a business case. Stop Replay and remove the namespace before
   returning.
10. Await the final result. Do not infer success from probe output alone. Only
    overall `status = "passed"` with all three phase results is authoritative.

Run this through the same managed recording machinery used by backend-rewrite
for normal source recording, including Recorder, network isolation, the source
adaptor, optional Breeze, CA creation, readiness, finalization, and cleanup.
Keep its run identity and artifacts in a dedicated preflight area below
`.traffic-e2e/local/preflight/<run-id>/`; never publish them as the workflow's
standard recording, Replay, or comparison evidence. Success output reports
`status = "passed"`, the isolated manifest, `published_cases`, exact Global
probe verification, Breeze DNS verification when configured, and the bounded
Replay positive/negative/egress result.
The command fails when the target image cannot be built or violates its static
image contract, no complete case is recorded, the required probe is not
published exactly once, Replay cannot consume it, an unrecorded endpoint is
not rejected with evidence, or external egress is available. No initialization phase starts the target;
`replay_network` starts Replay and its probe but not the target. No phase initializes API inventory or
advances coordinator workflow state. Do not invoke
`backend-rewrite next` to manufacture this check. If image construction, source
identity, source readiness, CA truststore setup, request admission, case
publication, finalization, or cleanup fails, initialization is incomplete.

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

Declare each source-proven authoritative local configuration file or root by
its normalized absolute source path through repeatable `--startup-mount`
arguments. Source containers commonly keep runtime configuration below
`/data1` or `/data0`; inspect both locations together with the proved startup
loader and container mounts. Initialization copies every declared path below
`.traffic-e2e/local/startup/mounts` with its source path preserved, for example
`/data1/authconfs` as
`.traffic-e2e/local/startup/mounts/data1/authconfs`. Declare each required
Docker `Config.Env` name through repeatable `--startup-env` arguments; the
engine freezes its value without printing it. Do not copy selected keys,
generated loader or SDK snapshots, local caches, decrypted output, remote
responses, logs, or process memory into startup inputs. Keep credentials and
other sensitive values out of commands and summaries and never commit the
local startup snapshot.

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

The same initialization task must create this source-controlled target build
and launch contract:

```text
.traffic-e2e/Dockerfile.e2e
.dockerignore
```

The target image's OCI entrypoint is the target launch contract used by
traffic-e2e. traffic-e2e owns `docker build`, `docker run`, readiness,
`docker stop`, and `docker rm`.

The target AI owns only the source-controlled Dockerfile, `.dockerignore`, and
target or mock implementation. It invokes `backend-rewrite init preflight` for
the build and static image contract, then consumes coordinator-owned Replay
results for the runtime contract; direct Docker commands, AI narration, and
self-reported checks are never evidence.

### Build One Reproducible Target Image

`Dockerfile.e2e` must be a BuildKit multi-stage build. Use the pinned shared
Rust builder and target runtime images:

```dockerfile
FROM registry.api.demo.test/weibo_rd_if/traffic-e2e-rust-builder:1.97.1@sha256:99663c03c7da6d638f9bef5d84d923840e2069e3f32067851b43ea7abf3f0004 AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo
COPY . .
RUN --mount=type=cache,id=traffic-e2e-cargo-registry,target=/opt/rust/cargo/registry,sharing=locked \
    --mount=type=cache,id=traffic-e2e-cargo-git,target=/opt/rust/cargo/git,sharing=locked \
    --mount=type=cache,id=traffic-e2e-<project>-target,target=/build/target,sharing=locked \
    cargo build --locked --release --bin <project> \
    && binary="$(find /build/target -type f -path '*/release/<project>' -print -quit)" \
    && test -n "${binary}" \
    && install --directory /out \
    && install --mode 0755 "${binary}" /out/<project>

FROM registry.api.demo.test/weibo_rd_if/traffic-e2e-rust-runtime:0.0.2@sha256:d322b050229334c2fec00cdce366a066697a7bafaf9b6842d77793eb1e4f10d2
COPY --from=builder --chown=998:998 /out/<project> /app/bin/<project>
ENTRYPOINT ["/app/bin/<project>"]
```

Adapt copied manifests, paths, and the normal Cargo command to the proved
workspace, but preserve the contract. Copy manifests before the source tree
when the workspace layout permits it. The build context is the target
repository root. Include all source and source-controlled build inputs required
by the normal release build; exclude `.git/`, `.traffic-e2e/local/`, `target/`,
recordings, credentials, and other runtime data through the root
`.dockerignore`. BuildKit cache mounts may persist Cargo registry, Cargo Git,
and `target` compilation data between builds. Use stable shared IDs for Cargo
registry and Git caches and a stable project-specific ID for the `target`
cache. A source-only change reruns `cargo build` but does not redownload cached
dependencies or rebuild unaffected dependency artifacts. Copy the finished
binary to a non-cache path such as `/out` in the same `RUN`. The caches are not
final-image content. Do not bind-mount a host binary, source tree, Cargo
registry, or `target` directory when the target container runs.

Do not add an external Dockerfile `# syntax=` frontend. The managed build uses
the Docker daemon's BuildKit frontend so initialization never depends on
Docker Hub; the required cache-mount syntax is validated by the real build.

The final stage contains only the release binary and its proved runtime assets.
It inherits `trp-record` UID/GID `998:998` and `USER 998:998` from the shared
runtime. Do not recreate that account. A target Dockerfile that temporarily
uses root to install an asset must restore `USER 998:998` before its
entrypoint. Do not add nscd, systemd, sudo, Docker, iptables, a daemon
supervisor, or a traffic-e2e binary to the target image.

During initialization, traffic-e2e builds from the repository root with
BuildKit and tags the local result as `traffic-e2e/<project>-target:cache`,
where `<project>` is the lowercase normalized repository directory name.
Building is required; pushing a project-specific target image is not. Later
workflow runs rebuild only when the target build fingerprint changes and
otherwise reuse the cache. traffic-e2e resolves the tag to one immutable image
ID before a validation round and uses that exact image ID for both Replay and
Comparison. It never rebuilds between the two phases for the same target
revision.

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

The entrypoint must emit application logs to stdout/stderr, remain attached to
the target process, and handle `SIGTERM` with bounded graceful shutdown. It must
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
satisfy the configured readiness path/status, stay in the foreground, log to
stdout/stderr, and exit cleanly on `SIGTERM`. It must not emulate
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

### Target-Image Phase Of The Initialization Preflight

As the first phase of the existing `backend-rewrite init preflight`,
traffic-e2e builds `traffic-e2e/<project>-target:cache` without starting its
entrypoint. The system, not the target AI, performs every step below:

1. Validate the immutable startup snapshot, pinned multi-stage Dockerfile,
   required BuildKit caches, and root `.dockerignore` exclusions.
2. Build the image from the target repository root, resolve the cache tag to
   the exact immutable image ID produced by that build, and inspect that image.
3. Require `linux/amd64`, default `USER 998:998`, a non-empty OCI entrypoint,
   no default command arguments, and no persisted proxy or traffic-e2e secret
   environment variables.

Fail initialization when the build or static image contract fails. The command
returns one bounded structured result containing overall `status`, separate
`target_image`, `recording`, and `replay_network` phase results, the immutable
target image ID, named static checks, and one failure stage/reason when
applicable. It starts `recording` only after `target_image` passes. Only overall
system-reported `status = "passed"` is authoritative.

### Target Runtime Checks During Replay

Do not start the target in a dependency-free initialization namespace. A
completed implementation may require Vintage or another dynamic startup
dependency, so that launch would be neither stable nor representative. Every
real Replay starts the immutable target image only after Replay dependencies
are ready, then the coordinator verifies:

1. PID 1 runs as UID/GID `998:998`; declared startup environment is present;
   generic `TRAFFIC_E2E_*` environment is absent; and `MESH_CONNECT_HOST` is
   present for Breeze-enabled targets.
2. Declared startup mounts, the public Replay CA, and managed Breeze mounts
   when enabled are present with the required access mode.
3. The configured readiness path reaches its final status and the target is
   listening on `0.0.0.0` at the configured port.
4. Bounded stdout/stderr output is available. At the end of Replay, normal
   `SIGTERM` shutdown exits cleanly and the target container and namespace are
   removed.

The run stores the successful launch checks in
`reports/target-runtime-checks.json`; target start, bounded logs, runtime state,
and stop evidence remain in the same Replay report directory. A failed runtime
check fails that Replay and is returned through the normal implementation
repair path. The target AI may repair the named source-controlled cause and
rerun the coordinator-issued Replay command; it must not substitute manual
Docker output or its own conclusion.

## Initialization Completion

Do not report initialization complete until all of the following are true:

- the initialization command succeeded and all three generated configuration
  files exist;
- `Dockerfile.recording` exists, and the adaptor builds successfully without
  runtime secrets or generated trust material as
  `traffic-e2e/<project>-recording:cache`, bound to the configured source
  container's immutable image ID;
- when Breeze is enabled, `.traffic-e2e/MeshConnectUtil.class`
  and `.traffic-e2e/CommonSwitcher.class` exactly match the bundled assets; both
  replacements in the source Breeze SDK JAR are verified byte-for-byte,
  and the inspected source entrypoint and command remain unchanged;
- the repository `.gitignore` contains the root-scoped
  `/.traffic-e2e/local/` entry;
- `.traffic-e2e/Dockerfile.e2e` exists, uses the pinned builder and target
  runtime, and the system reports that it built successfully from the target
  repository root as `traffic-e2e/<project>-target:cache`;
- the root `.dockerignore` excludes `.git/`, `.traffic-e2e/local/`, `target/`,
  recordings, credentials, and other runtime-only inputs from the build
  context;
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
  Global dependency, one cleanly published case, and, when Breeze is enabled,
  a successful `breeze.recording` lookup observed in `recording-network.json`;
- the disposable Replay network preflight consumed that Global probe through
  its assigned fake IP, rejected payload sent to unrecorded `example.com:443`
  with canonical endpoint evidence, rejected direct external egress for UID `998`, and
  completed cleanup;
- one disposable source-adaptor startup was analyzed for configuration and
  Vintage access, background destinations and counts, and local-cache loading
  or refresh behavior, with temporary findings summarized only in the ignored
  `.traffic-e2e/local/block.md`; and
- the initialization changes contain no generated runtime data, credentials,
  recordings, or `.traffic-e2e/local/` content.

Initialization ends after these repository requirements are delivered. It
does not start the target, compare, or invoke or advance the `backend-rewrite
next` workflow. Its disposable source recording and Replay network probe exist
only to validate the initialized recording environment. The first real Replay
that starts a target validates the runtime launch contract.

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
   `.traffic-e2e/Dockerfile.e2e`, the root `.dockerignore`, the root-scoped
   `.gitignore` update, and any minimal target scaffold required for its
   release build. Exclude unrelated work and all `.traffic-e2e/local/`
   content.
4. Push the necessary branches and create a PR whose target branch is
   `dev-migration`. Report the branch names and PR URL to the user.

If the user declines, stop after initialization and leave Git delivery to the
user. This optional delivery does not start or advance the rewrite workflow.
