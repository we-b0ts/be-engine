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

Do not declare or persist a source language. During every managed recording,
traffic-e2e tests the completed source adaptor image in a disposable,
network-disabled container as `998:998`, overriding its entrypoint to run only
`java -version`. It grants only `NET_BIND_SERVICE` so the contract's
capability-bearing Java executable remains runnable, but it does not start the
business entrypoint or mount business data. A successful probe selects the
fixed Java 8 truststore probe; otherwise the system-owned network probe is used.

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
`998:998`. Because `880` is a privileged port, grant
`cap_net_bind_service=+ep` only to the real source executable; do not run the
application as root or make the container privileged. For Java, resolve the
real Java executable behind any symlink. A capability-bearing Java executable
enters secure loader mode, so add its resolved `libjli.so` directory to the
system dynamic loader configuration and run `ldconfig` during the image build.
Fail the build unless `getcap` confirms the expected capability.

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
preflight` owns three ordered phases: `target_container`, defined below,
`recording`, and `replay_network`. Run it from the target repository after the
generated configuration, `Dockerfile.recording`,
`traffic-e2e/<project>-recording:cache`, `.traffic-e2e/Dockerfile.e2e`, and
`.dockerignore` exist. Provide the same
`TRAFFIC_E2E_ENCRYPTION_KEY_B64` required by managed recording. The command
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
3. Start the source adaptor with the inspected source runtime inputs and the
   explicit adaptor entrypoint. Mount the generated truststore read-only only
   when the system detected Java.
4. Verify the source entrypoint runs as UID/GID `998:998`, its port
   `880` listener is reachable without root or privileged-container execution,
   Breeze is ready when enabled, the source readiness contract passes, and
   Recorder admits cases.
5. After source readiness, send exactly one GET to `https://demo.test/`. When
   the system detected Java, execute the bundled Java 8 class inside the source
   adaptor and require it to
   use the mounted Java truststore through `JAVA_TOOL_OPTIONS`, the same trust
   path as the source application. Otherwise execute the pinned
   `traffic-e2e-network-probe:0.0.1` image as `998:998` in the Recorder
   anchor namespace with the public Recorder CA mounted read-only. Probe
   failure fails the phase; never fall back from the Java probe to the generic
   probe because doing so would mask a Java truststore defect.
6. After the command reports
   `phase = "preflight-business-input-required"`, admit the controlled request
   matching the configured HTTP gateway rule,
   using the rule's declared method without a separate read-only-method
   restriction. Finalize the disposable run and require a clean manifest with
   at least one published case and its source response.
7. Require Recorder to publish exactly that successful `demo.test` exchange
   once in `global-dependencies.jsonl` with
   `global_dependency_reason = "preflight_probe"`, runtime phase, and
   `java_truststore` or `system_network` attribution. Do not enable full
   `traffic.jsonl`, accept an arbitrary HTTPS exchange, or synthesize Global
   evidence from another file.
8. Start a disposable real Replay session over the recording run. In a
   Replay-owned host network namespace, run the fixed network probe image as
   `998:998`: require `demo.test` to resolve to its assigned fake IP, return the
   recorded response, and consume one Global HTTP exchange; require
   `example.com` to be absent from Replay targets and fail DNS resolution; and
   require a direct real-IP egress attempt to be rejected. This phase does not
   start the target or activate a business case. Stop Replay and remove the
   namespace before returning.
9. Await the final result. Do not infer success from probe output alone. Only
   overall `status = "passed"` with all three phase results is authoritative.

Run this through the same managed recording machinery used by backend-rewrite
for normal source recording, including Recorder, network isolation, the source
adaptor, optional Breeze, CA creation, readiness, finalization, and cleanup.
Keep its run identity and artifacts in a dedicated preflight area below
`.traffic-e2e/local/preflight/<run-id>/`; never publish them as the workflow's
standard recording, Replay, or comparison evidence. Success output reports
`status = "passed"`, the isolated manifest, `published_cases`, exact Global
probe verification, and the bounded Replay positive/negative/egress result.
The command fails when no complete case is recorded, the required probe is not
published exactly once, Replay cannot consume it, unrecorded DNS resolves, or
external egress is available. The recording phase does not start the target;
the preceding `target_container` phase starts it only for the bounded
launch-contract check, while `replay_network` starts Replay and its probe but
not the target. No phase initializes API inventory or
advances coordinator workflow state. Do not invoke
`backend-rewrite next` to manufacture this check. If image construction, source
identity, readiness, CA truststore setup, request admission, case publication,
finalization, or cleanup fails, initialization is incomplete.

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
target or mock implementation. It invokes `backend-rewrite init preflight` and
consumes its bounded result; direct Docker commands, AI narration, and
self-reported checks are never initialization evidence.

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

FROM registry.api.demo.test/weibo_rd_if/traffic-e2e-rust-runtime:0.0.1@sha256:63072803f35282f2134f08779bd1652e51c4ff30ba08728716b616ef96b3dc80
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
one foreground process. traffic-e2e passes no application CLI arguments. The
process must read these required environment variables:

```text
TRAFFIC_E2E_CONFIG_DIR=/traffic-e2e/config
TRAFFIC_E2E_TARGET_PORT=<configured target.port>
```

The coordinator creates the ignored host boot directory when needed and mounts
`.traffic-e2e/local/boot` read-only at `/traffic-e2e/config`. The target must use
that exact configuration root and port rather than a repository-local default.
Use the config root only for authoritative source-compatible runtime inputs;
never derive inputs from recordings, reports, source-process memory, or remote
responses. Keep credentials and generated trust below `.traffic-e2e/local/`
and never copy them into an image layer.

The entrypoint must emit application logs to stdout/stderr, remain attached to
the target process, and handle `SIGTERM` with bounded graceful shutdown. It must
not daemonize, write a PID file, run a build, or manage its own container.
traffic-e2e starts the container with `--user 998:998`, verifies that identity,
joins it to the run-owned network namespace, probes readiness from
`target.port`, and owns stop/removal. UID, network namespace, mounts, and stop
timeout are container-runtime inputs; the target entrypoint must not parse or
override them.

Initialization may provide an explicit source-controlled mock implementation
when genuine product startup is not implemented yet. The mock is the current
image entrypoint, not a fallback selected after a real startup failure. It must
honor the same configuration-root and port variables, verify that the mounted
configuration root exists and is readable, bind `0.0.0.0` on the supplied
port, satisfy the configured readiness path/status, stay in the foreground,
log to stdout/stderr, and exit cleanly on `SIGTERM`. It must not emulate
business responses, dependencies, Replay, or Comparison. Replace it through
ordinary product implementation later without changing the container
contract. A runnable mock proves only initialization and launch integration;
it is never API compatibility or workflow-completion evidence.

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
`/traffic-e2e/trust/replay-ca.pem` and sets
`TRAFFIC_E2E_REPLAY_CA_CERT_PATH` to that path. The target must add this public
certificate to the normal root set of every such TLS client, without replacing
the normal roots, disabling certificate verification, or receiving a private
key. If the variable is present and the certificate cannot be loaded, target
startup must fail. If the target emits no TLS dependency traffic, no
Replay-specific CA code is required.

Target code and configuration must never read cases, expected responses,
dependency recordings, Replay sessions, reports, coordinator state, or request
header encryption keys.

### Target-Container Phase Of The Initialization Preflight

As the first phase of the existing `backend-rewrite init preflight`,
traffic-e2e builds `traffic-e2e/<project>-target:cache` and runs one disposable
target-container check. Do not accept a successful image build as proof that
its entrypoint can run. This is not a separate user-facing command. The system,
not the target AI, performs every step below:

1. Resolve the cache tag to its immutable image ID and create a run-private
   internal Docker network with no external-network route.
2. Ensure the ignored `.traffic-e2e/local/boot` directory exists, then start
   that image ID with `--user 998:998`, its config bind-mounted read-only at
   `/traffic-e2e/config`, `TRAFFIC_E2E_CONFIG_DIR=/traffic-e2e/config`, and
   `TRAFFIC_E2E_TARGET_PORT=<configured target.port>`. Pass no application CLI
   arguments. Do not mount recordings, reports, source code, a build cache, or
   a Replay CA private key.
3. Verify the running foreground process has UID/GID `998:998`, the config
   mount is read-only, the configured port is listening, and the configured
   readiness path returns the configured final status. Use an external probe;
   do not add curl or another probe tool to the target image.
4. Read bounded `docker logs` output to confirm application output is on
   stdout/stderr, send `SIGTERM` through the normal container stop operation,
   require a clean exit within a bounded initialization timeout, and remove the
   container and private network.

When Breeze is configured, additionally provide the same managed
`/data1/breeze/socks` and `/data1/breeze/snapshot` mounts that later runs use;
the target or mock may ignore them until it owns a genuine Breeze client. Do
not start Breeze merely to make this launch-contract preflight pass. Replay CA
trust is not tested by a mock that emits no TLS traffic; validate it when a
genuine target TLS client is first implemented.

Fail initialization when the build, identity, required environment, mount,
foreground lifetime, readiness, logging, signal handling, clean exit, or
cleanup contract fails. Keep preflight state below `.traffic-e2e/local/` and
never publish it as recording, Replay, Comparison, or migration evidence.
The command returns one bounded structured result containing overall `status`,
separate `target_container` and `recording` phase results, the immutable target
`image_id`, each named target check, cleanup status, and one failure
stage/reason when applicable. It starts `recording` only after
`target_container` passes. Only overall system-reported `status = "passed"` is
authoritative. The target AI may repair the named source-controlled cause and
invoke the same command again; it must not substitute manual Docker output or
its own conclusion.

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
- `.traffic-e2e/Dockerfile.e2e` exists, uses the pinned builder and target
  runtime, and the system reports that it built successfully from the target
  repository root as `traffic-e2e/<project>-target:cache`;
- the root `.dockerignore` excludes `.git/`, `.traffic-e2e/local/`, `target/`,
  recordings, credentials, and other runtime-only inputs from the build
  context;
- the built target image defaults to `998:998`, contains its executable OCI
  entrypoint, and contains no source, build cache, credential, generated trust,
  recording, or `.traffic-e2e/local/` content;
- the system reports `status = "passed"` for the disposable target-container
  preflight, including the required environment and mounts, UID/GID `998:998`,
  configured listening port and readiness result, stdout/stderr logging,
  bounded `SIGTERM` shutdown, and complete cleanup; an explicit mock is allowed
  but is not business evidence;
- the disposable recording preflight passed with the adapted source process
  running as `998:998`, system-owned Java probe execution and truststore setup
  completed when applicable, exactly one `demo.test` probe published as a
  Global dependency, and one cleanly published case;
- the disposable Replay network preflight consumed that Global probe through
  its assigned fake IP, blocked DNS for unrecorded `example.com`, rejected
  direct external egress for UID `998`, and completed cleanup; and
- the initialization changes contain no generated runtime data, credentials,
  recordings, or `.traffic-e2e/local/` content.

Initialization ends after these repository requirements are delivered. It
leaves no target running and does not start Replay, compare, or invoke or
advance the `backend-rewrite next` workflow. Its disposable source recording
and target-container run exist only to validate the initialized environments.

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
   when applicable, `.traffic-e2e/Dockerfile.e2e`, the root `.dockerignore`, the
   root-scoped `.gitignore` update, and any minimal target scaffold required for
   its release build. Exclude unrelated work and all `.traffic-e2e/local/`
   content.
4. Push the necessary branches and create a PR whose target branch is
   `dev-migration`. Report the branch names and PR URL to the user.

If the user declines, stop after initialization and leave Git delivery to the
user. This optional delivery does not start or advance the rewrite workflow.
