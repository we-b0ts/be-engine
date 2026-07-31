# Platform Recording Runtime

Use this contract for the Platform department's Java/Tomcat services that use
Breeze and Vintage. Source startup details vary; the recording topology and
dependency interception do not.

## Contents

- Fixed topology
- Fixed Recorder policy
- Inspect and reproduce startup
- Source bind mounts
- Preserve the recording descriptor boundary
- Closed Mesh patch exception
- Low ports and CA
- Shared runtime validation

## Fixed Topology

Use these pinned Linux/amd64 images:

```text
Anchor:
registry.api.demo.test/weibo_rd_if/traffic-e2e-network-anchor:0.0.1@sha256:095f39e3b242e744ec8f7d85e732bb663af8a4a02bdef0d7a216d2e66e365a62

Recorder:
registry.api.demo.test/weibo_rd_if/traffic-e2e-recorder-runtime:0.0.1-dev@sha256:c71fa374b229bc6fbf7ad34c5bb5cede1c27b2314a7b274b62ce2d44d3213107

Breeze:
registry.api.demo.test/weibo_rd_if/breeze:v0.1.21-e2e@sha256:5aba065755724d43c7da3f6b79ac82890a0a0a08c6ae3f43af12558b5e52462f
```

Start one anchor with `--network host`. Start Recorder, Breeze, and the source
with `--network container:<anchor>`. Do not build project-specific Anchor or
Recorder images.

Resolve `traffic-e2e` through `PATH`, canonicalize its symlink with
`readlink -f`, and mount the resulting binary read-only into Recorder. Run
Recorder as root with `NET_ADMIN` and `NET_RAW`. Run Breeze with its inspected
root identity. Run only the genuine source Java process as numeric `998:998`.
The host `scripts/start-recording` process is the intended owner of finalized
recording artifacts; pass its numeric UID/GID to containerized Recorder through
`--artifact-owner`.

## Fixed Recorder Policy

Render `assets/recording/recorder.toml.tmpl` without changing its policies. It
provides:

- fake DNS with Breeze snapshot bypass;
- the static `breeze.recording` interception name;
- TCP dependency recording and HTTPS MITM;
- Vintage `/naming/service` response rewriting;
- HTTP gateway port `17171` to source port `8080`;
- `/healthz` readiness with exact status `404` and a fixed 10-second
  post-ready settle interval before first-case admission;
- `GET` recording over `/`, unrestricted matched forwarding, and fixed
  unmatched responses;
- commented HTTP and Breeze-backed Memcached background-rule shapes plus an
  empty AI-managed rule block; only evidence-backed `plan|apply` may populate
  it, and only an applied Memcached rule adds its configured first-load
  observation window;
- AES-256-GCM encryption of the request-side `authorization` header using
  `TRAFFIC_E2E_ENCRYPTION_KEY_B64`, while retaining response-side
  `authorization` redaction; and
- runtime CA files under ignored `.traffic-e2e/data`.

Mount the Breeze descriptor directory at `/data1/breeze/socks` and the snapshot
at `/data1/breeze/snapshot` into Recorder read-only. Mount the rendered config,
ignored data directory, recordings directory, and control-socket directory
once each under Recorder's `/workspace` layout.
Recorder uses `[dns_mock].upstream_dns` for both fake-DNS forwarding and the
local DNS interception bypass. Do not pass a separate `UPSTREAM_DNS`
environment variable.

## Inspect And Reproduce Startup

Inspect the source and Breeze containers for image identity, platform,
entrypoint, command, working directory, environment, bind mounts, capabilities,
security options, and ulimits. Preserve values required for genuine startup.
Initialize only the private `.traffic-e2e/boot/` root and do not populate it
during init. This is an input-only transport boundary; its name, existence,
and Git-ignore status do not establish provenance or authorize creating
content. Later source-proven setup may place allowed startup inputs there:

- use `.traffic-e2e/boot/config/` for complete files or directories
  synchronized from the source container, preserving their relationships;
- use `.traffic-e2e/boot/.env` for direct materialized environment variables;
- create purpose-named child directories for source-defined SDK snapshots or
  other machine-local startup dependencies only when needed.

Never derive boot content from source-process memory, remote responses,
recordings, logs, debug output, or diagnostics. Do not migrate or reuse a
legacy `.traffic-e2e/runtime/` tree wholesale. Use mode `0600` for sensitive
files; never print or commit boot inputs.

Merge the exact
[managed boot-input block](../assets/agents/boot-boundary.md) into the
repository-root `AGENTS.md`:

- create `AGENTS.md` when absent and append the block when its markers are
  absent;
- preserve all content outside the managed marker pair;
- replace only the managed range when one matched pair exists;
- reject unmatched markers or more than one marker pair.

The managed block contains policy only. Never write paths, names, or values
discovered from boot inputs into it.

Use the pinned Breeze E2E image and preserve the inspected project-specific
service pool. The standard Breeze launch remains rooted in Vintage discovery,
snapshot `/data1/breeze/snapshot`, service path `/data1/breeze/socks`, log
directory `/data1/breeze/logs`, and port `9984`. Reproduce the actual container
command and its remaining runtime values from inspected evidence.

The source image and start command are derived values, not user inputs. Keep
the source container's root initialization path. Replace only the final Java
application process with a recording launcher that uses:

```text
/usr/sbin/chroot --userspec=998:998 --groups=0
```

Preserve its working directory, executable, argv, environment, and signal
chain. Inside `chroot`, `cd` to the inspected working directory before
`exec`-ing the application; do not rely on the caller's working directory.
Do not use PAM, `su`, or `runuser`.

The adapter is a recording-only image. During its build, recursively assign
the complete application root to the recording identity:

```dockerfile
RUN chown -R 998:998 /data1/weibo
```

Do not substitute a narrower writable-directory guess. Root bootstrap remains
root and can still read or write this tree; the final Java process can then
read and write every application runtime path after dropping to `998:998`.

Reproduce the inspected effective `nofile` and `nproc` limits. Prove the
launcher does not introduce a lower per-user process limit before full
startup.

## Source Bind Mounts

For every private writable source bind:

```text
/data1/<project>/<path> -> /data1/<container-path>
```

create and mount:

```text
/data1/<project>-recording/<path> -> /data1/<container-path>
```

Do not copy original contents. Before startup, apply only to those exact new
host paths:

```bash
chown -hR 998:998 -- <path>
chmod -R u+rwX -- <path>
```

Preserve shared Platform mounts needed by Breeze instead of translating them.
The following host and container paths are fixed and must never become
`/data1/breeze-recording` or per-run directories:

```text
/data1/breeze/socks
/data1/breeze/snapshot
/data1/breeze/logs
```

Docker `-v` may recreate missing host directories as `root:root`. Therefore,
before every recording start, use a short-lived root helper container to
idempotently create and normalize exactly those three host directories:

```bash
mkdir -p \
  /host-data1/breeze/socks \
  /host-data1/breeze/snapshot \
  /host-data1/breeze/logs
chown -hR 998:998 -- \
  /host-data1/breeze/socks \
  /host-data1/breeze/snapshot \
  /host-data1/breeze/logs
chmod -R u+rwX -- \
  /host-data1/breeze/socks \
  /host-data1/breeze/snapshot \
  /host-data1/breeze/logs
chmod 2775 /host-data1/breeze/socks
chmod 0775 \
  /host-data1/breeze/snapshot \
  /host-data1/breeze/logs
```

Bind-mount host `/data1` at `/host-data1` for this helper when the login user
cannot repair the paths directly. Do not change the owner of the
`/data1/breeze` parent. Do not create per-run variants of source bind
directories.

## Preserve The Recording Descriptor Boundary

Initialization owns the shared `/data1/breeze/socks` mount and source Java SDK
behavior, not target Breeze SDK implementation. The source creates missing
descriptors during recording and the recording lifecycle preserves them. Do
not render observed resource ports into committed files or generate target
`brz-*` packages, application instructions, or SDK development documents.

Later target implementation must use
the [`breeze-sdk` skill](../../breeze-sdk/SKILL.md) for exact descriptor
identity and its generic `RequireExisting`, `EnsurePresent`, or `CreateNew`
descriptor policy. Recording initialization does not implement or expose that
target SDK lifecycle.

## Closed Mesh Patch Exception

This fixed Breeze Mesh patch is the sole source-bytecode exception in recording
initialization. It changes only how the existing SDK selects the TCP host so
the genuine dependency exchange can pass through Recorder. It must not change
resource identity, commands, values, cache semantics, business branching, or
responses.

Do not treat this exception as a source-adapter pattern. Never add another Java
source override, replace another class, patch another JAR, or modify the source
repository or business configuration. Missing evidence requires a
traffic-e2e capability diagnosis, not a new source patch.

The patch changes the SDK inside the source application image, not the Breeze
container. Copy these assets unchanged into the source adapter:

```text
assets/recording/source-adapter/MeshConnectUtil.java
assets/recording/source-adapter/apply-breeze-sdk-patch
```

Invoke the applicator during the adapter image build. It must find exactly one
`breeze-sdk-core-*.jar`, compile the fixed Java source against that image's
adjacent libraries, and replace only `MeshConnectUtil.class`. A missing,
ambiguous, or incompatible JAR is a hard initialization failure.

Use this fixed Dockerfile fragment after the inspected source `FROM` line:

```dockerfile
COPY MeshConnectUtil.java /usr/local/share/traffic-e2e/MeshConnectUtil.java
COPY apply-breeze-sdk-patch /usr/local/bin/apply-breeze-sdk-patch
RUN chmod 0755 /usr/local/bin/apply-breeze-sdk-patch \
    && /usr/local/bin/apply-breeze-sdk-patch \
    && chown -R 998:998 /data1/weibo
```

Start the source with:

```text
MESH_CONNECT_HOST=breeze.recording
```

The resulting dependency route is:

```text
source Breeze SDK
  -> breeze.recording
  -> fake DNS
  -> Recorder TCP gateway
  -> 127.0.0.1:<dynamic Breeze SDK port>
```

## Low Ports And CA

Platform source services may bind port `880` while running as UID 998. Resolve
the real Java executable in the adapter image, register only its required JDK
library directories with the loader, run `ldconfig`, and apply
`cap_net_bind_service=+ep`. Prove the exact Java executable starts under the
recording launcher before full startup.

Start Recorder first and run `traffic-e2e recording wait-listeners`; this
creates and validates the CA pair. Mount only the public CA certificate into
the source. Build a recording-only Java truststore under ignored
`.traffic-e2e/data`, import that CA, and point the recording JVM at it. Never
copy the private CA key into the source container.

## Shared Runtime Validation

- Validate the rendered TOML and YAML with the installed `traffic-e2e`.
- Build the adapter without network access and verify that the patched class
  exists in the source JAR.
- Prove Breeze, port `880`, source readiness, UID/GID `998:998`, and fake-DNS
  resolution of `breeze.recording` under the source identity.
- Prove source startup creates or reuses descriptors in the shared
  `/data1/breeze/socks` mount without generating target SDK code or
  repository-level SDK instructions.

Run the standard and comparison validation defined in their respective
references before reporting initialization complete.
