# Platform Recording Runtime

Use this contract for the Platform department's Java/Tomcat services that use
Breeze and Vintage. Source startup details vary; the recording topology and
dependency interception do not.

## Fixed Topology

Use these pinned Linux/amd64 images:

```text
Anchor:
registry.api.demo.test/weibo_rd_if/traffic-e2e-network-anchor:0.0.1@sha256:095f39e3b242e744ec8f7d85e732bb663af8a4a02bdef0d7a216d2e66e365a62

Recorder:
registry.api.demo.test/weibo_rd_if/traffic-e2e-recorder-runtime:0.0.1-dev@sha256:c71fa374b229bc6fbf7ad34c5bb5cede1c27b2314a7b274b62ce2d44d3213107
```

Start one anchor with `--network host`. Start Recorder, Breeze, and the source
with `--network container:<anchor>`. Do not build project-specific Anchor or
Recorder images.

Resolve `traffic-e2e` through `PATH`, canonicalize its symlink with
`readlink -f`, and mount the resulting binary read-only into Recorder. Run
Recorder as root with `NET_ADMIN` and `NET_RAW`. Run Breeze with its inspected
root identity. Run only the genuine source Java process as numeric `998:998`.

## Fixed Recorder Policy

Render `assets/recording/recorder.toml.tmpl` without changing its policies. It
provides:

- fake DNS with Breeze snapshot bypass;
- the static `breeze.recording` interception name;
- TCP dependency recording and HTTPS MITM;
- Vintage `/naming/service` response rewriting;
- HTTP gateway port `17171` to source port `8080`;
- `/healthz` readiness with exact status `404`;
- `GET` recording over `/`, unrestricted matched forwarding, and fixed
  unmatched responses; and
- runtime CA files under ignored `.traffic-e2e/data`.

Mount the Breeze snapshot into Recorder at `/data1/breeze/snapshot` read-only.
Mount the rendered config, ignored data directory, recordings directory, and
control-socket directory once each under Recorder's `/workspace` layout.

## Inspect And Reproduce Startup

Inspect the source and Breeze containers for image identity, platform,
entrypoint, command, working directory, environment, bind mounts, capabilities,
security options, and ulimits. Preserve values required for genuine startup.
Store sensitive environment values only under `.traffic-e2e/.env/` with mode
`0600`; never print or commit them.

Preserve the inspected Breeze image and project-specific service pool. The
standard Breeze launch remains rooted in Vintage discovery, snapshot
`/data1/breeze/snapshot`, service path `/data1/breeze/socks`, log directory
`/data1/breeze/logs`, port `9984`, URL prefix
`static.config.api.demo.test`, and region `cn1`. Reproduce the actual container
command when its flag spelling or additional parameters differ.

The source image and start command are derived values, not user inputs. Keep
the source container's root initialization path. Replace only the final Java
application process with a recording launcher that uses:

```text
/usr/sbin/chroot --userspec=998:998 --groups=0
```

Preserve its working directory, executable, argv, environment, and signal
chain. Do not use PAM, `su`, or `runuser`.

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
Do not create per-run variants of source bind directories.

## Breeze SDK Source Patch

The Breeze patch changes the SDK inside the source application image, not the
Breeze container. Copy these assets unchanged into the source adapter:

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
    && /usr/local/bin/apply-breeze-sdk-patch
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

## Generate Start Recording

Implement `scripts/start-recording` from the inspected source and Breeze
parameters. Different Platform services may use different images, environment,
`NAME_CONF`, Breeze service pools, mounts, or root bootstrap commands; preserve
that evidence instead of forcing one universal Docker command.

Copy `assets/recording/mesh_switch_task.sh` unchanged to
`scripts/mesh_switch_task.sh`. Do not inline, reconstruct, or depend on a
host-installed copy of this script.

The generated script must accept:

```bash
./scripts/start-recording
./scripts/start-recording --duration-seconds <positive-integer>
./scripts/start-recording --mesh-only <true|false>
```

Default `mesh_only` to `true`. Accept only the literal values `true` and
`false`, reject missing, invalid, or duplicate values before changing runtime
state, and allow it to be combined with `--duration-seconds`. Require `nc` and
an executable repository copy of the asset during preflight. When true, run the
repository's `scripts/mesh_switch_task.sh` immediately after source port `880`
becomes available. When false, do not execute it.

Use this fixed lifecycle:

1. validate arguments and create ignored runtime directories;
2. build the source adapter with `--network none`;
3. prepare stable recording bind sources and their `998:998` ownership;
4. start Anchor and Recorder, then run `recording wait-listeners`;
5. prepare the source truststore;
6. start Breeze with its genuine Vintage configuration and wait for Breeze;
7. start the source with `MESH_CONNECT_HOST=breeze.recording`;
8. wait for source port `880`, verify the genuine Java process is `998:998`,
   then run `scripts/mesh_switch_task.sh` when `mesh_only` is true;
9. run `traffic-e2e recording wait-ready`;
10. record for the selected duration;
11. send `SIGINT` to Recorder, wait for drain and finalization, preserve
    diagnostics, and remove only containers created by this invocation.

Both Recorder wait commands use its control socket and default 300-second
timeouts. Do not parse `recorder.toml` in shell. Do not reject startup merely
because a host port probe reports another listener; let actual component
startup expose conflicts.

Use strict shell behavior, deterministic project-prefixed container names,
stage-aware idempotent cleanup, and `exec` in launchers. Never use `kill -9` as
the normal Recorder shutdown path.

## Validation

Before reporting completion:

- validate the rendered TOML and YAML with the installed `traffic-e2e`;
- run `bash -n` for both generated scripts;
- build the adapter without network access;
- verify the patched class exists in the source JAR;
- prove Breeze, port `880`, source readiness, UID/GID `998:998`, and fake-DNS
  resolution of `breeze.recording` under the source identity;
- run `./scripts/start-recording --duration-seconds 1`; and
- require finalized run metadata with no Recorder startup or shutdown error.

This validation proves ready-to-record state. It does not require a business
request or a published traffic case.
