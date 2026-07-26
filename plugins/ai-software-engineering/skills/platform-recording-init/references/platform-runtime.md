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
- `/healthz` readiness with exact status `404` and a fixed 10-second
  post-ready settle interval before first-case admission;
- `GET` recording over `/`, unrestricted matched forwarding, and fixed
  unmatched responses; and
- runtime CA files under ignored `.traffic-e2e/data`.

Mount the Breeze snapshot into Recorder at `/data1/breeze/snapshot` read-only.
Mount the rendered config, ignored data directory, recordings directory, and
control-socket directory once each under Recorder's `/workspace` layout.
Recorder uses `[dns_mock].upstream_dns` for both fake-DNS forwarding and the
local DNS interception bypass. Do not pass a separate `UPSTREAM_DNS`
environment variable.

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

## Generate Start Recording

Implement `scripts/start-recording` from the inspected source and Breeze
parameters. Different Platform services may use different images, environment,
`NAME_CONF`, Breeze service pools, mounts, or root bootstrap commands; preserve
that evidence instead of forcing one universal Docker command.

Copy `assets/recording/brz-no-fallback.sh` unchanged to
`scripts/brz-no-fallback.sh`. Do not inline, reconstruct, or depend on a
host-installed copy of this script.

The generated script must accept:

```bash
./scripts/start-recording
./scripts/start-recording --run-id YYYYMMDDHHMMSS
./scripts/start-recording --duration-seconds <positive-integer>
./scripts/start-recording --brz-no-fallback <true|false>
./scripts/start-recording --api 'GET /api/widgets/*'
```

Default `brz_no_fallback` to `true`. Accept only the literal values `true` and
`false`. Default `duration_seconds` to `60` when omitted. AI and automated
invocations must explicitly pass `--duration-seconds 60` or another positive
integer. Require `--run-id` to be a valid 14-digit UTC timestamp. Reject
missing, invalid, or duplicate values before changing runtime state, allow all
options to combine, accept repeatable canonical `--api` selectors, and pass
the run ID and API selectors through unchanged to `traffic-e2e record`.
Require `nc` and an executable repository copy of the asset during preflight.
When `brz_no_fallback` is true, run the repository's
`scripts/brz-no-fallback.sh` immediately after source port `880` becomes
available. When false, do not execute it.

Use this fixed lifecycle:

1. validate arguments and create ignored runtime directories;
2. build the source adapter with `--network none`;
3. prepare stable private recording bind sources and normalize the three
   shared Breeze directories to `998:998`;
4. start Anchor and Recorder, then run `recording wait-listeners`;
5. prepare the source truststore;
6. start Breeze with its genuine Vintage configuration and wait for Breeze;
7. start the source with `MESH_CONNECT_HOST=breeze.recording`;
8. wait for source port `880`, verify the genuine Java process is `998:998`,
   then run `scripts/brz-no-fallback.sh` when `brz_no_fallback` is true;
9. run `traffic-e2e recording wait-ready`; this already waits through the
   configured post-ready settle interval, so do not add another shell sleep;
10. record for the selected duration;
11. send `SIGINT` to Recorder, wait for drain and finalization, preserve
    diagnostics, and remove only containers created by this invocation.

Run both Recorder wait commands through `docker exec` inside the Recorder
container, using the container's control-socket path. They default to
300-second timeouts. Do not access the bind-mounted socket from the host or
parse `recorder.toml` in shell. Do not reject startup merely because a host
port probe reports another listener; let actual component startup expose
conflicts.

Use strict shell behavior, deterministic project-prefixed container names,
stage-aware idempotent cleanup, and `exec` in launchers. Never use `kill -9` as
the normal Recorder shutdown path.

## Generate Comparison Recording

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
Require `--run-id` to be a valid 14-digit UTC timestamp. Allow every option to
combine, reject missing, invalid, or duplicate option values before changing
runtime state, and accept repeatable canonical `--api` selectors. Consume
`--brz-no-fallback` in the wrapper; pass the run ID, duration, baseline recheck,
and API selectors through unchanged to `traffic-e2e record-comparison`.

Start exactly one Breeze container for comparison and connect both the genuine
source container and candidate container to that same instance with their
normal dependency configuration. Do not start a Breeze per application.
`brz-no-fallback.sh` controls application-side fallback behavior, so when the
option is true, execute the mounted repository script against the source and
against every candidate runtime that exposes the Platform mesh control
endpoint after each becomes ready. Treat a required but unreachable control
endpoint as startup failure. When false, skip those commands. Use this
lifecycle:

1. validate arguments and create ignored runtime directories;
2. create the comparison network topology and start one genuine inspected
   Breeze instance without Recorder dependency interception;
3. start the genuine inspected source as the baseline and connect it to the
   shared Breeze;
4. invoke `scripts/<project>-cli stop` to remove only a stale owned candidate,
   then invoke `start`, connect the candidate to the same Breeze, and require
   `status` to succeed;
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
evidence is needed.

After a run with frontend cases finalizes, verify it offline:

```bash
traffic-e2e compare \
  .traffic-e2e/artifacts/comparison-recordings/<run-id> \
  --policy .traffic-e2e/verification.yaml
```

This command is file-only and must not enable isolation. It writes
`comparison-report.json` by default and reuses only the shared verification
policy's response rules. A changed optional source recheck is `source_drift`
and remains inconclusive; it must not be attributed to candidate code or
automatically exempted. Use `--comparison-report` with
`traffic-e2e config replay plan|apply response-rule` when reviewed online
evidence proves that another dynamic or unordered field should be exempted.

## Validation

Before reporting completion:

- validate the rendered TOML and YAML with the installed `traffic-e2e`;
- run `bash -n` for `scripts/start-recording`,
  `scripts/start-recording-comparison`, `scripts/<project>-cli`, and
  `scripts/brz-no-fallback.sh`;
- build the adapter without network access;
- verify the patched class exists in the source JAR;
- prove Breeze, port `880`, source readiness, UID/GID `998:998`, and fake-DNS
  resolution of `breeze.recording` under the source identity;
- run `./scripts/start-recording --duration-seconds 1` and require finalized
  standard recording metadata with no Recorder startup or shutdown error; and
- run `./scripts/start-recording-comparison --duration-seconds 1`, prove the
  source and candidate reused exactly one Breeze instance, require both
  upstreams to become ready, and require a finalized
  `comparison-recording-run.json`.

This validation proves ready-to-record state. It does not require a business
request or a published standard or comparison recording case.
