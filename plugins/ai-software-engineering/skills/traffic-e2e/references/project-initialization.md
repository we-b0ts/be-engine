# Initialize A Repository For Traffic Recording

Use this workflow when a user asks to initialize the current repository for
traffic recording from existing source-system containers or startup commands.
Create recording infrastructure around the genuine source environment. Do not
implement or scaffold application behavior.

Initialization is complete only when this command starts Recorder and the
genuine source environment and reaches ready-to-record state:

```bash
./scripts/start-recording
```

Generated files alone are not a completed initialization.

## Contents

- [Request And Scope](#request-and-scope)
- [Inspect The Runtime](#inspect-the-runtime)
- [Generate The Repository Scaffold](#generate-the-repository-scaffold)
- [Build The Recording Runtime](#build-the-recording-runtime)
- [Generate The Recording Command](#generate-the-recording-command)
- [Validate Completion](#validate-completion)

## Request And Scope

A concise request is sufficient:

```text
$traffic-e2e
Initialize the current repository for traffic recording.
Source application container: <name-or-id>
Supporting containers: <name-or-id> (<role-if-known>)
```

Container names or IDs may refer to stopped containers. Use `docker inspect` to
recover their runtime facts. Accept complete `docker run` commands or an
equivalent repository-native startup command as alternatives.

Ask only for facts that inspection and repository evidence cannot resolve,
such as an ambiguous container role or a required secret that is unavailable
locally. Do not require the user to reconstruct information Docker already
provides.

This workflow creates files in the current branch. It does not create or switch
Git branches. An outer rewrite or orchestration skill owns branch, commit,
push, and pull-request behavior.

The initialization request authorizes a bounded startup of distinctly named
recording containers and permission preparation for their exact writable bind
mounts. Do not send business traffic during initialization validation.

## Inspect The Runtime

Read the target repository instructions, existing startup scripts, deployment
files, ignored paths, and local conventions before writing files.

For every supplied container, record only the runtime facts needed to recreate
it:

- image, platform, entrypoint, command, working directory, and configured user;
- network mode, shared namespace, listen ports, and published ports;
- bind-mount source, destination, read/write mode, and host-path type;
- environment, environment-file, health, restart, security, capability,
  ulimit, PID, memory, and shared-memory settings;
- the genuine source process's effective resource limits and the user-switch
  path that establishes them; and
- the role of each supporting container and the process that emits each remote
  dependency connection.

Reproduce all environment values required for genuine startup. Keep secrets
and values that should not enter source control in an existing environment
file or `.traffic-e2e/.env` with owner-only permissions. Do not print, commit,
or embed secret values in generated scripts.

Resolve these target-specific facts:

- the source HTTP port inside the shared recording namespace;
- a genuine readiness path and exact expected status;
- an upstream DNS resolver reachable from that namespace;
- every required image, bind mount, sidecar, port, and environment file;
- every required listen port below 1024; and
- whether HTTPS interception requires Recorder CA trust.

Keep the inspected source-system behavior authoritative. Do not copy another
project's images, ports, routes, application patches, or topology.

## Generate The Repository Scaffold

Create this source-controlled scaffold:

```text
.traffic-e2e/
├── project.yaml
├── recorder.toml
├── replay.yaml
└── adapters/                 # only when required
    └── <component>/
        └── <recording-only adapter files>
scripts/
└── start-recording
.gitignore
```

Treat this as the complete source-controlled write allowlist:

- generate the three top-level `.traffic-e2e` configuration files only through
  their initializers;
- place every required recording-only Dockerfile, loader configuration, and
  source-container entrypoint under `.traffic-e2e/adapters/<component>/`;
- generate only the user-facing `scripts/start-recording`; and
- append only the required missing entries to `.gitignore`, preserving all
  unrelated content.

Add `.traffic-e2e/adapters/<component>/` only when the inspected image cannot
satisfy the fixed recording identity, CA trust, low-port, resource-limit, or
startup contract directly. Use that component directory as its Docker build
context and build it with `--network none`; a recording-only adapter must not
download build dependencies. Do not create a top-level `recording/`, `docker/`,
or other initialization directory.

Do not modify application source, application configuration, repository build
files, deployment files, CI, repository instructions, README, or other
documentation during initialization. Reading them for runtime evidence does
not authorize changing them. A write outside the allowlist requires explicit
user authorization naming the additional path. If the recording environment
cannot be built within this boundary, stop as `initialization incomplete`
instead of expanding scope.

Ensure Git ignores:

```text
/.traffic-e2e/local/
/.traffic-e2e/.env
/.traffic-e2e/data/
/recordings/
```

Generated logs, truststores, temporary state, CA material, and other local
runtime files must stay under the ignored `.traffic-e2e/data/`,
`.traffic-e2e/local/`, or `.traffic-e2e/.env` paths. Recording runs stay under
the ignored `recordings/` path. These paths may be created during validation
but must never be staged or committed.

Create the three configuration files in this order:

```bash
traffic-e2e config recorder init \
  --target-root . \
  --source-http-port <port> \
  --upstream-dns <ip:port>
traffic-e2e config replay init --target-root .
traffic-e2e config project init --target-root .
```

Recorder initialization defaults readiness to path `/healthz` with exact
status `404`. When source evidence requires another contract, override it with
`--readiness <path>` and, when needed, `--readiness-status <status>`.

The initializers own and validate the baseline templates. Do not hand-write or
post-edit the generated configuration during initialization. Recorder
initialization provides unrestricted matched-request forwarding, a fixed
unmatched-request response, standard paths, and empty AI-managed sections.
Project initialization records the future `scripts/<project>-cli` path without
requiring or creating that file.

## Build The Recording Runtime

### Shared Images And Network

Use these pinned Linux/amd64 images:

```text
Anchor:
registry.api.demo.test/weibo_rd_if/traffic-e2e-network-anchor:0.0.1@sha256:095f39e3b242e744ec8f7d85e732bb663af8a4a02bdef0d7a216d2e66e365a62

Recorder:
registry.api.demo.test/weibo_rd_if/traffic-e2e-recorder-runtime:0.0.1-dev@sha256:c71fa374b229bc6fbf7ad34c5bb5cede1c27b2314a7b274b62ce2d44d3213107
```

Create one distinctly named anchor container with `--network host`. Start
Recorder, the source application, and every dependency-producing supporting
container with:

```text
--network container:<anchor>
```

Only the anchor selects the backing network. Components in its namespace use
their original listen ports and communicate through their common loopback.

Use another backing network only when the user requests it or authoritative
runtime evidence requires it. In that case, prove required DNS, routes, egress,
and internal-service reachability first, and put required published ports on
the anchor.

Docker may store a namespace join as `container:<anchor-id>` rather than
`container:<anchor-name>`. Validate it against the anchor's resolved full
container ID.

Resolve the installed binary through `PATH`, then canonicalize every symlink:

```bash
traffic_e2e_command="$(command -v traffic-e2e)"
traffic_e2e_binary="$(readlink -f -- "$traffic_e2e_command")"
```

Mount that final file, not the PATH entry, read-only at
`/usr/local/bin/traffic-e2e`. Run the pinned shared Recorder image directly;
do not generate a project-specific Recorder image or Dockerfile. Before
startup, use that runtime to execute `traffic-e2e --version`.

Use `/workspace` as the Recorder working directory and exactly one mount for
each repository-owned path:

```text
.traffic-e2e/recorder.toml -> /workspace/.traffic-e2e/recorder.toml:ro
.traffic-e2e/data/         -> /workspace/data/
recordings/                -> /workspace/recordings/
```

The relative paths generated by `config recorder init` resolve against that
working directory. Do not mount the same host directory at a second container
path. Mount the control-socket directory separately at
`/run/traffic-e2e`. Start Recorder with `NET_ADMIN` and `NET_RAW`, not
`--privileged`.

### Fixed Identity And Bind Mounts

Run Recorder as root inside its bounded runtime with only the required
capabilities. Run the genuine source process that emits the dependency traffic
to be intercepted with numeric UID/GID `998:998`; host account names for that
identity are irrelevant. Always preserve the inspected users of supporting
containers.

Keep every inspected bind-mount source and destination unchanged. Require each
writable host source used by the fixed source process to exist and be a
directory. Before startup, recursively give that exact source and its existing
descendants to `998:998`:

```text
chown -hR 998:998 -- <exact-writable-bind-source>
chmod -R u+rwX -- <exact-writable-bind-source>
```

Apply these commands only to exact mounts used by the fixed source process.
Do not change ownership of Recorder or supporting-container mounts.

When an application image requires root initialization, use a bounded
recording entrypoint that prepares configuration and mounts as root, then
executes the genuine application process as `998:998`. Preserve the original
application command and dependency clients.

Inspect every image-internal directory that the genuine source process must
write, including work, temp, generated configuration, and application log
directories. Create or assign only those exact paths to `998:998` in the
recording adapter. Do not broadly change ownership of the application tree.

Use a non-PAM numeric identity-drop mechanism. Inspect its actual path, version,
and syntax inside the target image instead of assuming host behavior. The
adapter must preserve the inspected working directory, environment, executable,
and argv; use `exec` so the genuine process keeps the container signal chain.
Do not use `su` or `runuser`.

### Runtime Limits

Preserve inspected Docker ulimits. Because the source process changes identity,
also compare the original and recording process limits through
`/proc/<pid>/limits`, especially open files and user processes. Docker
`HostConfig.Ulimits` alone is not proof of the effective limits.

Use an identity drop that retains the required inherited limits, or pass the
exact evidenced Docker ulimits. Do not let an original unlimited process limit
become a soft `nproc=1024` merely because the recording process runs as a
non-root user. Do not raise a limit beyond the original effective value without
separate runtime evidence.

Before the first full recording startup, run a bounded probe through the same
adapter entrypoint and identity-drop path. Prove numeric UID/GID `998:998`, the
exact working directory, executable and argv handling, relevant effective
limits, required image-internal write access, and successful execution of the
real launcher. After the genuine source starts, verify its UID/GID and
`/proc/<pid>/limits` again before readiness.

### Ports Below 1024

Resolve every required source-process listen port below 1024 before the first
full recording startup. Read `net.ipv4.ip_unprivileged_port_start` from the
selected anchor network namespace, not a throwaway Docker namespace. Preserve
the original port.

When UID 998 will bind below that threshold, treat privilege as required unless
a narrow bind probe in the same namespace proves otherwise. Adapt only the
recording image:

1. resolve the real executable that owns the listener;
2. make its dynamic libraries available through the system loader when
   required;
3. apply `cap_net_bind_service=+ep` to that executable; and
4. run the real launcher as UID 998 before full startup, then verify the
   capability and genuine listener while the application runs as UID 998.

Do not change the host-wide unprivileged-port sysctl, run the application as
root, or use a privileged container to bypass this requirement. For Java,
resolve the actual launcher and JDK library layout before applying the file
capability. File capabilities enable secure-execution rules that can invalidate
`$ORIGIN` or environment-based library lookup. Run the exact Java launcher
as UID 998, such as with `java -version`, before full startup; if loading fails,
register only the required JDK library directories in the recording image's
loader configuration and run `ldconfig`.

### HTTPS And CA Trust

Apply CA handling only when the source makes HTTPS connections through
Recorder interception.

`config recorder init` writes CA paths but does not create the files. Start
Recorder first, then use `traffic-e2e recording wait-listeners` to wait for
Recorder initialization, CA generation, and all enabled listener binds. The
Recorder validates an existing CA pair and creates its private key with
owner-only permissions. Mount only the public certificate read-only into the
source container.

Use a recording-only truststore or CA bundle. For Java, copy the image's system
truststore into Git-ignored runtime storage, import the Recorder certificate
under a stable alias, and configure the recording JVM to use it. Never place
the Recorder private key in a source container or repository.

## Generate The Recording Command

Generate `scripts/start-recording` from the inspected runtime. It has one
optional runtime control:

```bash
./scripts/start-recording
./scripts/start-recording --duration-seconds <positive-integer>
```

The no-argument command uses a documented positive default duration.
`--duration-seconds` overrides that default. Reject invalid or duplicate
values before changing runtime state.

The script must:

1. use strict shell behavior and repository-root-relative paths;
2. verify Docker, resolve the installed binary, require the exact bind sources
   and environment files used by this runtime, and reject occupied managed
   container names;
3. prepare writable source bind-mount ownership;
4. start the anchor and Recorder with a control socket, then use
   `recording wait-listeners`;
5. prepare source CA trust when applicable, then start supporting containers
   and the genuine source in the shared namespace;
6. wait for required supporting-service prerequisites, then use
   `recording wait-ready` for genuine application readiness;
7. print the Recorder gateway and remain attached for the selected duration;
8. send `SIGINT` to Recorder when time expires or the operator interrupts;
9. wait for Recorder drain and finalization, report the run path and errors,
   then stop and remove the Recorder, supporting, source, and anchor containers
   created by this invocation.

Use distinct, deterministic managed container names and fail clearly when one
already exists. Once Recorder has started, use the same graceful finalization
path for normal timeout, operator interrupt, startup failure, and readiness
failure. Keep failure diagnostics. Do not use `kill -9` as the normal shutdown
path. Make cleanup idempotent and aware of each completed startup stage; a
failure before Recorder starts must not require run metadata, and every cleanup
must touch only components created by that invocation.

Start Recorder with an internal control socket:

```text
traffic-e2e record \
  --config /workspace/.traffic-e2e/recorder.toml \
  --control-socket /run/traffic-e2e/recording.sock
```

Before starting the source, wait for Recorder initialization and every enabled
listener:

```text
docker exec <recorder-container> traffic-e2e recording wait-listeners \
  --control-socket /run/traffic-e2e/recording.sock
```

After the genuine source has started, wait for the configured source readiness
probe:

```text
docker exec <recorder-container> traffic-e2e recording wait-ready \
  --control-socket /run/traffic-e2e/recording.sock
```

Both commands read Recorder's internal lifecycle state and default to a
300-second timeout. They fail on timeout, listener failure, or shutdown. Do
not parse `recorder.toml` in the generated shell script. Keep evidence-based
checks for supporting-service prerequisites that Recorder does not represent.

## Validate Completion

Run static checks:

```bash
bash -n scripts/start-recording
git check-ignore .traffic-e2e/local/probe
git check-ignore .traffic-e2e/data/probe
git check-ignore recordings/probe
```

Inspect the final Git diff and require every source-controlled change to match
the scaffold write allowlist. Treat an unexpected tracked path as incomplete;
do not justify or retain it after the fact.

Then execute the same user-facing command. The duration begins after readiness,
so one second is sufficient for initialization validation:

```bash
./scripts/start-recording --duration-seconds 1
```

Report `initialization complete` only when:

- all three configuration initializers succeeded;
- source-controlled outputs and ignore rules are correct;
- the command used the pinned shared images and ran the source traffic emitter
  with the fixed `998:998` identity;
- every managed component joined the anchor namespace;
- Recorder and the genuine source reached readiness; and
- Recorder finalized cleanly at the end of the bounded session.

If startup was prohibited or a required runtime fact remains unresolved,
report `initialization incomplete` with the exact blocker.

Initialization completion proves ready-to-record state, not that a traffic case
was recorded. Never claim success from generated files alone.
