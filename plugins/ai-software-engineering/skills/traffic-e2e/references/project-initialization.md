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
- environment, environment-file, health, restart, ulimit, and capability
  settings; and
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
└── replay.yaml
scripts/
└── start-recording
```

Add an application recording image or entrypoint only when the inspected image
cannot satisfy the fixed recording identity, CA trust, low-port, or startup
contract directly.

Ensure Git ignores:

```text
/.traffic-e2e/local/
/.traffic-e2e/.env
/.traffic-e2e/data/
/recordings/
```

Also ignore generated logs, truststores, temporary state, and CA material. If a
recording image uses the repository root as its build context, add equivalent
`.dockerignore` rules so those files never enter the context.

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
Resolve host port collisions before startup.

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

Require the resolved path to be an executable Linux/amd64 file. Mount that
final file, not the PATH entry, read-only at
`/usr/local/bin/traffic-e2e`, and run `traffic-e2e --version` inside the shared
Recorder runtime before startup.

Mount the generated recorder configuration and Git-ignored CA, log, state, and
recording paths. Start Recorder with `NET_ADMIN` and `NET_RAW`, not
`--privileged`.

### Fixed Identity And Bind Mounts

Run Recorder as root inside its bounded runtime with only the required
capabilities. Run the genuine source process that emits the dependency traffic
to be intercepted with numeric UID/GID `998:998`; host account names for that
identity are irrelevant. Preserve the inspected users of supporting containers
unless evidence proves that one is the actual emitter of source-owned outbound
dependency traffic.

Keep every inspected bind-mount source and destination unchanged. Require each
writable host source used by the fixed source process to exist and be a
directory. Before startup, recursively give that exact source and its existing
descendants to `998:998`:

```text
chown -hR 998:998 -- <exact-writable-bind-source>
chmod -R u+rwX -- <exact-writable-bind-source>
```

Apply these commands only to exact mounts used by the fixed source process.
Verify read, write, and directory traversal with a `998:998` probe before
starting the application. For its read-only mounts, verify traversal and read
access.

When an application image requires root initialization, use a bounded
recording entrypoint that prepares configuration and mounts as root, then
executes the genuine application process as `998:998`. Preserve the original
application command and dependency clients.

### Ports Below 1024

For each required source-process listen port below 1024, first prove whether
UID 998 can bind it in the selected namespace. Preserve the original port.

If binding requires privilege, adapt only the recording image:

1. resolve the real executable that owns the listener;
2. make its dynamic libraries available through the system loader when
   required;
3. apply `cap_net_bind_service=+ep` to that executable; and
4. verify the capability and the genuine listener while the process runs as
   UID 998.

Do not change the host-wide unprivileged-port sysctl, run the application as
root, or use a privileged container to bypass this requirement. For Java,
resolve the actual launcher and JDK library layout before applying the file
capability.

### HTTPS And CA Trust

Apply CA handling only when the source makes HTTPS connections through
Recorder interception.

`config recorder init` writes CA paths but does not create the files. Start
Recorder first and wait until its certificate and private key both exist, are
non-empty, form a valid pair, and have stable permissions. Then mount only the
public certificate read-only into the source container.

Use a recording-only truststore or CA bundle. For Java, copy the image's system
truststore into Git-ignored runtime storage, import the Recorder certificate
under a stable alias, configure the recording JVM to use it, and verify the
imported fingerprint. Never place the Recorder private key in a source
container or repository.

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
2. verify Docker, the installed binary, pinned images, environment files,
   exact bind mounts, source UID 998 access, required ports, and container-name
   availability;
3. prepare writable source bind-mount ownership;
4. start the anchor and Recorder with a control socket, then wait for the CA
   pair when applicable;
5. start supporting containers and the genuine source in the shared namespace;
6. wait for required supporting-service prerequisites, then use Recorder's
   readiness command to wait for all enabled Recorder listeners and genuine
   application readiness;
7. print the Recorder gateway and remain attached for the selected duration;
8. send `SIGINT` to Recorder when time expires or the operator interrupts;
9. wait for Recorder drain and finalization, report the run path and errors,
   then stop and remove the Recorder, supporting, source, and anchor containers
   created by this invocation.

Use distinct, deterministic managed container names and fail clearly when one
already exists. Once Recorder has started, use the same graceful finalization
path for normal timeout, operator interrupt, startup failure, and readiness
failure. Keep failure diagnostics. Do not use `kill -9` as the normal shutdown
path.

Start Recorder with an internal control socket:

```text
traffic-e2e record \
  --config /workspace/.traffic-e2e/recorder.toml \
  --control-socket /run/traffic-e2e/recording.sock
```

After the genuine source has started, make this the sole check for
Recorder-owned listeners and the configured source readiness probe:

```text
docker exec <recorder-container> traffic-e2e recording wait-ready \
  --control-socket /run/traffic-e2e/recording.sock \
  --timeout-seconds <bounded-timeout>
```

The command reads Recorder's internal lifecycle state and fails on timeout,
listener failure, or shutdown. Do not parse `recorder.toml` or probe
Recorder-owned TCP/UDP ports in the generated shell script. Keep
evidence-based checks for supporting-service prerequisites that Recorder does
not represent.

## Validate Completion

Run static checks:

```bash
bash -n scripts/start-recording
git check-ignore .traffic-e2e/local/probe
git check-ignore .traffic-e2e/data/probe
git check-ignore recordings/probe
```

Then execute the same user-facing command with a bounded duration long enough
for the genuine source to reach readiness:

```bash
./scripts/start-recording --duration-seconds <validation-seconds>
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
