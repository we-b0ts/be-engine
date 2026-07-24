# Initialize A Repository For Traffic Recording

Use this workflow when a user asks to initialize the current repository for
traffic recording. Initialization creates recording infrastructure around the
existing source system. It does not implement, rewrite, or scaffold application
behavior.

Initialization is complete only when the canonical command
`./scripts/start-recording` can start the genuine source environment and
Recorder and reach a ready-to-record state. Generated files alone are not a
completed initialization.

## Contents

- [Minimal Request Shape](#minimal-request-shape)
- [Required Inputs](#required-inputs)
- [Discovery](#discovery)
- [Repository Outputs](#repository-outputs)
- [Anchored Recording Network Namespace](#anchored-recording-network-namespace)
- [Recorder Container](#recorder-container)
- [Recording Execution Boundary](#recording-execution-boundary)
- [Privileged Ports](#privileged-ports)
- [TLS And CA Trust](#tls-and-ca-trust)
- [Recorder Configuration](#recorder-configuration)
- [Start Recording Script](#start-recording-script)
- [Optional Project Facade](#optional-project-facade)
- [Validation](#validation)
- [Completion](#completion)

## Minimal Request Shape

A concise request is sufficient when it names this skill and provides the
runtime facts that only the user can know:

```text
$traffic-e2e
Initialize the current repository for traffic recording.
Source application container: <name-or-id>
Supporting containers: <name-or-id> (<role-if-known>)
```

Container names or IDs are enough to begin discovery, including stopped
containers. Do not require the user to manually reconstruct `docker run` when
`docker inspect` can recover the necessary facts. Ask only for facts that
inspection and repository evidence cannot resolve, such as an ambiguous
container role, a protected trigger request, or required secret values.

Under an explicitly invoked orchestration or rewrite skill, a concise
`<repo> repo init` request may route here. Branch creation, commits, pushes, and
pull requests remain the responsibility of that outer skill; this workflow
does not change branches.

## Required Inputs

Require at least one authoritative source-system startup input:

- the names or IDs of all existing source and supporting containers; or
- the complete `docker run` commands for the source and supporting containers;
  or
- an equivalent repository-native command that starts the genuine source
  process and its required sidecars.

Treat these inputs as runtime facts, not as text to copy blindly. Also resolve:

- the target repository root;
- the exact source-system HTTP port;
- a real readiness path and expected HTTP status;
- an upstream DNS server reachable from the recording namespace;
- required images, mounts, networks, environment-file locations, and sidecars;
- whether HTTPS dependencies or response-rewrite plugins require Recorder CA
  trust; and
- whether the user supplied a live trigger that creates a recording case.

The configuration initializers do not create or switch Git branches. A
companion orchestration skill may prepare a feature branch; this workflow only
creates target recording files in the current branch.

If the user has not supplied a live trigger request, the repository may still
be initialized to a ready-to-record state. Do not invent credentials, request
parameters, API paths, or expected responses, and do not claim that a case was
recorded. The initialization request authorizes a startup-only smoke of
distinct managed recording containers unless the user explicitly prohibits
runtime startup. It does not authorize a business trigger or mutation of the
original containers. A missing route, identity, image, CA path, readiness
condition, or sidecar path that prevents `./scripts/start-recording` from
reaching readiness blocks initialization completion.

## Discovery

Read repository instructions before writing files. Inspect existing startup
scripts, deployment files, local environment conventions, and ignored paths.
Keep the target's normal startup behavior authoritative.

For supplied container names or IDs, inspect only the fields needed to
reconstruct the runtime:

- image, entrypoint, command, working directory, and configured user;
- network mode, shared network namespace, exposed or published ports;
- mount source, destination, access mode, and required host directories;
- environment variable names and explicitly user-provided non-secret values;
- health, restart, ulimit, capability, and dependency-container settings; and
- current existence and running state.

Do not dump a container's complete environment, labels, logs, or config into
the conversation or repository. They may contain credentials. Record variable
names and provenance; use a Git-ignored `.traffic-e2e/.env` or an existing
environment file for values.

Identify which process actually emits each dependency connection. A supporting
container may publish local ports or Unix sockets while the source process owns
the genuine client. Conversely, the sidecar may own the remote connection.
Localhost, shared-network-namespace, and Unix-domain-socket paths are not
automatically visible to fake-DNS interception. If the genuine dependency path
cannot pass through a supported recorder listener without replacing application
behavior, report that dependency path as blocked.

## Repository Outputs

Create the smallest source-controlled recording scaffold:

```text
.traffic-e2e/
├── project.yaml
├── recorder.toml
└── replay.yaml
scripts/
└── start-recording
```

Add only the environment-specific recording adapters that evidence requires,
such as a `Dockerfile.recorder`, `Dockerfile.recording`, an entrypoint wrapper,
or sidecar startup script. Do not copy another project's application patches,
ports, service names, routes, or container topology.

Ensure Git ignores at least:

```text
/.traffic-e2e/local/
/.traffic-e2e/.env
/.traffic-e2e/data/
/recordings/
```

Also ignore any target-specific generated logs, truststores, temporary
container state, or CA material. Never ignore the source-controlled
`project.yaml`, `recorder.toml`, or `replay.yaml`.

When any recording image is built from the repository root, add equivalent
rules to `.dockerignore` so CA keys, recordings, `.traffic-e2e/local`,
environment files, runtime copies, and logs are never sent to the Docker build
context.

Create the three configuration files with the dedicated initializers, in this
order:

```bash
traffic-e2e config recorder init \
  --target-root . \
  --source-http-port <port> \
  --readiness-path <path> \
  --readiness-status <status> \
  --upstream-dns <ip:port>
traffic-e2e config replay init --target-root .
traffic-e2e config project init --target-root .
```

These commands validate their generated documents and refuse to replace an
existing file. Do not hand-write the initial documents. Recorder initialization
creates a broad `record-api` rule for `GET /`, unrestricted source forwarding
for matched requests, a fixed 404 fallback for unmatched requests, and empty
AI-managed sections. Replay initialization creates an assertion-only
version-two policy with no rules. Project initialization uses the standard
paths, records the future `scripts/<project>-cli` path without requiring that
file to exist, uses `record-api`, and records `dev-migration` as the PR base.

## Anchored Recording Network Namespace

Container recording requires one namespace-anchor container. Start the anchor
with `--network host` by default, then start Recorder, the source application,
and every dependency-producing supporting container with:

```text
--network container:<recording-network-anchor>
```

Only the anchor declares the backing network. Recorder, source, and supporting
containers must join the anchor instead of independently declaring host,
bridge, or published-port settings. This gives the recording stack one named
lifecycle boundary while preserving the host routes and internal-service
reachability commonly required by source systems.

In the default host-backed mode, do not pass `--publish`: listeners bind host
ports directly through the shared namespace. Resolve every Recorder, source,
control, management, and supporting-container listen port before startup.
Detect collisions with the original containers and unrelated host processes.
Do not reject this mode merely because the Docker daemon disables its default
bridge or automatic iptables management; those settings constrain a
bridge-backed anchor, not a host-backed one.
Never stop or replace an original container implicitly; require it to be
stopped or preserve and restore its exact state under an explicitly authorized
workflow.

Use a project-specific Docker bridge or another Docker network only when the
user explicitly requests it or authoritative runtime evidence requires it.
Before choosing that mode, prove the network provides every required egress,
DNS, route, and internal-service path. Put required host-facing port publishing
on the anchor because child containers that join its namespace cannot publish
their own ports.

Prefer one versioned, pinned, organization-owned network-anchor image for all
projects. The image must be inert: a minimal runtime whose only default process
keeps the namespace alive, such as `sleep infinity`. It must not contain target
code, Recorder, CA material, credentials, project configuration, or
project-specific network behavior. Give each project a distinct anchor-container
name and, when applicable, a distinct Docker network name. A distinct project
image tag is not required.

Use this default shared anchor on Linux/amd64:

```text
registry.api.demo.test/weibo_rd_if/traffic-e2e-network-anchor:0.0.1@sha256:095f39e3b242e744ec8f7d85e732bb663af8a4a02bdef0d7a216d2e66e365a62
```

Verify the target platform before use. Do not replace the pinned reference with
`latest`.

Create one project-specific host-backed anchor container from that shared image
by default:

```text
docker run --detach \
  --name <project>-recording-network \
  --network host \
  registry.api.demo.test/weibo_rd_if/traffic-e2e-network-anchor:0.0.1@sha256:095f39e3b242e744ec8f7d85e732bb663af8a4a02bdef0d7a216d2e66e365a62
```

The image does not define ports or network behavior itself. Recorder, source,
and supporting containers join with
`--network container:<project>-recording-network` and must not use
`--publish`. Components in the namespace communicate through their common
loopback.

Docker may persist a child's requested
`container:<recording-network-anchor-name>` network mode as
`container:<recording-network-anchor-id>`. Resolve the anchor's full container
ID and compare the inspected child mode with `container:<resolved-id>`; do not
reject a correct namespace join because the original name is absent.

For an explicitly selected bridge-backed anchor, derive the complete mapping
set before creating it and publish only ports that a host-side operator,
trigger, readiness check, or control command must reach. Bind published ports
to `127.0.0.1` by default. Docker port mappings are fixed when the anchor is
created; if they change, recreate only the managed anchor after preserving its
prior state.

If the standard image is unavailable in the target environment, generate a
minimal `Dockerfile.recording-network` from an approved pinned base and build
`<project>-recording-network:local` automatically from
`scripts/start-recording`. Do not require the user to run a separate build
command. Keep this a fallback only, verify the resulting image before creating
the anchor, and do not copy repository contents into it.

Use the fixed recording identity `trp-record` with numeric UID/GID `998:998`
inside the Recorder and every dependency-producing recording image. Resolve
and verify this identity inside the recording containers, not from the host
password database. Host account names shown for numeric 998 are irrelevant.
Do not grant this identity access to the original application bind-mount
sources.

For every writable application directory bind mount, keep the container
destination unchanged and append the literal `-recording` suffix to the full
host source path. For example:

```text
host /x/y-recording -> container /x/y
```

Create these recording host directories once and reuse them across recording
runs; never place them beneath a run identifier. Own the recording directories
with numeric `998:998` and verify the required read, write, and traversal
operations from a `998:998` probe before startup. Never change the ownership,
mode, or ACL of the original host sources.

Classify each mount from the inspected runtime behavior. Seed a recording
directory that requires existing input from its original source into the stable
`-recording` sibling before first use. Preserve the original relative layout,
then assign the copied tree to numeric `998:998`. Create an output-only
recording sibling directly instead of copying historical output. If target
evidence requires refreshing an input on every startup, refresh only that
recording sibling and make the replacement atomic; never create a per-run
application mount.

For a read-only bind mount that the recording process can consume without
changing, retain the original source read-only. If the process must change any
part of it, use the same stable `-recording` sibling rule. Refuse an existing
recording sibling that is not provably owned by this recording scaffold rather
than recursively changing an unrelated directory.

Only Recorder case output, reports, and run-specific diagnostics belong under a
run identifier. Keep the Recorder CA pair and source truststore in their
separate persistent Git-ignored locations; never place the private key in an
application mount.

The anchor owns only the shared network lifecycle. Recorder owns interception
within that namespace and receives only the capabilities it needs for network
rule management. In the default host-backed mode, those rules affect the host
network namespace: allow only one managed recording session, detect stale
Recorder state before startup, and require managed recovery and graceful
shutdown. Capture the pre-run state of the anchor and all joined containers,
start them in the order anchor, Recorder, supporting containers, source, and
restore only state changed by the session.

## Recorder Container

Container recording requires Recorder itself to run in the anchored recording
network namespace. Do not invoke a separate host process for a container
source.

Prefer a versioned common Recorder runtime image only when inspection proves it
contains the required `traffic-e2e` version, network tools, and
`trp-record` identity at numeric `998:998`. Until such an image is published,
generate a minimal `Dockerfile.recorder` from a pinned compatible base. It must:

- install only the required CA, route, and iptables runtime tools;
- create `trp-record` as numeric `998:998`;
- use `/usr/local/bin/traffic-e2e` as its entrypoint; and
- contain no target code, recording data, CA material, credentials, or target
  configuration.

Have `scripts/start-recording` build the local Recorder runtime image
automatically. Mount the exact installed `traffic-e2e` binary read-only at
`/usr/local/bin/traffic-e2e`, verify its version and platform inside the image,
and mount the target recorder configuration plus Git-ignored writable CA,
state, log, and recording paths. Do not require a separate manual build.
Image-build networking is separate from the recording runtime boundary. Use
`--network none` when a derived image needs no downloads; when the Recorder
runtime must install packages and the host network is the authoritative build
path, use `docker build --network host` without persisting proxy credentials in
the image.

Start the Recorder container with
`--network container:<recording-network-anchor>` and only the network
capabilities required for managed interception, normally `NET_ADMIN` and
`NET_RAW`. Do not use `--privileged`. Run network setup as root inside this
bounded container; the fixed UID used by interception and dependency-producing
processes remains `998`.

## Recording Execution Boundary

Recorder interception always uses the fixed `trp-record` identity. Confirm the
numeric UID inside the environment that installs interception rules and ensure
the dependency-producing source process runs with the same kernel UID in the
same supported network boundary.

Do not widen interception to root, the developer login, an arbitrary UID, or
all processes. Do not assume that sharing a network namespace is enough; the
process identity must still match.

Existing application images often require root for `/etc/hosts`, configuration
preparation, mount setup, or port setup. When that is true, create a separate
recording image or entrypoint that:

1. performs only the required initialization as root;
2. prepares bounded writable directories and readable configuration;
3. drops privileges for the dependency-producing application process;
4. verifies that process runs as `trp-record`; and
5. preserves the original application command and ordinary dependency clients.

Prefer a new recording image and distinct container names over mutating or
replacing the user's original containers. Never delete, rename, or overwrite an
existing container implicitly. Reuse an existing container only when inspection
proves that its image, command, mounts, network, fixed identity, and CA behavior
already satisfy the recording contract.

Build the Recorder, source, and applicable supporting images with the dedicated
recording namespace's fixed numeric identity. Fail before startup when any
dependency-producing process does not match it.

## Privileged Ports

Treat every required listen port below 1024, such as 880, as an explicit
recording-image concern. First trace all consumers of the original port,
including health checks, startup scripts, control commands, mesh switches, and
sidecars. Preserve the original port when any runtime behavior depends on it;
do not renumber it merely to make the fixed recording user start.

Determine whether the target network namespace already permits the fixed
identity to bind the port. Do not change the host-wide
`net.ipv4.ip_unprivileged_port_start`, run the application as root, add
`--privileged`, or grant a broad container capability as an initialization
shortcut.

When privilege is required, prefer this bounded recording-image adaptation:

1. resolve the real executable that owns the listen socket, following wrapper
   scripts and symlinks;
2. make its required dynamic libraries available through the image's system
   loader configuration and run `ldconfig`;
3. grant only `cap_net_bind_service=+ep` to that real executable;
4. verify the file capability in the built image and again before startup; and
5. prove that the real application process still runs as `trp-record` and
   directly owns the original low-numbered listener.

File capabilities invoke the secure-execution loader path, which may discard
`LD_LIBRARY_PATH`. For Java and similar runtimes, derive the library directories
from the actual image and JDK layout, register all required launcher and VM
libraries before `setcap`, and verify resolution with the real binary. Do not
assume one JDK version's paths apply to another.

Do not start with `capsh` or ambient-capability choreography; old base images
commonly lack the required semantics. Do not introduce a low-port-to-high-port
forwarder until inspection proves direct file capability is unsafe or
impossible. If a supervised recording-only forwarder is the only supported
fallback, preserve the externally required port, bind it narrowly, track its
PID, and clean it with the managed session. Report the path as blocked when
neither direct binding nor a behavior-preserving bounded fallback can be
proved.

## TLS And CA Trust

Enable CA handling only when the target will make HTTPS connections through
MITM or a rewrite plugin requires it.

`traffic-e2e config recorder init` writes only the standard CA paths; it does
not generate certificate files. The first startup smoke must create and start
Recorder, then wait until both configured CA files exist, are non-empty, form a
valid matching pair, and have stable readable permissions before creating any
source container that mounts the certificate. Treat the certificate and key as
an inseparable pair: both missing may be generated; one missing is an error.
Mount only the public certificate into source containers. Never mount, log, or
copy the Recorder private key into the target.

Do not modify a developer host's global trust store or permanently replace a
base image's system trust store during repository initialization. Create a
recording-only trust store or certificate bundle and point only the recording
process at it.

For Java targets:

1. copy the image's system `cacerts` into a writable recording-only directory;
2. import the mounted Recorder certificate under a stable dedicated alias;
3. configure `javax.net.ssl.trustStore` and its password only for the recording
   JVM;
4. run the JVM as the fixed recording identity; and
5. compare the imported certificate fingerprint with the mounted certificate
   before declaring readiness.

Apply the equivalent isolated trust-bundle mechanism for other runtimes. If the
application pins certificates or ignores the configured trust store, report
HTTPS recording as blocked instead of disabling verification.

A startup smoke is not CA-complete until it verifies all of the following:

- Recorder created or reused a non-empty matching certificate and private-key
  pair in Git-ignored host storage;
- only the public certificate was mounted read-only into the recording source
  container, and the private key is absent from that container;
- the source created an isolated runtime truststore or trust bundle, imported
  the public certificate, and matched its fingerprint;
- the genuine application process is configured to use that truststore or
  trust bundle; and
- the trust artifact exists in the runtime-local bind mount while the source is
  ready.

Do not require CA files to remain inside a stopped or removed container. Keep
the host CA pair and runtime-local trust evidence outside source control so a
subsequent `scripts/start-recording` run can recreate or mount the required
container state deterministically.

## Recorder Configuration

The recorder initializer owns the baseline template. Provide only the four
target-specific facts it requires: source HTTP port, readiness path, readiness
status, and upstream DNS address. Keep the generated listener addresses,
limits, redaction defaults, `GET /` rule, unrestricted access policy, standard
paths, and empty AI-managed sections intact during initialization.

The generated HTTP gateway uses:

```toml
fallback_mode = "fixed_response"

[http_gateway.fixed_response]
status = 404
content_type = "application/json"
headers = { x-traffic-e2e-fallback = "fixed" }
body = '{"code":"40401","msg":"not_in_<project>_record_api"}'
```

Do not configure `fallback_upstream`. Requests outside the generated recording
rule terminate at Recorder with the fixed response, do not reach the source
application, and do not create a case. Replace `<project>` with the repository
directory name; never leave the placeholder in generated configuration.

## Start Recording Script

Generate `scripts/start-recording` for the discovered runtime. Do not ship one
generic script that assumes a particular image, service name, sidecar, port, or
language.

The no-argument invocation is the canonical recording entrypoint:

```bash
./scripts/start-recording
```

It must start Recorder and every required derived, supporting, and source
container, wait until the genuine source is ready, print the recorder gateway
and safe trigger guidance, and remain attached in a ready-to-record foreground
session when no trigger command was supplied. An invocation with `-- <trigger>`
may execute the controlled trigger, drain, finalize, and report the resulting
case.

Support a bounded recording session:

```bash
./scripts/start-recording --duration-seconds <positive-integer>
```

Interpret the value in seconds. When the option is omitted, use and document a
positive project default so the recording session is not unintentionally
unbounded. Reject zero, negative, non-integer, and duplicate values before
changing runtime state.

The script must:

1. use strict shell behavior and repository-root-relative paths;
2. expose `--help`, `--duration-seconds`, a startup-only `--smoke`, and a
   read-only `--check` or `doctor` mode;
3. verify commands, images, host directories, ports, container conflicts,
   the pinned or locally built anchor and Recorder images, the selected anchor
   backing network, child namespace topology, fixed `998:998` identity, config
   files, and required environment variable names before changing state;
4. capture the existence and running state of every managed container;
5. create or start the inert network-namespace anchor, then start managed
   Recorder in that namespace; when CA trust applies, wait for and validate the
   complete CA pair before creating a source container that mounts the public
   certificate; only then start dependency-producing supporting and source
   processes so startup dependencies can be observed;
6. wait on recorder listeners, supporting-container readiness, fixed target
   identity, CA trust when applicable, and genuine application readiness;
7. send only serial controlled trigger requests, or remain attached and print
   the gateway address when no trigger was supplied;
8. allow bounded post-response admission and drain;
9. stop Recorder with `SIGINT`, wait for finalization, and inspect the new run
   for errors, failed cases, and canonical case files; and
10. restore only state that the script changed when an explicit restore mode is
    selected.

Accept trigger commands as an argument array after `--`, or use a
Git-ignored owner-only request input. Never use `eval`, store credentials in
the script, print authorization values, or expose them in generated
documentation. Refuse overlapping triggers.

Install traps only after managed state has been captured. On startup or trigger
failure, still finalize Recorder cleanly, retain diagnostics, and avoid
destructive cleanup. Never use abrupt Recorder termination as the normal
success path.

When the configured duration expires, stop accepting new triggers and follow
the same graceful path as an operator interrupt: send `SIGINT` to Recorder,
wait for dependency drain and run finalization, then stop only the supporting
and source processes that this invocation started and restore only the state it
changed. Do not implement the normal timeout path with `kill -9` or a wrapper
that terminates Recorder before it finalizes the run.

## Optional Project Facade

The standard project facade belongs to replay and later implementation, not to
recording orchestration. `scripts/start-recording` must not masquerade as
`scripts/<project>-cli`.

Project initialization records the standard facade path
`scripts/<project>-cli` without inspecting or creating that file. Recording
initialization must not generate a placeholder facade merely to satisfy
configuration initialization. Create the repository-native facade when product
implementation begins; the standard runner will require it before execution.

## Validation

Run checks that do not start live recording:

```bash
bash -n scripts/start-recording
git check-ignore .traffic-e2e/local/probe
scripts/start-recording --check
```

Use `shellcheck` when the repository already requires it or it is available.
The three configuration initializers already validate the documents they
create. Static validation does not prove a live container, readiness, CA,
dependency, or recording path.

Run `scripts/start-recording --smoke` to start the genuine source without a
business trigger, verify readiness and fixed identity, then stop Recorder
cleanly. Do not claim case evidence from a startup-only smoke. This smoke is the
runtime proof for a completed initialization when no live trigger was supplied.

## Completion

Report `initialization complete` only when:

- the three configuration initializers succeeded, the source-controlled outputs
  exist, ignored paths are verified, and generated scripts pass static and
  read-only checks;
- every discovered runtime fact has provenance;
- `scripts/start-recording --check` has no unresolved route, image, identity,
  CA, readiness, port, mount, network, or sidecar requirement; and
- the namespace anchor uses the resolved backing network and every managed
  recording component joins that anchor without independently selecting a
  network or publishing ports; and
- a startup-only smoke in the target environment has proved that
  `./scripts/start-recording` starts the genuine source environment and
  Recorder, verifies the recording boundary, and reaches ready-to-record state.

If live startup was not authorized, or any runtime requirement remains
unresolved, report `initialization incomplete` and name the exact pending
verification or blocker. Do not soften this to “scaffold complete.”

`Initialization complete` does not mean that a case was recorded. Report
`recording complete` only after a controlled trigger, managed shutdown, and the
recording evidence gates in the main skill have published valid canonical case
evidence.

Never call initialization, readiness, or recording successful based only on
generated files.
