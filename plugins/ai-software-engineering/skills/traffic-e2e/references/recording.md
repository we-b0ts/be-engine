# Managed Traffic Recording

Use the installed `traffic-e2e` binary and the target's authoritative recorder
configuration. Managed recording modifies local DNS and interception state; let
the command own setup, recovery, and cleanup.

## Preconditions

Confirm before starting:

- the recorder configuration path and named HTTP gateway rule;
- upstream and fallback behavior;
- the target's normal startup command and readiness condition;
- the fixed `trp-record` interception user or an equivalent supported target
  execution path;
- the numeric host artifact owner when Recorder runs as root in a container;
- output directory and optional explicit UTC run ID;
- request/response body limits and decoded-size limits;
- request-header encryption, key-variable availability, response-header
  redaction, and handling of sensitive dependency payloads;
- enabled HTTP, HTTPS, MySQL, Redis, Memcached, Kafka, TCP, and UDP paths;
- fake-DNS CIDR, bypass domains, ports, and host routing from configuration;
- `recording.access_policy` and any narrowly scoped access rules;
- source-proven `recording.background_dependencies` rules;
- post-response dependency admission and drain timeouts.

Do not infer values from the example config when the target owns a
`.traffic-e2e/recorder.toml`. Validate the actual file through the installed
binary before changing host state.

Create the fixed system user only when it is absent and the user authorized
host setup:

```bash
sudo useradd --system --create-home --shell /bin/bash trp-record
```

The interception owner cannot be selected from the CLI, environment, or
configuration. Do not change the tool or host rules to intercept the developer
login user, an arbitrary UID, or every process.

## Start

Install or build the requested binary once, then run:

```bash
traffic-e2e record --config .traffic-e2e/recorder.toml
traffic-e2e record --config .traffic-e2e/recorder.toml \
  --api 'GET /api/widgets/*'
```

Use an explicit run identifier only when orchestration needs to know the output
directory before startup:

```bash
traffic-e2e record \
  --config .traffic-e2e/recorder.toml \
  --run-id YYYYMMDDHHMMSS
```

Use repeatable `--api 'METHOD /path-or-pattern'` values when the intended API
scope is known. They filter only the current run, are intersected with the
configured rules, define the selected cases' API grouping, and do not authorize
editing recorder TOML.

Managed recording enables local DNS and fake-IP redirects by default. Use
`--no-dns` only when the target already routes relevant dependencies through
the recorder. A bypassed domain is deliberately not recorded; verify that the
bypass rule matches the intended dependency ownership rather than using a broad
wildcard to reduce load.

For a container source, run Recorder in the same anchored network namespace as
the source and dependency-producing sidecars. Start the anchor with
`--network host` by default, then join every managed component with
`--network container:<anchor>`. Use another verified Docker network only when
the user or authoritative target runtime explicitly requires it. Do not start
Recorder, source, or sidecars independently on different network namespaces.

Build steps may run as the developer. The dependency-producing source process
must run with the fixed interception identity or through another tool-supported
arrangement that places its traffic inside that identity and network boundary.

When a host wrapper starts Recorder as root in a container and bind-mounts the
recording output, capture the wrapper's numeric `id -u` and `id -g` before
starting containers and pass them directly to:

```bash
traffic-e2e record --artifact-owner UID:GID ...
```

The option controls only finalized run artifacts. It does not change the fixed
`trp-record` interception identity. Do not source the value from Recorder TOML,
an environment variable, or an identity discovered inside the root container.
Direct host execution as the intended artifact owner omits the option.

## Readiness And Case Admission

Prefer the recorder rule's ready probe. Until readiness succeeds, matching
traffic receives the configured fallback and does not create a case. Do not
replace application readiness with a fixed sleep; large services can bind a
port or answer a trivial path before business initialization finishes.

After readiness, only one matching case owns dependency attribution at a time.
Overlapping matched requests use fallback and do not become part of the active
case. Send a controlled trigger and wait for it to finish before sending the
next.

After the upstream response, the recorder accepts new case dependencies for
`case_dependency_post_response_window_ms`, then closes admission and waits only
for already accepted in-flight dependencies. Set the window to zero only when
source behavior proves relevant dependencies finish before the response.
Continuous background traffic must not extend a case. A drain timeout means
accepted work did not finish; increasing it without identifying that work risks
publishing an incoherent contract.

When source inspection proves an HTTP poll belongs to a process-level task and
not to the triggering API, add a narrow background rule before re-recording.
Use `background-dependencies plan` and `apply`; do not hand-edit these rules.
Each rule requires exactly one authority, method, and path prefix plus the
source revision and a single-line file/symbol explanation proving process-level
ownership and API independence. Matching exchanges do not enter an active
case's dependencies. The run-level `traffic.jsonl` remains controlled by
`recording.traffic_jsonl`, and a matching exchange observed while bootstrap is
open remains bootstrap replay evidence. Classification changes attribution
only; it does not change forwarding, capture limits, or responses.

Case limits apply per resolved static path or configured case pattern. Requests
after the limit use fallback and create no case. Failed cases do not consume the
limit.

## Access And Safety

`unrestricted` preserves ordinary forwarding. `block_known_writes` rejects
recognized writes for supported protocols but is a compatibility policy, not a
complete security boundary: unknown/raw TCP and UDP can still pass. Use exact
allow rules only for source-proven MySQL writes required by the case. A policy
rejection during a case invalidates it.

Do not log or commit credentials, authorization headers, cookies, tokens,
private keys, cache keys/values, Kafka payloads, full SQL binds, or recording
files. Exact dependency payloads may be necessary for replay, so protect the
entire output directory even when application headers are redacted.

`recording.encrypt_request_headers` matches header names case-insensitively and
stores each configured request-header value as a versioned AES-256-GCM
envelope directly in `request.json`. Request encryption takes precedence when
a name is also present in `recording.redact_headers`; keeping
`authorization` in both lists protects request replayability and response-side
redaction. Encryption requires `TRAFFIC_E2E_ENCRYPTION_KEY_B64` to decode to
exactly 32 bytes. Generate it outside the recording script, for example with
`openssl rand -base64 32`, and protect the value as a secret.

When encryption is configured, missing, empty, invalid-Base64, or wrong-length
key material must fail Recorder startup before recording artifacts are
created. Repository wrappers pass the variable only to Recorder or the host
`record-comparison` process; they must not log it or inject it into source,
candidate, Breeze, or other supporting services.

## Shutdown And Validation

Stop through the managed process signal path and wait for finalization. Do not
kill the recorder abruptly merely because the trigger request returned.
When `--artifact-owner` was supplied, finalization must assign the complete
exact run tree to that numeric UID and GID; an ownership failure makes the
managed recording unsuccessful even when its canonical payloads were written.

Inspect:

```text
<run-id>/recording-run.json
<run-id>/errors.jsonl
<run-id>/traffic.jsonl
<run-id>/bootstrap-dependencies.jsonl
<run-id>/<rule>/<group>/<case-id>/request.json
<run-id>/<rule>/<group>/<case-id>/expected-response.json
<run-id>/<rule>/<group>/<case-id>/dependencies.jsonl
<run-id>/<rule>/<group>/<case-id>/dependencies-summary.json
<run-id>/failed/
```

A valid newly published case has canonical request and expected response files,
an untruncated body, semantic dependencies, and a summary. An empty semantic
dependency file plus `total_events: 0` is valid explicit evidence. A missing
file, partial body, proxy error, unsupported or unsafe protocol, access-policy
rejection, or failed directory is not.

For a root container recording, also verify that the exact finalized run and
all descendants have the requested host UID and GID and that the host wrapper
can create runner-owned artifacts under that run. Do not repair this with
world-writable permissions or by changing the owner of the recordings root.

Use `dependencies-debug.jsonl` only for protocol diagnosis. Normal replay and
acceptance use `dependencies.jsonl`. Fix failed cases and create a new run;
never edit or promote failed artifacts manually.
