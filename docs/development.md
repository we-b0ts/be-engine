# Development Guide

Use this file for local commands, runtime behavior, recording, replay, and
testing details. Keep `AGENTS.md` as the short navigation map.

## Rust Tooling

Use the standard Cargo workflow:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
scripts/check-code-organization
cargo build
```

The repository includes `.cargo/config.toml` for the configured crates.io
mirror. Do not replace that registry configuration unless explicitly asked.

## Running Locally

Run the service with:

```bash
cargo run -- --config config/recorder.example.toml
```

For watch-mode recording, install the repo-level command and run
`traffic-record`:

```bash
mkdir -p "$HOME/.local/bin"
ln -sf "$PWD/scripts/traffic-record" "$HOME/.local/bin/traffic-record"
traffic-record --config config/recorder.example.toml
```

`traffic-record` enables local DNS capture and fake-IP TCP/UDP redirect by default,
which modifies local DNS/iptables state through the setup scripts. Use this
when you intentionally want the recorder to intercept local traffic. To skip
those rules:

```bash
traffic-record --config config/recorder.example.toml --no-dns
```

`config/recorder.example.toml` enables `[local_record]` owner filtering for the
dedicated Unix user `trp-record`. Prefer running the source service as that user
so bootstrap and case dependencies are not polluted by unrelated local
processes. `--user`, `--owner-uid`, `--all-users`, or `OWNER_UID` override the
owner scope when used with `traffic-record --config ...`.

HTTP gateway recording is intentionally conservative. Until the configured
ready probe succeeds, matching traffic is sent to `fallback_upstream` and no
case is created. After ready, only one matched case can be active at a time;
overlapping matching requests are also sent to fallback so dependencies are not
shared across cases.

For replay-mode development:

```bash
cargo build
mkdir -p "$HOME/.local/bin"
ln -sf "$PWD/target/debug/traffic-recorder-proxy" "$HOME/.local/bin/traffic-recorder-proxy"
ln -sf "$PWD/scripts/traffic-record" "$HOME/.local/bin/traffic-record"
ln -sf "$PWD/scripts/traffic-replay" "$HOME/.local/bin/traffic-replay"
ln -sf "$PWD/scripts/traffic-replay-cli" "$HOME/.local/bin/traffic-replay-cli"
ln -sf "$PWD/scripts/traffic-replay-aggregate" "$HOME/.local/bin/traffic-replay-aggregate"
ln -sf "$PWD/scripts/traffic-recorder-config" "$HOME/.local/bin/traffic-recorder-config"
traffic-replay path/to/case-dir
traffic-replay --no-intercept path/to/case-dir
```

`traffic-replay` also defaults to owner filtering for `trp-record`. Run the
target service as that user, or pass `--user`, `--owner-uid`, or `--all-users`
when the replay environment requires a different scope.

For a case collection, start one replay session and control active case
ownership through the CLI:

```bash
traffic-replay path/to/recordings/<run-id>/<rule>/<uri-group>
traffic-replay path/to/recordings/<run-id>
traffic-replay-cli wait-ready
traffic-replay-cli cases
traffic-replay-cli begin <case-id>
traffic-replay-cli end <case-id> --fail-on-dirty
traffic-replay-cli report --fail-on-dirty
traffic-replay-cli stop
```

When one recording source has been replayed through several sessions, generate
one deterministic coverage and dependency summary from the recording source
root. The command recursively finds standard `.replay/replay-report.json`
files and also reports published cases that have no replay report:

```bash
traffic-replay-aggregate \
  --case-source recordings/<run-id>/<rule> \
  --output aggregate-report.json
```

Use `--fail-on-incomplete` to fail when a published case has no report or has
not ended. Use `--fail-on-dirty` to apply the recorder's strict raw dependency
dirty check. The aggregate command does not parse target-project test output or
classify why an unreported case was skipped.

`traffic-replay-cli` is a thin facade over `traffic-recorder-proxy
replay-control`; the Rust binary owns the control protocol and Unix socket
client. The script should stay small and should not implement JSON/socket
protocol logic.

Replay-time route discovery can produce safe `case_path_patterns` feedback for
a target repository. Preview focused, add-only feedback before applying it:

```bash
traffic-recorder-config case-path-patterns plan \
  --config ../target/config/recorder.toml \
  --rule record-api \
  --authority focused \
  --source-revision "$(git -C ../source rev-parse HEAD)" \
  --case-source /path/to/focused-cases \
  --pattern '/api/users/*/xxx'

traffic-recorder-config case-path-patterns apply \
  --config ../target/config/recorder.toml \
  --rule record-api \
  --authority focused \
  --source-revision "$(git -C ../source rev-parse HEAD)" \
  --case-source /path/to/focused-cases \
  --pattern '/api/users/*/xxx'
```

The selected rule must already contain exactly one explicit
`BEGIN/END AI-MANAGED CASE PATH PATTERNS` block. The command preserves all text
outside that block, sorts and deduplicates patterns, validates the complete
recorder config, and replaces the file atomically. Focused feedback cannot
remove patterns. Authoritative feedback may remove them only when the case
collection is declared authoritative and `apply` includes `--allow-delete`.
Use `--format json` for machine-readable feedback. The command never modifies
recordings or existing case directories.

Do not send target E2E requests before replay is ready. Replay startup, port
binding, DNS redirect, or stale-process failures are replay lifecycle/setup
failures, not product behavior evidence.

When using setup scripts directly, always pair `up` with `down`:

```bash
sudo ./scripts/setup_local_dns.sh up
sudo ./scripts/setup_fake_ip_redirect.sh up
sudo ./scripts/setup_fake_ip_redirect.sh down
sudo ./scripts/setup_local_dns.sh down
```

## Recording Files

Recording access can be limited with the recording configuration:

```toml
[recording]
access_policy = "block_known_writes"
```

`unrestricted` is the default and preserves normal forwarding. The
`block_known_writes` policy rejects requests classified as writes by the HTTP,
MySQL, Redis, Memcached, and Kafka adapters. Read, session-setup, unknown, raw
TCP, and UDP operations continue to be forwarded, so this compatibility policy
is not a strict security boundary. Rejections are written to `traffic.jsonl` as
payload-free `readonly_rejection` events. A rejection during an active HTTP
gateway case is also added to that case's `dependencies.jsonl` for diagnosis
and invalidates the whole case. The case is moved under `failed/` and is never
published as replay evidence. A rejection outside an active case remains a
run-level audit event and does not create dependency evidence.

`block_known_writes` can explicitly allow narrowly scoped MySQL writes:

```toml
[[recording.access_rules]]
name = "allow-request-log-insert"
effect = "allow"
protocol = "mysql"
operations = ["insert"]
routes = ["audit-db"]
databases = ["pluto"]
tables = ["request_log"]
```

`operations`, `databases`, and `tables` are required and non-empty. A rule must
also contain at least one exact `route` or business `target`; when both are
present, both must match. Supported operations are `insert`, `update`,
`delete`, `replace`, and `upsert`. A missing field, empty required list,
unsupported operation, incomplete SQL classification, multi-table write, or a
multi-statement query not wholly covered by one rule is rejected. Database and
table identifiers are matched exactly and case-sensitively. Mixing session
changes such as `USE` with an allowed write in one multi-statement query is
also rejected. Rules cover the SQL-visible target only; operators must account
for database triggers or other server-side side effects on an allowed table.

An allowed write is forwarded and recorded as a normal `mysql_exchange`, so it
can remain part of a valid case dependency contract. The rule match is also
audited in run-level `traffic.jsonl` as a payload-free `access_policy_allow`;
that audit event itself is not appended to `dependencies.jsonl`.

The automated gateway GET plus dependency GET/POST scenario lives in
`tests/readonly_case_integration.rs`. The local two-mock and optional
cross-machine manual procedure lives in `tests/manual/readonly/README.md`.

Generated runtime artifacts are ignored by git:

- `target/`
- `data/`
- `recordings/`
- `*.swp`

Do not commit generated CA files, traffic recordings, test captures, or local
swap files.

Each recorder process creates one run directory under `recording.output_dir`
named `YYYYMMDDHHMMSS`. Valid case output is published inside that run:

```text
<run-id>/traffic.jsonl
<run-id>/recording-run.json
<run-id>/errors.jsonl
<run-id>/bootstrap-dependencies.jsonl
<run-id>/bootstrap-dependencies-summary.json
<run-id>/bootstrap-dependencies-debug.jsonl
<run-id>/<rule-name>/<uri-group>/<case-id>/request.json
<run-id>/<rule-name>/<uri-group>/<case-id>/expected-response.json
<run-id>/<rule-name>/<uri-group>/<case-id>/dependencies.jsonl
<run-id>/<rule-name>/<uri-group>/<case-id>/dependencies-summary.json
<run-id>/<rule-name>/<uri-group>/<case-id>/dependencies-debug.jsonl
<run-id>/failed/<rule-name>/<uri-group>/<case-id>/
```

Every newly published case contains `dependencies.jsonl` and
`dependencies-summary.json`, including cases with no semantic third-party
dependencies. For a zero-dependency case, `dependencies.jsonl` is empty and
the summary has `total_events: 0`. This distinguishes a confirmed empty
dependency contract from missing capture evidence.

Failed cases are diagnostic artifacts, not replay fixtures. A case with a
truncated request or expected response body is kept under `<run-id>/failed`
with `recording-error.json` instead of being published. On clean shutdown,
recording exits with an error if the run contains failed cases.

Use `dependencies.jsonl` for replay-oriented semantic data. Use
`dependencies-debug.jsonl` only for protocol-level debugging. UDP datagrams,
including push-metrics side effects, are recorded as semantic dependencies when
captured by the UDP gateway. Run-level
bootstrap dependency files capture replay-oriented dependencies observed before
the service is ready, or before the first case starts when no ready probe is
configured. Replay discovers them by walking upward from a case directory.

Redis and Memcached dependencies are semantic `redis_connection`,
`redis_exchange`, `memcached_connection`, and `memcached_exchange` records.
Successful Redis authentication/session initialization is handled by replay
and omitted from case dependencies; failed initialization remains as redacted
evidence. Any truncated frame, parse/correlation failure, unsupported cache
mode, or unsafe cache connection prevents a case from being published and
prevents unsafe bootstrap replay from starting. The recording directory is
sensitive because ordinary cache keys and values are needed for exact replay.

Kafka dependencies are semantic `kafka_connection`, `kafka_produce`, and
`kafka_delivery` records. V1 is a successful-path dependency facade rather than
a full Kafka broker: use an E2E client profile with
`security.protocol=PLAINTEXT`, `compression.type=none`,
`enable.idempotence=false`, and `acks=1`. Replay advertises one broker and one
partition, synthesizes control-plane responses, matches Produce by exact topic,
key, headers, and value bytes, and delivers recorded Fetch records once.
Transactions, Admin APIs, compression, TLS/SASL, rebalance behavior, retries,
and Kafka failure injection are unsupported and fail closed. Schema Registry
remains an ordinary HTTP dependency. Kafka payloads and headers are sensitive
because exact bytes are required for replay.

Dependency summaries are generated when a case is published, when bootstrap
recording closes, and when the run finishes. They are intentionally not rebuilt
after every cache exchange.

## Testing Guidance

Add unit tests near the parser or module being changed. Add integration tests in
`tests/proxy_integration.rs` when changing externally visible proxy behavior.

Useful focused test commands:

```bash
cargo test mysql::wire
cargo test recorder::mysql::semantic
cargo test proxy_integration
cargo test redis::
cargo test memcached::
cargo test replay::command_protocol_tests
cargo test kafka::
```

Network or root-requiring behavior should be covered with isolated unit tests
where possible. Do not require host iptables changes for automated tests.
