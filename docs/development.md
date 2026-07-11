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
traffic-record config/recorder.example.toml
```

`traffic-record` enables local DNS capture and fake-IP TCP/UDP redirect by default,
which modifies local DNS/iptables state through the setup scripts. Use this
when you intentionally want the recorder to intercept local traffic. To skip
those rules:

```bash
traffic-record --no-dns config/recorder.example.toml
```

`config/recorder.example.toml` enables `[local_record]` owner filtering for the
dedicated Unix user `trp-record`. Prefer running the source service as that user
so bootstrap and case dependencies are not polluted by unrelated local
processes. `traffic-record --user`, `traffic-record --owner-uid`,
`traffic-record --all-users`, or `OWNER_UID` override the config.

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

`traffic-replay-cli` is a thin facade over `traffic-recorder-proxy
replay-control`; the Rust binary owns the control protocol and Unix socket
client. The script should stay small and should not implement JSON/socket
protocol logic.

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

Dependency summaries are generated when a case is published, when bootstrap
recording closes, and when the run finishes. They are intentionally not rebuilt
after every cache exchange.

## Testing Guidance

Add unit tests near the parser or module being changed. Add integration tests in
`tests/proxy_integration.rs` when changing externally visible proxy behavior.

Useful focused test commands:

```bash
cargo test mysql_protocol
cargo test mysql_semantic
cargo test proxy_integration
cargo test cache_protocol
cargo test cache_proxy
cargo test replay::cache_tests
```

Network or root-requiring behavior should be covered with isolated unit tests
where possible. Do not require host iptables changes for automated tests.
