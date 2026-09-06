# traffic-e2e

Rust binaries for traffic-based E2E contracts and backend rewrite
orchestration. `traffic-e2e` owns recording, replay, comparison, and
diagnostics; `backend-rewrite` owns the AI-facing migration workflow and uses
the same `traffic_e2e` crate; `backend-rewrite-admin` owns explicit
administrator repair outside ordinary AI workflows.

## Features

- Optional HTTP proxy for regular absolute-form proxy requests.
- Optional HTTPS proxy with `CONNECT` MITM recording.
- HTTP gateway for tcpcopy mirrored traffic with rule-based forwarding.
- Local fake-DNS + TCP gateway mode for dependency discovery, broad port
  capture, and HTTP/HTTPS recording.
- Automatic local root CA generation, with support for configured CA cert/key paths.
- Full request/response recording with configurable body truncation.
- Live baseline/candidate response recording without dependency interception.
- Default redaction for sensitive proxy and HTTP headers.
- Optional MySQL TCP proxy with DNS/hosts routing through per-IP listeners.
- MySQL login/query/response packet metadata and raw response payload recording.
- MySQL TLS detection and explicit rejection in v1.

## Install Rust

If this machine does not have Rust yet:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
source "$HOME/.cargo/env"
rustup component add rustfmt clippy
```

This repository includes `.cargo/config.toml` configured to use the `rsproxy.cn`
sparse registry.

## Build

```bash
cargo build --release --bins
```

This produces sibling `traffic-e2e`, `backend-rewrite`, and
`backend-rewrite-admin` executables. Keep them together when installing or
packaging them: detached rewrite recording actions delegate engine work to the
sibling `traffic-e2e` binary.

## Command Model

Use `traffic-e2e` for direct traffic operations and `backend-rewrite` for
migration orchestration:

```bash
traffic-e2e config init --source-pod <pod> --namespace <namespace>
backend-rewrite next --api 'GET /api/widgets/*' \
  --source-route '/api/widgets/:id'
backend-rewrite status
backend-rewrite inventory
backend-rewrite evidence <query-id>
backend-rewrite recording request --kind standard \
  --reason user-requested --duration-seconds 60 --per-api-case-limit 100
traffic-e2e record ...
traffic-e2e record-comparison ...
traffic-e2e compare ... --policy .traffic-e2e/verification.yaml
traffic-e2e prepare ...
traffic-e2e run-api ...
traffic-e2e run ...
traffic-e2e status ...
traffic-e2e recover ...
traffic-e2e abort ...
```

From a target repository root, the conventional initialization is simply
`traffic-e2e config init --source-pod <pod> --namespace <namespace>`.
Initialization snapshots the selected Kubernetes runtime once and adds
`/.traffic-e2e/local/` to the target `.gitignore`; all non-versioned runtime
data, including recordings, boot inputs, internal state, and rewrite
worktrees, lives below that root.

For a backend migration, `backend-rewrite next` is the normal facade. It
returns one argv-based action, automatically owns Prepare/E2E/Compare
transitions, and exposes only bounded evidence queries. Direct `prepare`,
`run-api`, `compare`, and report-oriented commands remain available to traffic
operators and system maintainers.

Nonpassing focused E2E attempts reuse the active immutable standard cases;
passing attempts advance to fresh comparison recording. An explicit
`backend-rewrite recording request --kind standard` transition replaces the standard
evidence chain only after explicit user authorization. The coordinator, not
the caller, allocates the run ID and returns
the exact recording argv. Omitting `--api` on that request resets any prior
single-API scope and records every API admitted by recorder configuration;
provide `--api` only for an explicitly narrowed fresh recording. Executing the
returned action starts a detached coordinator worker and returns immediately;
poll `backend-rewrite status` until it reports `advance_required`, then execute
the exact `action.commands.advance` command once.

Process-owned dependency rules are evidence-ownership rules, not fresh-capture
contracts. `backend-rewrite dependency-rule apply <plan-id>` preserves the
published cases and raw dependency JSONL, reapplies the current rules to the
latest focused replay report, rebuilds bounded evidence, and returns `next`.
If an interrupted or older coordinator state still carries the strict
dependency-finalize error after that derived view becomes clean, the next
coordinator step repairs the same attempt in place before choosing its action.
If that removes the remaining case-scoped dirty evidence, the same focused
attempt advances to comparison without a new standard recording.

`backend-rewrite` emits one compact JSON object per command by default; use
global `--pretty` for interactive inspection. Normal `next` and `status`
responses contain only the bounded API-inventory summary. Query the full
ordered per-API list explicitly with the read-only `backend-rewrite inventory`
command.

Representative evidence returns the exact immutable standard or comparison
case directory and a structured response difference. Use that case as the
efficient starting point for diagnosis; all generated files under
`.traffic-e2e/local/artifacts/` remain available for read-only inspection when
additional cases are useful.

Dependency evidence is case-scoped. Replay publishes a bounded sidecar with
dirty events clustered by protocol and endpoint, an exact representative case,
and a compact expected/actual dependency difference. Source traffic observed
before readiness is returned separately as reference context. Unused global
traffic and target activity outside a case do not make a case dirty.

Use `backend-rewrite case dependencies <case-dir>` to summarize one returned
case by dependency target. Each target includes an exact `detail_command` that
expands only bounded representative exchanges for that target. Redis key,
argument, and response association is preserved; response previews are capped
at 256 bytes with length and truncation metadata, and complete small Redis
scalars also expose a decoded `response_value`. Memcached flags are not
interpreted or returned.

Evidence-driven recorder and verification-policy changes live under
`traffic-e2e config ... plan|apply`; low-level grouping and report commands live
under `traffic-e2e diagnose`. Managed recording, replay, fixed-user target
isolation, and host interception are implemented by the same Rust binary.

Comparison recording accepts only explicitly configured `GET`, `HEAD`, and
`OPTIONS` methods. Its managed runtime isolates the candidate in a run-owned
bridge namespace, allowing source and candidate to use the same native service
ports. It normally captures one source
response and one candidate response. Set
`comparison_recording.baseline_recheck = true` to additionally capture a
source response after the candidate for source-drift diagnosis. Passing
`record-comparison --baseline-recheck` enables it for one run without changing
the configuration. Comparison recording defaults to 60 seconds; automated
calls pass `--duration-seconds 60` or another positive integer explicitly. An
explicitly scoped recording may finish earlier when every selected API reaches
its per-API case limit; an unscoped recording retains the complete window for
low-frequency API discovery. Backend-rewrite's finite-input comparison binds
the gateway to loopback for that run, so concurrent environment traffic cannot
be published as managed comparison evidence.
Offline `compare` reuses
`.traffic-e2e/verification.yaml`; see
[development.md](docs/development.md#running-locally).

## Run

```bash
cargo run -- --help
cargo run -- diagnose recorder --config config/project.example.yaml
```

Install all binaries and run managed recording from an initialized target
repository:

```bash
cargo install --path .
traffic-e2e record --target-root /path/to/target
traffic-e2e record --target-root /path/to/target \
  --api 'GET /api/widgets/*'
```

Automation can reserve the recording directory name with an explicit UTC run
identifier: `traffic-e2e record --target-root ... --run-id YYYYMMDDHHMMSS`.
Repeat `--api 'METHOD /path-or-pattern'` to restrict only that run; omission
uses the YAML rules unchanged. A supplied selector is also the case's
`api_pattern`, so wildcard traffic stays grouped under the requested API.
Source, optional Breeze, Recorder, interception, readiness, finalization, and
cleanup are owned by traffic-e2e. Use `diagnose recorder` only for low-level
Recorder development; its process-level lifecycle commands are internal.

The default example listens on:

- DNS mock: `127.0.0.153:4053`
- TCP fake-IP gateway: `127.0.0.1:4001`
- UDP fake-IP gateway: `127.0.0.1:4002`
- HTTP gateway for tcpcopy traffic: `0.0.0.0:18084`
- JSONL output: `./.traffic-e2e/local/artifacts/recordings/<run-id>/traffic.jsonl`
- Generated CA: `./.traffic-e2e/local/data/traffic-recorder-ca.pem`

For dependency replay, install the binary and pass the case directory directly:

```bash
cargo install --path .
traffic-e2e --help
traffic-e2e diagnose --help
traffic-e2e replay path/to/case-dir
traffic-e2e replay path/to/recordings/<run-id>
```

For runtime-generated UUIDs, timestamps, signed query fields, and reviewed
response-comparison exemptions, keep a
source-controlled `.traffic-e2e/verification.yaml` in the target project and pass it with
`--policy`. Initialize it with `traffic-e2e config init --source-pod <pod>
--namespace <namespace>` from the target root; initialization, strategy application, replay, and comparison each
validate the policy. See
[Dependency Replay And Response Verification Policy](docs/replay-policy.md).

`traffic-e2e replay` starts the replay DNS and fake-IP TCP gateway, then applies
the same local interception rules used for recording. Interception is always
limited to numeric UID `998`, so every containerized dependency-producing
target process must run as `998:998`. The host's `trp-record` account and its
UID do not determine this owner scope. Build steps, replay itself, and
replay-control commands may remain under the developer account. Use
`--no-intercept` only when the target already routes dependencies directly to
the replay listeners.

For an in-process E2E, build its executable as the developer and run the
prebuilt command through `traffic-e2e target exec`. The command stages the
executable and copied inputs, clears the inherited environment, provides a
private writable work directory, and drops to the fixed numeric identity
`998:998` without resolving a host account. It never accepts a username or UID. Keep
`traffic-e2e diagnose replay-control begin/end/finalize` in the outer
developer-owned process; the target process must not access the replay session
or control socket.

Replay supports recorded HTTP/HTTPS, MySQL, Redis, and Memcached dependencies.
Redis and Memcached exchanges are normally consumed in recorded connection
order. Exact-key Redis `GET`, `SCARD`, and `HGETALL` exchanges and Memcached
`get` exchanges explicitly recorded by a process-scoped process-owned rule remain
single-use but are matched without source
connection binding or lane blockers. The
v5 replay report keeps complete unmatched, unsupported, unsafe, and unused
evidence, records exact success totals, and retains a bounded prefix of success
details. `traffic-e2e diagnose replay-control end/report --fail-on-dirty`
treats all cache protocol discrepancies as failures.

## Optional Explicit HTTP/HTTPS Proxy

The default fake-IP setup does not need a client proxy setting and does not
listen on a proxy port. If you still want traditional explicit proxy mode,
enable it:

```toml
[http]
enabled = true
listen = "127.0.0.1:18081"
```

Then set both HTTP and HTTPS proxy settings to the recorder:

```bash
export HTTP_PROXY=http://127.0.0.1:18081
export HTTPS_PROXY=http://127.0.0.1:18081
```

For HTTPS MITM recording, trust the generated CA certificate on the client:

```bash
sudo ./scripts/setup_system_ca.sh up
```

Some clients use their own trust store, such as browsers, Java, Node.js, or
Python cert bundles. Import the same CA into the relevant client trust store.

## Configure HTTP Gateway for tcpcopy

`http_gateway` is for mirrored HTTP traffic, such as traffic copied by tcpcopy
to the recorder machine. It accepts normal origin-form HTTP requests, applies
rules, and forwards traffic:

- matched traffic goes to `matched_upstream` and is recorded as request/response
- unmatched traffic goes to `fallback_upstream` and is not recorded

Example:

```yaml
recorder:
  http_gateway:
    enabled: true
    listen: 0.0.0.0:18080
    matched_upstream: http://127.0.0.1:8081
    fallback_upstream: http://10.10.20.30:8080
    preserve_host: true
    ready:
      enabled: true
      path: /
      success_status: 200
      interval_ms: 1000
    exclude_rules:
      - name: exclude-health
        methods: [GET]
        path_prefixes: [/health, /metrics]
    rules:
      - name: http-api
        hosts: [api.example.com]
        methods: [GET, POST]
        path_prefixes: [/api/]
        headers: { x-record: "yes" }
```

AI/coordinator-owned source-traffic policy values are stored only in
`.traffic-e2e/source-traffic-policy.yaml`:

```yaml
version: 2
http:
  source_revision: source-git-revision
  case_path_patterns: [/api/users/*/xxx]
  allowed_unused_http_hosts: []
breeze_capture: []
process_owned_dependencies: []
```

`recorder.http_gateway.exclude_rules` uses the same host, method, path-prefix, and
exact-header conditions as ordinary rules. Exclusions are evaluated first;
matching traffic uses the configured fallback and does not create a case. If
no `recorder.http_gateway.rules` entries are configured, all non-excluded gateway
traffic is treated as matched and recorded. Within a rule, values in one list
are alternatives while different fields must all match. `preserve_host = true`
keeps the original `Host` header when forwarding. Recording access policy is
evaluated before both rule sets, so exclusion rules do not bypass
`block_known_writes`.

Use repeatable `record --api 'METHOD /path-or-pattern'` arguments to narrow one
recording run without editing project YAML. Runtime selectors are intersected
with `recorder.http_gateway.rules`; they never widen the configured recording scope.
They also define the selected cases' API grouping. Omitting `--api` preserves
the configured behavior.

`[http_gateway.ready]` is an optional active readiness probe against
`matched_upstream`. When enabled, the recorder sends `GET path` every
`interval_ms` milliseconds, defaulting to once per second. When the response
status equals `success_status`, the recorder waits
`recording.post_ready_settle_ms` milliseconds before closing the shared
bootstrap dependency window and admitting the first case. The default is
10 seconds. Dependencies observed during this fixed settle interval remain
bootstrap dependencies, and matching requests continue to use the configured
fallback. Before case admission opens, Recorder waits for accepted bootstrap
events to finish and flushes their JSONL files; the potentially large bootstrap
summary is generated only when the run finishes. The probe itself is not
recorded as a case. If this section is disabled, the settle interval does not
apply and the bootstrap window still closes when the first matched gateway
case is reserved.

Each recorder process creates one run directory under
`artifacts.root_dir/recordings` named `YYYYMMDDHHMMSS`. Comparison recording
runs use the sibling `artifacts.root_dir/comparison-recordings` directory.
Matched gateway requests create case directories inside the recording run
after the case is complete and valid:

```text
<run-id>/traffic.jsonl
<run-id>/recording-run.json
<run-id>/errors.jsonl
<run-id>/bootstrap-dependencies.jsonl
<run-id>/bootstrap-dependencies-summary.json
<run-id>/bootstrap-dependencies-debug.jsonl
<run-id>/apis/<api-directory>/<case-id>/request.json
<run-id>/apis/<api-directory>/<case-id>/expected-response.json
<run-id>/apis/<api-directory>/<case-id>/dependencies.jsonl
<run-id>/apis/<api-directory>/<case-id>/dependencies-summary.json
<run-id>/apis/<api-directory>/<case-id>/dependencies-debug.jsonl
<run-id>/failed/<api-directory>/<case-id>/
```

`uri-group` is built from the full request URI path joined by hyphens, so
`/api/users/list` is recorded under `api-users-list`. To group dynamic paths,
configure `case_path_patterns`. `*` matches exactly one non-empty path segment.
A final `**` is a catch-all matching one or more remaining path segments. For
example, `/api/users/123/xxx` and `/api/users/456/xxx` both record under
`api-users-wildcard-xxx` when the global HTTP policy has
`case_path_patterns = ["/api/users/*/xxx"]`.

For replay-time AI feedback, keep patterns in `source-traffic-policy.yaml`. Use
`traffic-e2e config recorder apply case-path-patterns`; the command plans and
validates against current evidence before atomically replacing that managed
document. Feedback is add-only even for a
collection-wide case source; an existing pattern is never deleted merely
because current cases omit it. Correct a specifically proven-invalid
AI-managed pattern only through the explicit correction flags described in
[docs/development.md](docs/development.md). Use
`traffic-e2e diagnose case-group ensure` to persist exact static or dynamic API
membership before migration; it writes a
manifest outside the recording source and never moves or edits published
cases.

`request.json` stores the matched gateway request. `expected-response.json`
stores the matched upstream response; if the response body has
`Content-Encoding: gzip` or `deflate`, it is decoded before being written.
Incomplete cases, including truncated request or expected response bodies, are
not published into `apis/<api-directory>/<case-id>`. They are moved under
`<run-id>/failed/...` with `recording-error.json`. A cleanly finalized run
remains `completed`; `failed_cases` and `errors` describe the rejected
individual cases, while run-level `failed` is reserved for Recorder failure.
Fix the recording limit or recorder behavior and record again; do not consume
failed cases as replay fixtures.
When `block_known_writes` rejects a dependency during an active case, the
payload-free `readonly_rejection` is retained in the failed case's
`dependencies.jsonl` and the complete case is moved under `failed/`. The
rejected request never reaches its upstream and the invalid case is not
published for replay.

MySQL writes can be allowed narrowly under `block_known_writes` with an exact
recording access rule:

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

The required non-empty operation, database, and table scopes are matched
exactly; each rule must also specify a route or business target. One rule must
cover every write in a multi-statement query, and queries mixing session
changes with writes are rejected. Allowed writes are forwarded and recorded as
normal `mysql_exchange` dependencies without invalidating the case. A
payload-free `access_policy_allow` audit stays in run-level `traffic.jsonl`.
The rule describes SQL-visible targets; database triggers on an allowed table
remain part of the operator-trusted database schema.
While that gateway request is active, dependency traffic captured by the
fake-IP gateway or explicit HTTP/HTTPS proxy is appended to
`dependencies.jsonl` or `dependencies-debug.jsonl`. The main
`dependencies.jsonl` file is intended for managed replay and keeps semantic
events such as `mysql_exchange`,
`mysql_connection`, and dependency errors. MySQL protocol details such as
`mysql_query`, `mysql_response`, and `mysql_packet` are written to
`dependencies-debug.jsonl` so raw/base64 payloads do not distract the replay path.
Each dependency line keeps the original event fields and adds
`case_dependency_matched_by: "active_window"` because dependencies are owned by
the single active request/response window in the recorder network namespace.

Run the automated readonly gateway/dependency integration test with
`cargo test --test readonly_case_integration`. For a local two-mock or optional
cross-machine system check, follow
[`tests/manual/readonly/README.md`](tests/manual/readonly/README.md).

Before the first matched gateway case is registered, replay-oriented dependency
traffic is also written to run-level `bootstrap-dependencies.jsonl`; protocol
debug records go to `bootstrap-dependencies-debug.jsonl`. The bootstrap window
closes permanently after `[http_gateway.ready]` succeeds and
`recording.post_ready_settle_ms` elapses or, if no ready probe is configured,
when the first case is reserved. Recorder flushes the closed bootstrap files
before activating that case and writes `bootstrap-dependencies-summary.json`
during final run shutdown. Later idle traffic remains only in that run's
`traffic.jsonl` unless it belongs to an active case.

## Configure Local Fake-IP DNS Gateway

This mode is for discovering and proxying many local dependencies without
knowing all ports in advance. It assumes the client process and recorder run on
the same Linux machine.

Flow:

```text
client DNS query -> dns_mock returns fake IP from 198.18.0.0/15
client connects fake_ip:any_port
iptables REDIRECT sends fake_ip:any_port to tcp_gateway.listen
tcp_gateway reads SO_ORIGINAL_DST to recover fake_ip:original_port
fake_ip maps back to original domain and real DNS answer
recorder forwards to real_ip:original_port
```

Example config:

```toml
[dns_mock]
enabled = true
listen = "127.0.0.153:4053"
upstream_dns = "10.10.10.10:53"
fake_cidr = "198.18.0.0/15"
ttl_seconds = 60
registry_path = "./.traffic-e2e/local/artifacts/fake_dns_registry.json"
# Exact names, suffixes starting with ".", and glob wildcards using "*" or "?"
# are returned from upstream DNS unchanged.
bypass_domains = [
  "preview-wss-wegent.intra.demo.test",
  ".metrics.internal.example.com",
  "*.dingtalk.com",
]

# Static host mappings are returned as fake IPs while the recorder keeps the
# configured real IPs for forwarding. Do not add these names to /etc/hosts.
[dns_mock.hosts]
"db-10-185-28-119.test" = ["10.185.28.119"]

[tcp_gateway]
enabled = true
listen = "127.0.0.1:4001"
# Maximum pending connections passed to listen(2); the kernel may cap it at
# net.core.somaxconn.
backlog = 65535
record_http = true
mitm_https = true
# Empty means attempt HTTPS MITM for all TLS-looking TCP streams.
https_ports = []

[tcp_gateway.protocol_detection]
enabled = true
redis_port_hints = [6379]
memcached_port_hints = [11211]
kafka_port_hints = [9092]

[[tcp_gateway.protocol_detection.overrides]]
host = "cache.internal"
port = 6380
protocol = "redis" # redis | memcached | kafka | motan | raw
```

Set up local DNS capture. This keeps the recorder on non-privileged port
`4053`, then captures local UDP/TCP DNS traffic on port `53` and sends it to
`127.0.0.153:4053`. Capture is limited to numeric UID `998`, independent of
host account resolution. Run the Recorder under root or a developer account so
its own upstream DNS queries are outside that owner scope:

```bash
sudo traffic-e2e diagnose interception dns up \
  --dns-ip 127.0.0.153 \
  --dns-port 4053
```

On Linux, the whole `127.0.0.0/8` block routes to loopback, so this does not
usually require adding an address first. If you prefer to make the alias
explicit:

```bash
sudo ip addr add 127.0.0.153/32 dev lo
```

Set up fake-IP TCP capture:

```bash
sudo traffic-e2e diagnose interception fake-ip up \
  --fake-cidr 198.18.0.0/15 \
  --tcp-port 4001 \
  --udp false
```

Test the DNS mock with `dig`:

```bash
dig @127.0.0.153 -p 4053 demo.test A +short
dig demo.test A +short
```

To keep a domain out of recording, add it to `bypass_domains`. Exact entries
match one hostname. Entries starting with `.` match the suffix and the suffix
root, for example `.example.com` matches both `example.com` and
`api.example.com`. Glob-style `*` and `?` wildcards are also supported, so
`*.dingtalk.com` matches `open.dingtalk.com` and `a.b.dingtalk.com`, but not
the root `dingtalk.com`.

To capture a dependency that is configured as a raw IP, give it an application
hostname and put the real IP in `[dns_mock.hosts]` instead of `/etc/hosts`:

```toml
[dns_mock.hosts]
"db-10-185-28-119.test" = ["10.185.28.119"]
```

Then change the application endpoint from `10.185.28.119:3306` to
`db-10-185-28-119.test:3306`. The DNS mock returns a `198.18.x.x` fake IP,
and the TCP gateway forwards to `10.185.28.119:3306`.
Avoid `.local` for these names because many Linux systems route it through
mDNS instead of normal DNS.

When the IP comes from an upstream JSON response, configure an HTTP response
rewrite rule with `authorities`, `methods`, `path_pattern`, and `pointers`
(e.g. `/base_url`). Recorder substitutes a registered synthetic hostname and
captures subsequent HTTP(S) calls. See [response rewriting](docs/development.md#rewriting-http-responses)
for the short configuration and matching semantics. In backend rewrites,
`route --cause unrecorded-ip` returns source investigation and rule plan/apply
instructions before a system defect is submitted; applied capture rules require
fresh recording. Replay rejection packet counts are auxiliary evidence shown
with response/dependency failures and do not identify an IP or change gates.

Fake DNS mappings are persisted at `registry_path` so recorder restarts can
continue handling fake IPs that clients already cached. If a cached fake IP now
belongs to a `bypass_domains` entry, the TCP gateway only forwards it
transparently and does not record or MITM it while the client cache drains.
Registry updates are coalesced in memory and atomically flushed at most once
every 15 seconds, with one final flush during graceful shutdown. A forced
process kill can lose mappings created since the previous periodic flush.

Port `5353` is intentionally avoided because it is commonly used by mDNS/Avahi
on UDP. Binding to `127.0.0.153:4053` also avoids the common systemd-resolved
stub listeners on `127.0.0.53:53` and `127.0.0.54:53`. Interception does
not depend on `resolvectl`; it works by adding a narrow nat chain in iptables.
Every DNS request emitted by a process running as UID `998` is redirected to
the local DNS mock; no destination DNS server is excluded.

To remove the DNS and fake-IP rules:

```bash
sudo traffic-e2e diagnose interception fake-ip down \
  --fake-cidr 198.18.0.0/15 \
  --tcp-port 4001 \
  --udp false
sudo traffic-e2e diagnose interception dns down \
  --dns-ip 127.0.0.153 \
  --dns-port 4053
sudo ./scripts/setup_system_ca.sh down
```

Plain HTTP traffic detected by `tcp_gateway` is recorded as request/response.
When `mitm_https = true`, TLS-looking streams are intercepted with the generated
recorder CA, decoded as HTTPS over HTTP/1.1, forwarded to the real upstream IP
with the original domain as SNI, and recorded as request/response.

Trust `./.traffic-e2e/local/data/traffic-recorder-ca.pem` on the client before enabling HTTPS
MITM. Clients with certificate pinning, or clients that require HTTP/2 only, may
reject the recorder certificate or protocol negotiation.

MySQL upstreams are detected from the server handshake after fake-IP routing.
Redis RESP array commands and Memcached Basic Text/Binary frames are detected
from client wire prefixes on any port. Detection uses complete protocol
metadata, preserves peeked bytes, waits at most one second for a fragmented
prefix, and falls back to raw forwarding when the bytes clearly do not match.
Overrides take precedence; default ports are only hints for incomplete input.
Other TCP protocols are forwarded transparently and recorded as connection-level
`tcp_gateway_connection` events with domain, fake address, upstream address,
byte counts, and timing.

Redis recording supports plaintext standalone RESP2/RESP3 request-response
traffic, pipelines, connection reuse, and `MULTI/EXEC`. It excludes inline
commands, Pub/Sub, `MONITOR`, RESP3 Push, Cluster/Sentinel, TLS, and Unix
sockets. Memcached supports plaintext TCP Basic Text and Binary, including
multi-get, CAS, `noreply`, quiet commands, and NOOP barriers. Meta Text, SASL,
TLS, and UDP are excluded. Entering an excluded or unparseable cache mode marks
the dependency unsafe so the case is failed instead of publishing incomplete
replay evidence.

Cache replay returns the recorded response; it does not implement a general
cache state machine or reproduce response timing. Redis authentication and
common connection initialization are handled by the replay server. Passwords
from Redis `AUTH`/`HELLO AUTH` and Memcached SASL payloads are never stored.
Keys and values are required replay evidence and are recorded in full by
default, so the recording directory must be handled as sensitive data.

## Optional MySQL Protocol Proxy

When using `dns_mock + tcp_gateway`, you do not need to configure `[mysql]`.
MySQL traffic is captured through fake IP routing. The gateway detects the
server handshake, records login metadata without auth response bytes, rejects
MySQL TLS, and records parseable query metadata plus grouped server response
payloads as `mysql_connection`, `mysql_query`, `mysql_response`, or
`mysql_exchange` records. By default, `mysql_response` records one concatenated
response payload and omits the raw packet list. `mysql_exchange` is the
semantic form intended for replay: it includes SQL, prepared statement ids,
parsed execute parameters when available, response columns, rows, OK
metadata, and MySQL errors. Set
`[mysql].record_raw_packets = true` only when you need per-packet protocol
debugging details.

Enable `[mysql]` only when you want a dedicated MySQL protocol proxy listener.
In that mode, keep the original database hostname and port in the client by
resolving each database hostname to a different IP alias on the recorder
machine.

Local Linux test setup:

```bash
sudo ip addr add 127.0.0.2/8 dev lo
sudo ip addr add 127.0.0.3/8 dev lo
```

Production usually uses aliases/VIPs on the real NIC:

```bash
sudo ip addr add 10.10.10.11/32 dev eth0
sudo ip addr add 10.10.10.12/32 dev eth0
```

Example hosts/DNS:

```text
10.10.10.11 mysql-master.example
10.10.10.12 mysql-slave.example
```

Example recorder routes:

```toml
[mysql]
enabled = true
record_raw_packets = false

[[mysql.routes]]
name = "master"
listen = "10.10.10.11:3306"
upstream = "real-master:3306"

[[mysql.routes]]
name = "slave"
listen = "10.10.10.12:3306"
upstream = "real-slave:3306"
```

The client endpoint stays unchanged:

```bash
mysql -h mysql-master.example -P 3306 -u app_user -p
mysql -h mysql-slave.example -P 3306 -u app_user -p
```

Important: MySQL does not send the original hostname in its protocol handshake.
If two database hostnames resolve to the exact same recorder IP and port, the
recorder cannot tell them apart. Use different recorder IP aliases for
different upstreams when the port must remain the same.

MySQL TLS is not implemented in v1. If the client sends a `CLIENT_SSL` upgrade
request, the proxy records a `mysql_tls_rejected` event and closes the
connection. Disable MySQL SSL/TLS in the client for recorded sessions.

## JSONL Events

Records are appended to the current run's `traffic.jsonl`. Event types include:

- `http_exchange`
- `tcp_gateway_connection`
- `mysql_connection`
- `mysql_query`
- `mysql_response`
- `mysql_exchange`
- `mysql_packet` (legacy/debug packet-level records)
- `mysql_tls_rejected`
- `redis_connection`
- `redis_exchange`
- `memcached_connection`
- `memcached_exchange`
- `kafka_connection`
- `kafka_produce`
- `kafka_fetch`
- `kafka_delivery`
- `motan_connection`
- `motan_exchange`
- `proxy_error`

HTTP/HTTPS bodies and binary-safe cache arguments, values, and response frames
are base64 encoded and truncated according to
`recording.max_body_bytes`. Original and stored byte lengths are included.
MySQL response payloads are also base64 encoded and truncated with the same
limit. MySQL password/auth response bytes are not recorded. For AI replay use
cases, prefer `mysql_exchange` over raw `mysql_response.payload`: it contains
structured query input and parsed output rows where the recorder has enough
protocol context.

## Validate

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```
