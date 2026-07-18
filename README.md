# traffic-recorder-proxy

Rust single-binary proxy that records HTTP, HTTPS, and MySQL traffic to JSONL.

## Features

- Optional HTTP proxy for regular absolute-form proxy requests.
- Optional HTTPS proxy with `CONNECT` MITM recording.
- HTTP gateway for tcpcopy mirrored traffic with rule-based forwarding.
- Local fake-DNS + TCP gateway mode for dependency discovery, broad port
  capture, and HTTP/HTTPS recording.
- Automatic local root CA generation, with support for configured CA cert/key paths.
- Full request/response recording with configurable body truncation.
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
cargo build --release
```

## Run

```bash
cargo run -- --config config/recorder.example.toml
```

For watch-mode recording, install the repo-level command and run
`traffic-record`. It runs `cargo watch` and enables local DNS capture plus
fake-IP TCP redirect by default. Use `traffic-record --no-dns` when you want to
skip those local rules.

```bash
mkdir -p "$HOME/.local/bin"
ln -sf "$PWD/scripts/traffic-record" "$HOME/.local/bin/traffic-record"
command -v traffic-record
traffic-record --config config/recorder.example.toml
```

Local interception is always filtered to the fixed `trp-record` Unix user.
This is a project-created system account, not a Linux built-in. Create it once,
run the source service as that user, then start the recorder:

```bash
sudo useradd --system --create-home --shell /bin/bash trp-record
sudo -u trp-record /path/to/source-service start
traffic-record --config config/recorder.example.toml
```

The owner scope cannot be overridden from the CLI, environment, or recorder
configuration. This prevents a recording session from intercepting DNS and
fake-IP traffic belonging to the developer's login user.

The default example listens on:

- DNS mock: `127.0.0.153:15353`
- TCP fake-IP gateway: `127.0.0.1:15001`
- HTTP gateway for tcpcopy traffic: `0.0.0.0:18084`
- JSONL output: `./recordings/<run-id>/traffic.jsonl`
- Generated CA: `./data/traffic-recorder-ca.pem`

For dependency replay, install the repo-level replay command and pass the case
directory directly:

```bash
cargo build
mkdir -p "$HOME/.local/bin"
ln -sf "$PWD/target/debug/traffic-recorder-proxy" "$HOME/.local/bin/traffic-recorder-proxy"
ln -sf "$PWD/scripts/traffic-record" "$HOME/.local/bin/traffic-record"
ln -sf "$PWD/scripts/traffic-replay" "$HOME/.local/bin/traffic-replay"
ln -sf "$PWD/scripts/traffic-replay-target" "$HOME/.local/bin/traffic-replay-target"
ln -sf "$PWD/scripts/traffic-replay-policy" "$HOME/.local/bin/traffic-replay-policy"
ln -sf "$PWD/scripts/traffic-recorder-config" "$HOME/.local/bin/traffic-recorder-config"
ln -sf "$PWD/scripts/traffic-case-group" "$HOME/.local/bin/traffic-case-group"
command -v traffic-recorder-proxy
command -v traffic-record
command -v traffic-replay
command -v traffic-replay-target
command -v traffic-replay-policy
command -v traffic-case-group
traffic-replay path/to/case-dir
traffic-replay path/to/recordings/<run-id>
```

For runtime-generated UUIDs, timestamps, and signed query fields, keep a
source-controlled `config/replay.yaml` in the target project and pass it with
`--policy`. Validate it with `traffic-replay-policy validate --policy
config/replay.yaml`. See [Replay Dynamic-Value Policy](docs/replay-policy.md).

`traffic-replay` starts the replay DNS and fake-IP TCP gateway, then applies
the same local interception rules used for recording. Interception is always
limited to `trp-record`, so the dependency-producing target process must run as
that user. Build steps, replay itself, and replay-control commands may remain
under the developer account. Use `--no-intercept` only when the target already
routes dependencies directly to the replay listeners.

For an in-process E2E, build its executable as the developer and run the
prebuilt command through `traffic-replay-target`. The command stages the
executable and copied inputs, clears the inherited environment, provides a
private writable work directory, and resolves the fixed user from
`traffic-replay --print-intercept-user`. It never accepts a username or UID.
Keep `traffic-replay-cli begin/end/finalize` in the outer developer-owned
facade; the target process must not access the replay session or control socket.

Replay supports recorded HTTP/HTTPS, MySQL, Redis, and Memcached dependencies.
Redis and Memcached exchanges are consumed in recorded connection order. The
v5 replay report keeps complete unmatched, unsupported, unsafe, and unused
evidence, records exact success totals, and retains a bounded prefix of success
details. `traffic-replay-cli end/report --fail-on-dirty` treats all cache
protocol discrepancies as failures.

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

```toml
[http_gateway]
enabled = true
listen = "0.0.0.0:18080"
matched_upstream = "http://127.0.0.1:8081"
fallback_upstream = "http://10.10.20.30:8080"
preserve_host = true

[http_gateway.ready]
enabled = true
path = "/"
success_status = 200
interval_ms = 1000

[http_gateway.verified_excludes]
consecutive_successes = 3
# BEGIN AI-MANAGED VERIFIED API EXCLUDES
apis = [
  # { rule = "record-api", method = "GET", path_pattern = "/api/users/*" },
]
# END AI-MANAGED VERIFIED API EXCLUDES

[[http_gateway.exclude_rules]]
name = "exclude-health"
methods = ["GET"]
path_prefixes = ["/health", "/metrics"]

[[http_gateway.rules]]
name = "record-api"
hosts = ["api.example.com"]
methods = ["GET", "POST"]
path_prefixes = ["/api/"]
# BEGIN AI-MANAGED CASE PATH PATTERNS
# source_revision = "source-git-revision"
case_path_patterns = ["/api/users/*/xxx"]
# END AI-MANAGED CASE PATH PATTERNS
headers = { "x-record" = "yes" }
```

`[[http_gateway.exclude_rules]]` uses the same host, method, path-prefix, and
exact-header conditions as ordinary rules. Exclusions are evaluated first;
matching traffic is sent to `fallback_upstream` and does not create a case. If
no `[[http_gateway.rules]]` entries are configured, all non-excluded gateway
traffic is treated as matched and recorded. Within a rule, values in one list
are alternatives while different fields must all match. `preserve_host = true`
keeps the original `Host` header when forwarding. Recording access policy is
evaluated before both rule sets, so exclusion rules do not bypass
`block_known_writes`.

`[http_gateway.verified_excludes]` contains recorder-owned, replay-verified API
exclusions. After the configured number of consecutive clean cases also pass
the target response assertions, run the managed `verified-excludes ensure`
command. It decides the threshold outcome, applies an eligible exact
`rule + method + path_pattern`, and verifies convergence without AI judgment.
On the next recorder start, matching traffic goes to `fallback_upstream`
without creating a case.
See [Verified API Excludes](docs/verified-api-excludes.md).

`[http_gateway.ready]` is an optional active readiness probe against
`matched_upstream`. When enabled, the recorder sends `GET path` every
`interval_ms` milliseconds, defaulting to once per second. When the response
status equals `success_status`, the shared bootstrap dependency window closes.
The probe itself is not recorded as a case. If this section is disabled, the
bootstrap window still closes when the first matched gateway case starts.

Each recorder process creates one run directory under `recording.output_dir`
named `YYYYMMDDHHMMSS`. Matched gateway requests create case directories inside
that run after the case is complete and valid:

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

`uri-group` is built from the full request URI path joined by hyphens, so
`/api/users/list` is recorded under `api-users-list`. To group dynamic paths,
configure `case_path_patterns`. `*` matches exactly one non-empty path segment.
A final `**` is a catch-all matching one or more remaining path segments. For
example, `/api/users/123/xxx` and `/api/users/456/xxx` both record under
`api-users-wildcard-xxx` when the rule has
`case_path_patterns = ["/api/users/*/xxx"]`.

For replay-time AI feedback, keep patterns inside the explicit managed block
shown above. Use `traffic-recorder-config case-path-patterns plan` to inspect
the proposed diff, then rerun it with `apply`. Focused case sources are
add-only; deletion requires an authoritative case source and the explicit
`--allow-delete` flag. See [docs/development.md](docs/development.md) for the
complete command. Use `traffic-case-group ensure` to persist exact static or
dynamic API membership before migration; it writes a manifest outside the
recording source and never moves or edits published cases.

`request.json` stores the matched gateway request. `expected-response.json`
stores the matched upstream response; if the response body has
`Content-Encoding: gzip` or `deflate`, it is decoded before being written.
Incomplete cases, including truncated request or expected response bodies, are
not published into `<rule-name>/<uri-group>/<case-id>`. They are moved under
`<run-id>/failed/...` with `recording-error.json`, and a clean shutdown
returns an error when the run has failed cases. Fix the recording limit or
recorder behavior and record again; do not consume failed cases as replay
fixtures.
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
`case_dependency_matched_by`: `process` when the dependency process matches the
upstream process, or `active_window` when it was recorded because it happened
during the request/response window. Dependency case files compact
`client_process` to just the process id to keep them small; the global
`traffic.jsonl` keeps the full process details.

Run the automated readonly gateway/dependency integration test with
`cargo test --test readonly_case_integration`. For a local two-mock or optional
cross-machine system check, follow
[`tests/manual/readonly/README.md`](tests/manual/readonly/README.md).

Before the first matched gateway case is registered, replay-oriented dependency
traffic is also written to run-level `bootstrap-dependencies.jsonl`; protocol
debug records go to `bootstrap-dependencies-debug.jsonl`. The bootstrap window
closes permanently when `[http_gateway.ready]` succeeds or, if no ready probe is
configured, when the first case starts. Later idle traffic remains only in
that run's `traffic.jsonl` unless it belongs to an active case.

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
listen = "127.0.0.153:15353"
upstream_dns = "10.10.10.10:53"
fake_cidr = "198.18.0.0/15"
ttl_seconds = 60
registry_path = "./recordings/fake_dns_registry.json"
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
listen = "127.0.0.1:15001"
record_http = true
mitm_https = true
# Empty means attempt HTTPS MITM for all TLS-looking TCP streams.
https_ports = []

[tcp_gateway.protocol_detection]
enabled = true
redis_port_hints = [6379]
memcached_port_hints = [11211]

[[tcp_gateway.protocol_detection.overrides]]
host = "cache.internal"
port = 6380
protocol = "redis" # redis | memcached | raw
```

Set up local DNS capture. This keeps the recorder on non-privileged port
`15353`, then captures local UDP/TCP DNS traffic on port `53` and sends it to
`127.0.0.153:15353`. The configured upstream DNS is excluded so the recorder can
forward queries without recursively hitting itself:

```bash
sudo DNS_IP=127.0.0.153 DNS_PORT=15353 UPSTREAM_DNS=10.10.10.10:53 ./scripts/setup_local_dns.sh up
```

On Linux, the whole `127.0.0.0/8` block routes to loopback, so this does not
usually require adding an address first. If you prefer to make the alias
explicit:

```bash
sudo ip addr add 127.0.0.153/32 dev lo
```

Set up fake-IP TCP capture:

```bash
sudo FAKE_CIDR=198.18.0.0/15 GATEWAY_PORT=15001 ./scripts/setup_fake_ip_redirect.sh up
```

Test the DNS mock with `dig`:

```bash
dig @127.0.0.153 -p 15353 demo.test A +short
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

Fake DNS mappings are persisted at `registry_path` so recorder restarts can
continue handling fake IPs that clients already cached. If a cached fake IP now
belongs to a `bypass_domains` entry, the TCP gateway only forwards it
transparently and does not record or MITM it while the client cache drains.

Port `5353` is intentionally avoided because it is commonly used by mDNS/Avahi
on UDP. Binding to `127.0.0.153:15353` also avoids the common systemd-resolved
stub listeners on `127.0.0.53:53` and `127.0.0.54:53`. The setup script does
not depend on `resolvectl`; it works by adding a narrow nat chain in iptables.
Keep `UPSTREAM_DNS` aligned with `[dns_mock].upstream_dns`.

To remove the DNS and fake-IP rules:

```bash
sudo DNS_IP=127.0.0.153 DNS_PORT=15353 UPSTREAM_DNS=10.10.10.10:53 ./scripts/setup_local_dns.sh down
sudo FAKE_CIDR=198.18.0.0/15 GATEWAY_PORT=15001 ./scripts/setup_fake_ip_redirect.sh down
sudo ./scripts/setup_system_ca.sh down
```

Plain HTTP traffic detected by `tcp_gateway` is recorded as request/response.
When `mitm_https = true`, TLS-looking streams are intercepted with the generated
recorder CA, decoded as HTTPS over HTTP/1.1, forwarded to the real upstream IP
with the original domain as SNI, and recorded as request/response.

Trust `./data/traffic-recorder-ca.pem` on the client before enabling HTTPS
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

For local Linux clients, `tcp_gateway` also tries to attribute intercepted
connections to a process by scanning `/proc/net/tcp` and `/proc/<pid>/fd`.
When available, JSONL events include `client_process` with `pid`, `comm`,
`cmdline`, and `exe`; TLS handshake warnings log the same process label.

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
