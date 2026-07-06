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
cargo run -- --config config.example.toml
```

For watch-mode development, `./scripts/dev.sh` runs `cargo watch` and enables
local DNS capture plus fake-IP TCP redirect by default. Use
`./scripts/dev.sh --no-dns` when you want to skip those local rules.

The default example listens on:

- DNS mock: `127.0.0.153:15353`
- TCP fake-IP gateway: `127.0.0.1:15001`
- HTTP gateway for tcpcopy traffic: disabled by default, sample `127.0.0.1:18080`
- JSONL output: `./recordings/traffic.jsonl`
- Generated CA: `./data/traffic-recorder-ca.pem`

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

[[http_gateway.rules]]
name = "record-api"
hosts = ["api.example.com"]
methods = ["GET", "POST"]
path_prefixes = ["/api/"]
headers = { "x-record" = "yes" }
```

If no `[[http_gateway.rules]]` entries are configured, all gateway traffic is
treated as matched and recorded. Matching supports host, method, path prefix,
and exact header value checks. `preserve_host = true` keeps the original `Host`
header when forwarding.

Matched gateway requests also create a case directory under
`recording.output_dir`:

```text
<rule-name>/<case-id>/request.json
<rule-name>/<case-id>/expected-response.json
<rule-name>/<case-id>/dependencies.jsonl
<rule-name>/<case-id>/dependencies-debug.jsonl
```

`request.json` stores the matched gateway request. `expected-response.json`
stores the matched upstream response; if the response body has
`Content-Encoding: gzip` or `deflate`, it is decoded before being written.
While that gateway request is active, dependency traffic captured by the
fake-IP gateway is appended to `dependencies.jsonl` or
`dependencies-debug.jsonl`. The main `dependencies.jsonl` file is intended for
mock generation and keeps semantic events such as `mysql_exchange`,
`mysql_connection`, and dependency errors. MySQL protocol details such as
`mysql_query`, `mysql_response`, and `mysql_packet` are written to
`dependencies-debug.jsonl` so raw/base64 payloads do not distract the mock path.
Each dependency line keeps the original event fields and adds
`case_dependency_matched_by`: `process` when the dependency process matches the
upstream process, or `active_window` when it was recorded because it happened
during the request/response window. Dependency case files compact
`client_process` to just the process id to keep them small; the global
`traffic.jsonl` keeps the full process details. Dependency traffic without an
active matched gateway request is only written to the global `traffic.jsonl`.

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

MySQL upstreams are detected from the server handshake after fake-IP routing and
recorded with parsed connection/query/packet events. Other TCP protocols are
forwarded transparently and recorded as connection-level
`tcp_gateway_connection` events with domain, fake address, upstream address,
byte counts, and timing.

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
semantic form intended for mock generation: it includes SQL, prepared statement
ids, parsed execute parameters when available, response columns, rows, OK
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

Records are appended to `traffic.jsonl`. Event types include:

- `http_exchange`
- `tcp_gateway_connection`
- `mysql_connection`
- `mysql_query`
- `mysql_response`
- `mysql_exchange`
- `mysql_packet` (legacy/debug packet-level records)
- `mysql_tls_rejected`
- `proxy_error`

HTTP and HTTPS bodies are base64 encoded and truncated according to
`recording.max_body_bytes`. Original and stored byte lengths are included.
MySQL response payloads are also base64 encoded and truncated with the same
limit. MySQL password/auth response bytes are not recorded. For AI/mock use
cases, prefer `mysql_exchange` over raw `mysql_response.payload`: it contains
structured query input and parsed output rows where the recorder has enough
protocol context.

## Validate

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```
