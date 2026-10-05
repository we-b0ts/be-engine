# DNS conntrack isolation regression

This opt-in Linux test exercises the real `traffic-e2e diagnose interception
dns up/down` commands in a disposable network namespace. It never changes the
host firewall or contacts an external DNS service. It uses only Python's
standard library and local DNS stubs; no application image is needed. It runs
once with loopback source/resolver addresses and again with source `192.0.2.10`
and resolver `192.0.2.53` assigned to a dummy interface in a separate namespace.
Both runs use concrete loopback mock listener IPs and require working reverse
NAT. DNS interception requires a concrete IPv4 listener address; wildcard
`0.0.0.0` is rejected before changing rules or existing conntrack state.

Requirements: Python 3.9 or newer (including `/usr/bin/python3` for UID 998),
`ip`, `iptables`, `conntrack`, `unshare`,
and root privileges or passwordless `sudo -n`. The kernel must support network
namespaces, owner matching, DNAT and conntrack zones. Build the product binary
before running:

```bash
cargo build --bin traffic-e2e
python3 tests/manual/dns_conntrack/verify.py --binary target/debug/traffic-e2e
```

The launcher always creates a new network namespace. Its inner runner also
checks that its namespace differs from the launcher's before issuing firewall
commands. Firewall cleanup runs on failure; destroying the namespace removes
its listeners, rules and conntrack entries regardless of cleanup success.

The test asserts:

- A root DNS query establishes an existing UDP conntrack tuple. UID 998 then
  reuses its exact source address, source port and resolver endpoint and still
  receives the mock answer. Root continues receiving the real answer, and both
  conntrack zones coexist.
- Connected UDP receives the resolver's reverse-NAT response, and TCP capture
  also respects the UID boundary.
- Repeated `up` is idempotent. Changing both listener IP and port removes old
  listener rules and replaces the existing captured UDP tuple at the new
  listener without deleting root's conntrack entry (its ID remains unchanged).
  TCP also uses the new listener. A wildcard listener is rejected without
  changing the active capture.
- Repeated `down` removes all added raw/nat rules and chains, restores normal
  DNS for UID 998, and permits another complete `up/down` cycle using that same
  UDP tuple.
- Redirecting the command's stdout to `/dev/full` induces a real failure after
  rule installation. `up` must return nonzero and roll back its rules and
  captured conntrack entries while preserving root's established flow.

The fresh namespace installs one temporary filter `ACCEPT` rule with conntrack
matching to activate tracking before the first root query. It removes that rule
on exit; the product lifecycle assertions compare raw/nat rules to their empty
namespace baseline.

An unfixed binary fails the first UID 998 assertion: it receives the real DNS
answer through the conntrack tuple established by root. This test intentionally
does not run as part of ordinary `cargo test`, which must not require firewall
privileges.
