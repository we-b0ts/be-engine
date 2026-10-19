# External Kubernetes recording lifecycle regression

This opt-in test runs the actual `traffic-e2e record` controller and UID 998 Source
in disposable Docker network namespaces. A synthetic kubectl supplies Service
JSON and listens on allocated local ports. No Kubernetes cluster or credentials
are used. Containers use `--network=none` and loopback DNS; the real fake-DNS,
conntrack-zone and TCP interception rules remain confined to each container.

Requirements: Linux/amd64, Docker, Python 3 on the host, kernel support for the
recording interception rules, and a local recording image containing Python 3,
`setpriv`, `ip` and `iptables`. The image's application is never started.

```bash
cargo build --bin traffic-e2e
python3 tests/manual/kubernetes_recording/verify.py \
  --binary target/debug/traffic-e2e --image source-recording:local
```

The test checks:

- Source starts only after both discovered ports are ready; the project route
  configuration contains no ports, and Pod target ports differ from Service ports.
- Actual Source HTTP calls to an otherwise unresolvable cluster hostname cross
  fake DNS and the recording gateway, preserving Host and logical endpoint ports.
- Normal shutdown completes and publishes its case.
- Port-forward exit stops recording and persists a failed run manifest.
- Partial forwarding startup failure never starts Source.

Each test owns its container and temporary fixture tree and cleans them up on
success or failure. Ordinary `cargo test` does not require Docker/firewall access;
unit tests cover subprocess cancellation, descendant cleanup and HTTPS SNI too.
