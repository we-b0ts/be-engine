# Target Integration

The target repository exposes one conventional build contract:

```text
.traffic-e2e/Dockerfile.e2e
```

The Dockerfile is a BuildKit multi-stage build. Its final image must declare a
non-empty OCI entrypoint, default to `USER 998:998`, run the normal target and
genuine dependency clients in the foreground, and stop cleanly on `SIGTERM`.
Application logs belong in a configured writable runtime output such as
`/data1/weibo/logs`; stdout/stderr output is not required. Each configured
source-compatible startup path is mounted at the same absolute path it had in
the source snapshot. Captured ConfigMap/Secret access is preserved and
image-local source paths default to read-only. Every target start loads source
application environment from that snapshot, followed by the ignored
project-level `.traffic-e2e/local/target.env` overrides. There is no
generic or application-specific port mapping. The Breeze connection host below
is runtime-owned and does not require a declaration. Target code must not
depend on generic `TRAFFIC_E2E_*` environment variables.

When Breeze is configured, the system mounts `/data1/breeze/socks` and
`/data1/breeze/snapshot` read-only and injects
`MESH_CONNECT_HOST=breeze.recording` without a target startup declaration; the
image must not start Breeze. During Replay,
`/traffic-e2e/trust/replay-ca.pem` is a read-only public certificate. A target
runtime that needs an application-owned variable for this fixed path receives
it through `target.env`, managed during implementation. Target TLS clients must
additionally trust it through their normal TLS configuration. The image must
not inspect Replay sessions or receive a CA private key.

Optional `target.runtime_outputs` are application-output-only writable mounts.
The engine creates retained host directories per run, role, and output below
`.traffic-e2e/local/runtime-outputs/`, prints and reports each resolved host
path, and mounts it at the configured absolute container path. Managed Record
mounts the source role, managed Comparison mounts separate source and target
roles, and Replay mounts the target role. These paths must not overlap startup
inputs. Their contents never enter the startup snapshot, target build context,
Replay inputs, or expected-response evidence.

Use the pinned shared Rust builder/runtime images, the required BuildKit SSH
mount, and stable BuildKit cache mount IDs. traffic-e2e owns the repository-local
SSH agent at `.traffic-e2e/local/socks/ssh-agent.sock`: it reuses a usable agent,
recreates a stale socket, loads the calling account's default OpenSSH identities,
and forwards that exact socket to Docker. The private keys never enter the
image. The target stays alive for every case in one focused/full round. A
Docker or Cargo build failure must remain bounded but include actionable build
output in preflight and E2E APIs.

Do not add traffic-specific `status`, `e2e`, test, check, recording,
comparison, case execution, response capture, assertion, Replay lifecycle, or
aggregation commands. traffic-e2e owns those operations and sends recorded
HTTP requests itself.

Target production behavior must not depend on:

- `expected-response.json` or candidate response artifacts;
- `dependencies.jsonl` or Global dependency files;
- Replay session/control files;
- generated `.traffic-e2e/local/runtime/` state or reports;
- request-header encryption keys.

The managed startup snapshot captures declared authoritative inputs below
`.traffic-e2e/local/startup/mounts`, preserving each absolute source path.
Application environment comes from `.traffic-e2e/local/source/`; the mode-0600
`.traffic-e2e/local/target.env` contains overrides and additions. Never
materialize configuration from remote responses, recordings, logs, or
diagnostics. A complete source-SDK-owned snapshot may be transported only in
its native format.

The port in recorder `http_gateway.matched_upstream` is the single native HTTP
port source for readiness, the replay HTTP driver, and the Platform comparison
driver. Replay addresses it on loopback; Comparison preserves it on the
run-owned target bridge IP. traffic-e2e does not inject that port through an
environment-variable convention.
