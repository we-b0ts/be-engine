# Target Integration

The target repository exposes one conventional build contract:

```text
.traffic-e2e/Dockerfile.e2e
```

The Dockerfile is a BuildKit multi-stage build. Its final image must declare a
non-empty OCI entrypoint, default to `USER 998:998`, run the normal target and
genuine dependency clients in the foreground, log to stdout/stderr, and stop
cleanly on `SIGTERM`. Each configured source-compatible startup path is mounted
read-only at the same absolute path it had in the source container. Only
allowlisted, application-owned environment names are supplied with values
frozen from the source container. Optional application-owned port and Replay
CA environment names are configured explicitly. Target code must not depend on
generic `TRAFFIC_E2E_*` environment variables.

When Breeze is configured, the system mounts `/data1/breeze/socks` and
`/data1/breeze/snapshot` read-only; the image must not start Breeze. During
Replay, `/traffic-e2e/trust/replay-ca.pem` is a read-only public certificate.
When the project declares `replay_ca_environment`, that application-owned
variable names this path. Target TLS clients must additionally trust it through
their normal Rust TLS configuration. The image must not inspect Replay sessions
or receive a CA private key.

Use the pinned shared Rust builder/runtime images and stable BuildKit cache
mount IDs. The target stays alive for every case in one focused/full round.

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

Initialization captures declared authoritative inputs below
`.traffic-e2e/local/startup/mounts`, preserving each absolute source path, and
captures only named Docker `Config.Env` values in mode-0600
`environment.json`. Never materialize configuration from source-process memory,
remote responses, recordings, logs, or diagnostics. A complete
source-SDK-owned snapshot may be transported only in its native format.

The configured `target.port` is the single port source for readiness, the
replay HTTP driver, and the Platform comparison driver. It is passed to the
target only when `target.startup.port_environment` declares the application's
native variable name.
