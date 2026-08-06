# Target Integration

The target repository exposes one conventional build contract:

```text
.traffic-e2e/Dockerfile.e2e
```

The Dockerfile is a BuildKit multi-stage build. Its final image must declare a
non-empty OCI entrypoint, default to `USER 998:998`, run the normal target and
genuine dependency clients in the foreground, log to stdout/stderr, and stop
cleanly on `SIGTERM`. The entrypoint reads only the supplied
`TRAFFIC_E2E_CONFIG_DIR=/traffic-e2e/config` and
`TRAFFIC_E2E_TARGET_PORT=<port>` contract. The system mounts
`.traffic-e2e/local/boot` read-only at that config path.

When Breeze is configured, the system mounts `/data1/breeze/socks` and
`/data1/breeze/snapshot` read-only; the image must not start Breeze. During
Replay, `TRAFFIC_E2E_REPLAY_CA_CERT_PATH` names a read-only public certificate
that target TLS clients must additionally trust through their normal Rust TLS
configuration. The image must not inspect Replay sessions or receive a CA
private key.

Use the pinned shared Rust builder/runtime images and stable BuildKit cache
mount IDs. The target stays alive for every case in one focused/full round.

Do not add traffic-specific `status`, `e2e`, test, check, recording,
comparison, case execution, response capture, assertion, Replay lifecycle, or
aggregation commands. traffic-e2e owns those operations and sends recorded
HTTP requests itself.

Target product code, entrypoint, configuration, tests, and support must not read:

- `expected-response.json` or candidate response artifacts;
- `dependencies.jsonl` or Global dependency files;
- Replay session/control files;
- generated `.traffic-e2e/local/ai-forbidden/` state or reports;
- request-header encryption keys.

`.traffic-e2e/local/boot` may be absent at initialization. When startup proves a
required configuration root, place only authoritative source-compatible
inputs there. Never materialize configuration from source-process memory,
remote responses, recordings, logs, or diagnostics. A complete
source-SDK-owned snapshot may be transported only in its native format.

The configured `target.port` is the single port source for the container
environment, readiness origin, replay HTTP driver, and Platform comparison
driver.
