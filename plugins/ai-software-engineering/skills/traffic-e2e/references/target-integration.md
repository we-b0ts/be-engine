# Target Integration

The target repository exposes one thin conventional executable:

```text
scripts/<project>-cli start --e2e --start-breeze off \
  --boot-dir .traffic-e2e/boot --port <port>
scripts/<project>-cli stop
```

`start` launches the normal target and genuine dependency clients. It must use
the exact supplied configuration directory and port. `--start-breeze off`
means traffic-e2e owns any shared Breeze lifecycle. When
`TRAFFIC_E2E_REPLAY_CA_CERT_PATH` is present, `start` may stage that read-only
public certificate through the target's normal trust mechanism. It must not
inspect Replay sessions or receive a CA private key.

Every `start --e2e` invocation must invoke the project's normal compile
command once before launching the target, even if an artifact already exists.
If the compile command supports `--release`, it must receive `--release` and
the CLI must launch the resulting release artifact. This is a compile option,
not a `start` subcommand argument; traffic-e2e never appends `--release` to the
fixed start command above.

`stop` is idempotent and stops only the target-owned process. The target stays
alive for every case in one focused/full round.

Do not add traffic-specific `status`, `e2e`, test, check, recording,
comparison, case execution, response capture, assertion, Replay lifecycle, or
aggregation commands. traffic-e2e owns those operations and sends recorded
HTTP requests itself.

Target product code, CLI, configuration, tests, and support must not read:

- `expected-response.json` or candidate response artifacts;
- `dependencies.jsonl` or Global dependency files;
- Replay session/control files;
- generated `.traffic-e2e/local/` state or reports;
- request-header encryption keys.

`.traffic-e2e/boot` may be absent at initialization. When startup proves a
required configuration root, place only authoritative source-compatible
inputs there. Never materialize configuration from source-process memory,
remote responses, recordings, logs, or diagnostics. A complete
source-SDK-owned snapshot may be transported only in its native format.

The configured `target.port` is the single port source for the CLI start
argument, readiness origin, replay HTTP driver, and Platform comparison driver.
