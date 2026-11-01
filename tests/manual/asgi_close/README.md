# Python ASGI Socket.IO close regression

Run against a local recording image with Python Socket.IO, Engine.IO, Uvicorn,
websockets, `setpriv`, `ip`, and `iptables`:

```bash
python3 tests/manual/asgi_close/verify.py \
  --binary target/release/traffic-e2e --image wegent-recording:local
```

Omit `--binary` to validate the engine packaged inside the image. Docker needs
permission to create a network namespace with NET_ADMIN and NET_RAW. The test
uses `--network=none`, synthetic Source/configuration, static fake-DNS mapping,
temporary private evidence, and no business credentials or host ports.

Twelve consecutive cases alternate client WS CLOSE 1000/1001, Engine.IO CLOSE,
bare TCP EOF, TCP reset and a truncated WebSocket frame. The four complete-boundary
TCP ends must publish with their actual typed `transport_end` input and original
offset, without an invented CLOSE. The two truncated-frame cases must stay
failed. Each must retain its disconnect dependency and allow the next case to run.
Each application's disconnect callback starts a real Redis read after 180 ms,
beyond the ordinary 100 ms post-response window, and waits for its response.
Every read must remain in its original case; the Source and Recorder must stay
alive for the next case. Final SIGTERM must finalize evidence and return exit 1
because the batch contains two failed cases; it must not exit on its own before
that signal. Independent finalization errors must still fail this verifier.

For v3 recordings the verifier authenticates the sealed central semantic ledger
and each Case scope against `dependency-manifest.json`, then seeks only the
scope's original offset/length/SHA256 references in `dependencies.jsonl`. It
checks physical exchange/effect identity and `origin_case_id`, exactly one
successful `GET late-N`, its real response, and the delayed callback's request
clock. Metadata, per-record sizes and Case record counts are bounded. Legacy
Case-local semantic files remain readable when no v3 manifest exists; the test
never reads `dependencies-debug.jsonl` or substitutes another scope.

Before its cleanup-only `chown`, the verifier checks the recording directories,
all sealed manifest files and derived JSON metadata/index fragments against the
host UID/GID passed through `--artifact-owner`. This includes hidden dependency
and Global replay indexes. It does not traverse controller CA or secret
directories; those are outside recording publication. A cleanup command cannot
make the ownership assertion pass retroactively.

The synthetic Redis bodies use explicit base64 encoding. Private interaction
message payloads are left protected; only terminal action/timing metadata is
inspected. Opaque or unsupported dependency encodings fail explicitly rather
than being decrypted or interpreted as plaintext. EOF and reset must retain
their distinct actual typed endings, with no fabricated client CLOSE.

The original engine rejects the first client's WS-close SID removal;
the earlier close-only patch accepts that close but isolates Source on bare EOF.
