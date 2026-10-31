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
that signal. The original engine rejects the first client's WS-close SID removal;
the earlier close-only patch accepts that close but isolates Source on bare EOF.
