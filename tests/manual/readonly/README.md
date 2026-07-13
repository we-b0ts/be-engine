# Readonly Manual Verification

This manual system test covers an HTTP gateway `GET` whose application
upstream issues dependency `GET` and `POST` requests through the recorder's
explicit HTTP proxy. The dependency `POST` must receive `403`, never reach its
upstream, and invalidate the active gateway case.

The automated Rust equivalent is:

```bash
cargo test --test readonly_case_integration
```

## Local two-process topology

The checked-in `config/recorder.readonly.toml` uses this topology by default:

```text
gateway :18084 -> app mock 127.0.0.1:18085
app mock -> recorder proxy 127.0.0.1:18081
recorder proxy -> dependency mock 127.0.0.1:18086
```

Start the dependency mock:

```bash
cd /home/ubuntu/workspace/traffic-recorder-proxy
rm -f /tmp/readonly-dependency-events.jsonl
python3 tests/manual/readonly/readonly_mock.py \
  --role dependency \
  --listen 127.0.0.1:18086 \
  --event-log /tmp/readonly-dependency-events.jsonl
```

Start the application mock in a second terminal:

```bash
cd /home/ubuntu/workspace/traffic-recorder-proxy
rm -f /tmp/readonly-app-events.jsonl
python3 tests/manual/readonly/readonly_mock.py \
  --role app \
  --listen 127.0.0.1:18085 \
  --dependency-base http://127.0.0.1:18086 \
  --proxy http://127.0.0.1:18081 \
  --event-log /tmp/readonly-app-events.jsonl
```

Start the recorder in a third terminal:

```bash
cd /home/ubuntu/workspace/traffic-recorder-proxy
cargo run -- --config config/recorder.readonly.toml
```

Wait for gateway readiness, then trigger the matched scenario:

```bash
curl -sS http://127.0.0.1:18084/scenario/readonly | jq .
```

The response must report dependency GET `200`, dependency POST `403`, and
`case_published: false`.

## Verify evidence

The dependency upstream must receive GET and no POST:

```bash
rg '"path": "/dependency/read' /tmp/readonly-dependency-events.jsonl
if rg '"path": "/dependency/write"' /tmp/readonly-dependency-events.jsonl; then
  echo "FAIL: blocked POST reached the dependency upstream"
else
  echo "PASS: blocked POST did not reach the dependency upstream"
fi
```

Select the newest failed case:

```bash
RUN_DIR="$(ls -1dt recordings/readonly-manual/*/ | head -n 1)"
FAILED_REQUEST="$(rg -l '"uri": "/scenario/readonly"' "$RUN_DIR/failed" \
  -g request.json.invalid | head -n 1)"
FAILED_CASE_DIR="$(dirname "$FAILED_REQUEST")"
printf 'run: %s\nfailed case: %s\n' "$RUN_DIR" "$FAILED_CASE_DIR"
```

The dependency GET and the payload-free POST rejection must be retained, but
the POST must not appear as a forwarded `http_exchange`:

```bash
rg '"event_type":"http_exchange".*"method":"GET".*dependency/read' \
  "$FAILED_CASE_DIR/dependencies.jsonl"
rg '"event_type":"readonly_rejection".*"operation":"POST".*dependency/write' \
  "$FAILED_CASE_DIR/dependencies.jsonl"
if rg '"event_type":"http_exchange".*"method":"POST".*dependency/write' \
  "$FAILED_CASE_DIR/dependencies.jsonl"; then
  echo "FAIL: rejected POST was recorded as a forwarded exchange"
else
  echo "PASS: rejected POST exists only as rejection metadata"
fi
```

The normal published case directory must remain empty:

```bash
if [ -d "$RUN_DIR/readonly-manual" ] && \
   rg -l '"uri": "/scenario/readonly"' "$RUN_DIR/readonly-manual" \
     -g request.json; then
  echo "FAIL: readonly-violating case was published"
else
  echo "PASS: readonly-violating case was not published"
fi
```

Stopping the recorder returns a non-zero exit because this scenario
intentionally creates a failed case.

## Optional cross-machine topology

The same checked-in script can run on another machine:

```bash
python3 tests/manual/readonly/readonly_mock.py \
  --role dependency \
  --listen 0.0.0.0:18085 \
  --event-log /tmp/readonly-dependency-events.jsonl
```

Point the local app mock's `--dependency-base` at that machine, for example
`http://10.37.254.56:18085`. The matched readonly scenario does not require the
gateway fallback to use the same target.
