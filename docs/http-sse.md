# Bounded primary HTTP SSE recording and replay

`recorder.http_gateway.record_streaming` controls request admission for both
ordinary and online recording. It defaults to `false`, bypassing requests
declaring SSE before any case is created or Source request is dispatched.
The setting can be made explicit in project YAML:

```yaml
recorder:
  http_gateway:
    record_streaming: false
```

With `false`, any `Accept` field containing a `text/event-stream` media range
uses the configured fallback. Matching is case-insensitive and checks all
repeated fields and comma-separated ranges, including parameters and `q=0`;
this is conservative selection, not content negotiation. Mixed
`application/json, text/event-stream` requests also bypass recording, including
MCP initialization POSTs. No response headers or request JSON are needed for
this decision. Requests without an explicit SSE media range keep their existing
behavior; `*/*` alone does not trigger the bypass.

`fixed_response` returns the configured status, headers and body; a configured
404 lets the upstream recording gateway retry its original Python path.
`upstream` forwards to `fallback_upstream`. Bypassed requests do not occupy a
case slot or count toward API case limits. Enabling the switch retains the
bounded observation below; it does not enable long-lived stream forwarding.

For admitted recording requests, the HTTP gateway recognizes `Content-Type: text/event-stream`
(case-insensitive, with optional parameters). After receiving the upstream
response headers, it observes the response body for **50 ms**. It collects all
body bytes received in that window up to `recording.max_body_bytes`.

If the server completes the HTTP response within the window, the observation
ends with `server_eof`. Otherwise the engine cancels the upstream response at
the deadline and records `observation_window_elapsed`. This engine cancellation
does not count as the server completing the response. EOF here describes HTTP
response completion, including the terminal chunk or content-length boundary;
it does not require closing a keep-alive TCP connection.

The gateway buffers the observed bytes, persists and finalizes the case using
its usual dependency drain, and returns a finite HTTP response to the caller.
The total request time includes header acquisition and case finalization, so it
can exceed 50 ms. Header acquisition retains the configured request timeout.
Ordinary HTTP response bodies retain their full-body request timeout.
Unmatched fallback requests retain their existing full-body forwarding behavior.

The request artifact stores the independent execution policy:

```json
"sse_observation": {"window_ms": 50}
```

The expected and actual response artifacts store the observation:

```json
"sse_observation": {"window_ms": 50, "end": "observation_window_elapsed"}
```

`run-api` and `run` execute this policy from `request.json` and observe the
target for the same 50 ms after its headers. Execution does not read the
expected response. Response assertions compare status, standard headers and
captured body as usual, and independently compare SSE observation metadata.
Equal empty bodies do not suppress an end-behavior mismatch.

When Source remains open but Target completes early, the response assertion
fails with:

```json
{"pointer": "$sse_observation/end", "kind": "sse_stream_end_mismatch"}
```

The runner's `diagnosis.response_differences.failure_clusters` contains this
difference. `diagnosis.representative.expected.value` and `actual.value` show
`observation_window_elapsed` and `server_eof`. The response verification gate is
`nonpassing`; dependency `dirty` remains a separate result. Missing observation
metadata or different window sizes fail as `sse_observation_mismatch`.

This is a bounded recording contract for primary SSE responses, including
the standalone online recorder. The captured body may be an SSE event prefix;
it is compared as bytes without parsing events or normalizing heartbeats.
Data and server termination after the observation window are outside this
contract. A malformed/incomplete HTTP body, a read error or a body-limit
violation is an acquisition failure, not successful deadline completion.

Long-lived streaming to clients, HTTP dependency SSE, WebSocket/Socket.IO,
multi-request MCP sessions and `record-comparison` SSE acquisition are outside
this initial support. Existing cases without request execution metadata keep
their ordinary HTTP behavior and need re-recording to use bounded SSE replay.
