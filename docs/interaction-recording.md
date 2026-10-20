# Streaming and Socket.IO recording

Enable `recorder.http_gateway.record_streaming` in project YAML. The existing
recording route rules, API patterns and per-API case limits still apply. Primary
SSE and NDJSON responses are selected by the actual response Content-Type.
An Accept offer such as `application/json, text/event-stream` permits either
response; JSON responses (including errors) and non-stream empty responses retain
ordinary HTTP recording, including their status, headers and body. Protocol
selection never resends the request or sends an already executed POST to fallback.
Response-header waits use
the ordinary HTTP request timeout; established streams use the interaction
lifecycle budgets. When streaming recording is disabled, requests explicitly
offering SSE or NDJSON still use the configured pre-dispatch fallback. Raw
`application/octet-stream` recording additionally requires
`recorder.http_gateway.record_raw_streaming: true`. Binary downloads otherwise
retain ordinary HTTP recording and lifecycle behavior.
Socket.IO uses the `/socket.io` endpoint and validated EIO4 transport parameters.
The external gateway forwards that entire endpoint to Recorder. It does not
inspect business events or select events for routing. `brz-http-router` and Wegent
business services require no changes for capture.

## One connection, one case

Authentication, namespace connection and multiple business exchanges share a case
and its exclusive Source slot. HTTP keep-alive does not group independent HTTP
requests into one case. Pending requests may overlap and complete out of order.
An ACK or configured terminal event completes its matching exchange, then the
connection remains available for another exchange.

The shared defaults under `recorder.http_gateway.interaction` are:

| Setting | Default | Meaning |
| --- | --- | --- |
| `business_idle_ms` | 10000 | Close after business quiet with no pending work |
| `request_timeout_ms` | 120000 | Fail an unfinished exchange |
| `max_duration_ms` | 600000 | Hard limit from admission; reaching it is incomplete |
| `cleanup_timeout_ms` | 60000 | Hard bound for transport close and case finalization |
| `input_gap_ms` | 100 | Maximum replay gap after a proven completion barrier |
| `preserve_input_timing` | false | Preserve original input gaps for time-sensitive behavior |
| `max_message_bytes` | 8388608 | Bound one decoded message |
| `max_messages` | 100000 | Bound observed messages |
| `max_total_bytes` | 67108864 | Bound decoded input/output evidence |

Engine.IO ping/pong, upgrade controls, WebSocket ping/pong and SSE comments do not
extend business idle. A business event named `heartbeat` receives ordinary
business handling. Pending work suppresses the idle-success condition; timeout,
transport errors, partial binary attachments and budget exhaustion cannot pass.

## Completion profiles

Socket.IO requests carrying ACK IDs can use their matching ACK. Requests without
ACKs need an explicit terminal event profile, for example:

```yaml
recorder:
  http_gateway:
    record_streaming: true
    interaction:
      completion:
        - namespace: /
          event: chat
          completion:
            kind: terminal_event
            event: done
            correlation:
              input_pointer: /0/request_id
              output_pointer: /0/request_id
```

Pointers address the event argument array, excluding the event name. A terminal
event without correlation is only usable when a single matching exchange is
pending. `require_ack: true` additionally requires its ACK. Unknown completion or
ambiguous correlation fails capture. These profiles establish case boundaries;
they do not relax output equality or authorize dependency matching exceptions.

Finite HTTP streams complete at EOF. Long-lived streams need an explicit
`stream_terminal` profile (`sse_event`, `text` or `json`) before idle can succeed:

```yaml
interaction:
  stream_terminal:
    kind: sse_event
    event: done
```

Generic WebSocket requires an explicit stream terminal profile and supports one
primary exchange. Ambiguous overlapping generic WebSocket requests fail. Use the
Socket.IO adapter for correlated, concurrent exchanges.

## Evidence and replay

`request.json.interaction` contains a versioned input program and resolved policy.
`expected-response.json.interaction` contains Source output events and closure.
The runner independently writes `actual-response-*.json.interaction`. HTTP method
and route identity preserve existing grouping, `prepare`, `run-api`, `run` and
backend-rewrite orchestration. Semantic dependencies remain in
`dependencies.jsonl`; debug wire data never substitutes for them.

The input driver never reads expected outputs. It opens a fresh Target session,
learns the actual Engine.IO SID, rebinds polling/upgrade requests, and binds ACKs
to actual server event occurrences. Only protocol-owned dynamic IDs are
normalized. Business fields named `sid` remain strict; application identity
mapping requires an explicit supported input/value contract.

SSE events and NDJSON records are framed independently of TCP/HTTP chunking. Raw
stream comparison concatenates observed bytes. Missing, extra or reordered
business outputs fail, and incomplete closure cannot pass even if both bodies
match. Protocol heartbeat schedules may differ.

Only a Source-proven serial input gap can be compressed to `min(gap,100ms)`;
Replay waits for the corresponding **actual Target** completion first. Overlap
timing and dependency response delays remain intact. The final business idle
observation is retained. Old `sse_observation` 50 ms evidence is rejected with a
re-record instruction; immutable recordings are never reinterpreted or rewritten.
Set `preserve_input_timing: true` before recording behavior that depends on input
spacing, such as throttling, scheduled work or application timers. Completion and
network quiet alone do not grant permission to change those clock semantics.

## Closing a case and background work

Normal completion closes that interaction's actual transport and releases its
case after the existing dependency lifecycle. Source and Target remain running
to handle the next case. Each Socket.IO case uses a new logical session; HTTP
stream cases follow request boundaries regardless of HTTP connection reuse. The
10-second business-idle limit governs the primary interaction, not a separate
dependency quiet period.

Engine business-idle closure, client closure and server EOF are distinct observed
end reasons and are compared during Replay. WebSocket close codes and reasons
are compared too. If the client or server closes first, recording retains that
actual origin instead of waiting out business idle and labeling it engine close.

Recording uses `recorder.recording.case_dependency_post_response_window_ms`
(default 100 ms) after transport close. This fixed window accepts disconnect
after-hooks into the same case; new dependencies do not restart it. When it ends,
new dependency attribution closes and the recorder waits for already accepted
in-flight exchanges, using
`recorder.recording.case_dependency_drain_timeout_ms` (default 5000 ms). A streamed
HTTP dependency retains its reservation through body EOF, drop or error. Its
headers alone cannot release the reservation. The interaction's 60-second
`cleanup_timeout_ms` bounds the whole close/finalization path; it adds no normal
wait beyond the configured window and active work. Failure to finish this path
fails the case and closes admission.

Replay uses the existing case `end` lifecycle and
`project.replay.case_dependency_post_response_window_ms` (default 10 ms).
Dependency responses retain their original case and finite delivery state;
streamed responses remain in flight through body completion. Normal case closure
does not terminate Target or require a new run for the remaining selected cases.

Longer detached work uses the existing source-proven process-owned policy.
Ordinary process-owned selectors cover MySQL, Redis, HTTP, Memcached and Motan.
API-origin selectors currently cover MySQL and Redis, with an identity captured
from a proven MySQL INSERT in the triggering HTTP case. Idle matching candidates
are retained as finite Global evidence; active-window exchanges keep their
original case. Replay uses complete origin/identity proof to classify eligible
unused foreign work. Unmatched Target calls, response differences, unsafe traffic
and trigger-owned required dependencies remain failures. This mechanism does not
infer completion of an arbitrary background job or automatically turn Socket.IO
business events into HTTP API origins. See
[API-triggered process traffic](api-triggered-process-traffic.md) and
[unified rule contracts](unified-rule-contracts.md) for policy authoring.

Primary HTTP streams can record a client close after explicit business completion
at a complete logical-message boundary. Replay sends that input cancellation at
the corresponding actual Target completion plus the recorded post-completion
gap, preserving that gap even when it is zero. It independently observes whether
the client, server or engine actually closes first. Cancellation with pending
business or a partial message remains incomplete. Finite server EOF and terminal followed by engine
idle-close are also replayable. Socket.IO/WebSocket client close actions retain
their close code and reason.

HTTP dependency SSE/NDJSON/raw responses are captured incrementally on both the
explicit proxy and fake-DNS transparent HTTP/HTTPS paths. Their semantic records
retain one bounded payload plus timed byte ranges, header time, trailers and EOF.
Replay preserves those delays and holds dependency delivery in flight until body
completion. Incomplete dependency streams and full-body rewrite rules on streams
fail explicitly. Client-cancelled dependency streams require a termination
contract beyond this first complete-EOF adapter.

Redis-coordinated sessions keep the same token-owned reservation through close
and drain. Renewal never recreates a missing token or overwrites another owner.
The engine uses published gateway 0.2.11 and Redis 0.0.16. The gateway SDK owns the
token-checked Redis renewal operation; the engine calls `provider.renew(&ticket)`
at one third of the configured reservation TTL (20 seconds by default) through
case completion and dependency cleanup. The default 60 second reservation TTL
recovers abandoned slots and is independent of the case duration limit. Gateway
changes also retain permits and shutdown ownership for upgraded tunnels.

A new connection that cannot acquire the exclusive recording reservation is
rejected with 503 by the standalone ingress. Existing admitted polling requests
reuse their session reservation. Fixed `/socket.io` routing must be enabled for
the intended recording window and switched off when recording ends; this adapter
does not choose an implicit production fallback or send unowned sessions into the
recording Source.

## Sensitive evidence

Connection query parameters, CONNECT payloads, business messages, cookies and
authentication headers can contain credentials. New interaction input/output
payloads and private connection metadata use authenticated encryption with the
managed project key, alongside private storage and the existing service isolation.
Loaders decrypt a caller-owned view in memory; no plaintext evidence copy is
written. Existing encrypted request-header configuration remains effective.
Missing keys and failed authentication fail closed. Do not publish raw decrypted
transcripts in logs, reports or examples. Payloads are not guessed or redacted
and then treated as replayable originals.

Primary SSE/NDJSON parsing currently requires an uncompressed response. Declared
stream requests negotiate `Accept-Encoding: identity`; a compressed stream
discovered only after dispatch fails explicitly. A declared primary stream that
returns a different or missing stream Content-Type also fails explicitly; an
ordinary JSON response cannot be interpreted as an empty successful SSE stream.
HTTP request streaming uploads,
HTTP/2 bidirectional streaming and cross-request MCP session grouping are outside
this first adapter. Ordinary HTTP body handling is unchanged.
