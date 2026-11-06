# Streaming and Socket.IO recording

Enable `recorder.http_gateway.record_streaming` in project YAML. The existing
recording route rules, API patterns and per-API case limits still apply. Primary
SSE and NDJSON responses are selected by the actual response Content-Type.
An Accept offer such as `application/json, text/event-stream` permits either
response; JSON responses (including errors) and non-stream empty responses retain
ordinary HTTP recording, including their status, headers and body. Protocol
selection never resends the request or sends an already executed POST to fallback.
The shared `recorder.http_gateway.request_timeout_ms` defaults to 900000 ms
(900 seconds) and controls HTTP response waits and pending streaming exchanges.
Established streams retain the interaction lifecycle's completion and capture
limits. When streaming recording is disabled, requests explicitly
offering SSE or NDJSON still use the configured pre-dispatch fallback. Raw
`application/octet-stream` recording additionally requires
`recorder.http_gateway.record_raw_streaming: true`. Binary downloads otherwise
retain ordinary HTTP recording and lifecycle behavior.
Socket.IO uses the `/socket.io` endpoint and validated EIO4 transport parameters.
The external gateway forwards that entire endpoint to Recorder. It does not
inspect business events or select events for routing. `brz-http-router` and Wegent
business services require no changes for capture.

For WebSocket upgrades, Recorder removes HTTP body framing headers on the
Source hop only after fully reading and confirming an empty request body. This
supports older gateways that add `Content-Length: 0`, which strict WebSocket
servers reject. The original request evidence is retained. Nonempty bodies and
ordinary HTTP requests keep their existing forwarding behavior.

Interaction phase and progress logs identify the case, protocol, pending count,
initial-response wait and next deadline without logging request headers or
message contents. They distinguish an upstream handshake wait from transport
cleanup, dependency drain and case publication.

For Python Uvicorn/Hypercorn Socket.IO peers, Recorder verifies the captured
Engine.IO SID is live before forwarding CLOSE and retains the case until the
native session reports disconnect completion or removal of that same proven
SID. Python Engine.IO deletes the SID after a client WS CLOSE, including 1001,
only after its awaited disconnect handler completes. An initial unknown SID,
another SID, an unrelated HTTP 400 or an automatic WS close echo is insufficient.
Close-confirmation failures report a safe typed outcome at WARN level, without
logging probe URLs, tokens or response bodies. The opt-in
[real Python ASGI regression](../tests/manual/asgi_close/README.md) verifies
client and Engine.IO closes, delayed dependency capture and consecutive cases.

## One connection, one case

Authentication, namespace connection and multiple business exchanges share a case
and its exclusive Source slot. HTTP keep-alive does not group independent HTTP
requests into one case. Pending requests may overlap and complete out of order.
An explicitly configured ACK or terminal event completes its matching exchange,
then the connection remains available for another exchange.

The shared defaults under `recorder.http_gateway.interaction` are:

| Setting | Default | Meaning |
| --- | --- | --- |
| `business_idle_ms` | 10000 | Close after business quiet with no pending work |
| `request_timeout_ms` | 900000 | Resolved from the shared HTTP request timeout; fail an unfinished exchange |
| `max_duration_ms` | 900000 | HTTP stream duration equals the shared timeout; session limits are at least that timeout |
| `cleanup_timeout_ms` | 60000 | Hard bound for transport close and case finalization |
| `input_gap_ms` | 100 | Maximum replay gap after a proven completion barrier |
| `preserve_input_timing` | false | Preserve original input gaps for time-sensitive behavior |
| `max_message_bytes` | 8388608 | Bound one decoded message |
| `max_messages` | 100000 | Bound observed messages |
| `max_total_bytes` | 67108864 | Bound decoded input/output evidence |

Set the shared timeout under `recorder.http_gateway`, rather than setting a
separate streaming request timeout. The runtime resolves the interaction request
budget from that value, including a `record --request-timeout-seconds` override.
HTTP streams use the shared timeout as their absolute duration limit, so the
previous 600-second default cannot truncate a 900-second request. Socket.IO and
WebSocket sessions may retain a longer explicit interaction duration. Resolved
policies are saved in new recordings; Replay retains the explicit budgets and
deadline precedence in historical input programs.

Engine.IO ping/pong, upgrade controls, WebSocket ping/pong and SSE comments do not
extend business idle. A business event named `heartbeat` receives ordinary
business handling. Pending work suppresses the idle-success condition; timeout,
transport errors, partial binary attachments and budget exhaustion cannot pass.
An explicitly observed, valid WebSocket Close from Source ends the captured
session even when business exchanges remain pending. The recording retains those
identities and the peer's close code/reason; it does not manufacture ACKs or
business completion. A bare EOF with pending work is not equivalent to this
observed Close, and incomplete frames or transport/capture errors still fail.
Engine.IO polling also ends at an explicitly received protocol CLOSE packet
(`1`). That packet remains output evidence, with pending exchanges intact and no
invented WebSocket close code or reason. Replay stops polling after the Target's
own CLOSE packet instead of issuing another GET on the terminated session.
For WebSocket transport, an Engine.IO CLOSE packet does not hide a later physical
transport failure or replace the existing physical close-frame observation.

## Completion profiles

Socket.IO requests carrying ACK IDs can declare `completion: {kind: ack}` to use
their matching ACK. Without a completion profile, an ACK alone does not prove
business completion. Requests without ACKs need an explicit terminal event
profile, for example:

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

GET SSE responses without an explicit `stream_terminal` rule are subscriptions.
Their open HTTP connection does not create a pending business request. The
business-idle window starts when response headers arrive, and complete business
events reset it; SSE comment heartbeats do not. A silent or heartbeat-only
subscription closes normally after the default 10 seconds, publishes its bounded
observation and releases the recording slot while Source keeps running. Its end
reason is `business_idle`, not server EOF or proof that future events cannot
arrive. Partial messages still fail capture.

Other HTTP streams, including POST responses and GET responses with an explicit
terminal rule, retain pending response completion. Finite responses complete at
EOF. Long-lived response streams need an explicit `stream_terminal` profile
(`sse_event`, `text` or `json`) before idle can succeed:

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
New GET SSE subscription inputs carry `http_stream_mode: subscription`; replay
uses this recorded mode and independently observes Target business silence.
Inputs without this field retain response-completion semantics, and replay does
not infer a subscription from expected outputs or reinterpret older recordings.
Socket.IO sessions ending in an explicitly observed Source protocol CLOSE or
WebSocket Close carry an optional `socket_io_heartbeat` input program. Its
`responses` bind each
observed client PONG input sequence to the Source PING ordinal and response delay.
Replay waits for the corresponding actual Target PING, preserves the client
response delay and replies using that live PING's payload. An empty response
table deliberately sends no PONGs; missing client replies remain missing, so a
Target can independently reach the same heartbeat timeout. Replay never reads
expected output or its end time to choose or synthesize a Target close.

The input transcript remains version 1. Historical programs and other bounded
sessions without `socket_io_heartbeat` retain the previous automatic Engine.IO
PONG behavior. Older engines reject the new explicit field rather than silently
changing its meaning. WebSocket protocol-level ping/pong and upgrade probes keep
their existing transport handling; this program controls Engine.IO text PONGs.
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

For a remote Socket.IO RPC proven by an original Global Redis notification and
its Case callback, replay also preserves preceding same-session native emits.
It derives that prefix from Source dependency **requests** before the notification,
waits for their exact PUBLISH exchanges to be consumed, and waits for the trusted
live WebSocket driver to observe the corresponding namespace/event occurrences.
The metadata-only observation is bounded and tied to the active request epoch.
Only then may the original remote notification be injected. Elapsed Source time,
a known SID, or a completed PUBLISH alone cannot replace the live event proof.
Recorded client ACK contents and ordinal references remain unchanged; missing
Target events remain failures instead of receiving another event's ACK payload.

When input timing is compressed, independent client requests may have replies
in flight together. Response assertions use the validated original input graph
to pair consecutive non-binary Socket.IO ACKs by exact namespace and request id.
This requires unique original request identities and no completion dependency
between them. Missing, extra, duplicate or unknown replies cannot be paired;
kind, ACK presence, payloads and configured field contracts remain strict.
Pairing never crosses business events or protocol boundaries. Timing-preserving
programs, causally ordered requests and comparisons without original input
provenance retain positional comparison.

SSE events and NDJSON records are framed independently of TCP/HTTP chunking. Raw
stream comparison concatenates observed bytes. Missing, extra or reordered
business outputs fail, and incomplete closure cannot pass even if both bodies
match. Protocol heartbeat schedules may differ.

An observed HTTP client cancellation may interrupt an SSE event or NDJSON record.
The recorder retains complete semantic messages and the exact bounded unfinished
wire suffix in `interaction.end.partial_message`, using binary encoding. This
field is authenticated and encrypted with the other output evidence. It is valid
only with a recorded `client_close` input; pending response identities remain
pending. Replay follows that input's cancellation time and independently captures
Target's suffix. Assertions compare the suffix bytes exactly, so missing or changed
partial output fails. This does not admit a partial message at normal server EOF,
business-idle closure, a transport error, or a capture-budget limit. Existing failed
recordings are immutable and require fresh recording to acquire this evidence.

Only a Source-proven serial input gap can be compressed to `min(gap,100ms)`;
Replay waits for the corresponding **actual Target** completion first. Overlap
timing and dependency response delays remain intact. The final business idle
observation is retained. Old `sse_observation` 50 ms evidence is rejected with a
re-record instruction; immutable recordings are never reinterpreted or rewritten.
Set `preserve_input_timing: true` before recording behavior that depends on input
spacing, such as throttling, scheduled work or application timers. Completion and
network quiet alone do not grant permission to change those clock semantics.

Socket.IO replay timing is independently selectable for existing recordings:

```yaml
project:
  replay:
    socketio_timing: auto # default; use recorded for the original input timeline
```

Managed Replay with `replay_timing: fast` in `regression.yaml` also accelerates
Socket.IO inputs in `auto`, using the same `replay_interval_cap_ms` (default 5 ms).
Business inputs can advance after the original MySQL and Redis requests in
their preceding interval have been admitted on the actual Target Case.
Recorded completion and callback prerequisites still apply. If a preceding
request remains missing, the input is sent at its original offset. Existing
recordings with sufficient request timestamps and native identities can be
reused. Explicit `recorded` and `preserve_input_timing` retain original timing.

New input actions record integer `offset_ms` and `offset_us` from the same
elapsed-time sample. Ordered fast Socket.IO replay uses microseconds to decide
whether a dependency request preceded an input. Legacy actions without
`offset_us` still treat requests in the input's millisecond as ambiguous.
Replay scheduling and output offsets use milliseconds.

For a clean Source business-idle or completed client-close tail, Fast can
shorten the remaining quiet once the actual output and dependency delivery
requirements are met. Fast can also skip a direct WebSocket heartbeat tail
when the last Source Engine.IO PING was unanswered, the clean server close
followed after the declared `pingTimeout`, and no input or dependency activity
remained in the tail. Replay waits for the real Target output frames, matching
native ACK receipts and required dependency deliveries before releasing the connection
without sending a close frame. The actual response reports
`fast_heartbeat_tail_skipped` and still undergoes business comparison and
dependency audit. Use recorded timing to verify Target's own heartbeat timeout
and server close. Other server closures, client cancellation with pending work
and incomplete tail evidence retain their normal closing rules. Dependencies
triggered by the close retain their existing drain.

JWT request rules also select exact fields in namespace CONNECT auth objects,
using the same named signing profile as header or query credentials:

```yaml
api:
  GET /socket.io/:
    request:
      socketio_connect:
        /wework-runtime:
          /token: default
```

The configured original token must verify against the startup signing key before
its NumericDate claims are translated and re-signed. Invalid signatures and
relative expiration failures remain failures. Other namespaces, unselected auth
fields and business frames remain unchanged. Repeated CONNECTs with different
tokens at the same selected field are rejected as ambiguous. Request execution
and private derived-input reconstruction use the same transformation; neither
reads expected responses.

In `auto`, business EVENT/BINARY_EVENT inputs also wait for successful delivery
of individually timed finite Redis responses completed strictly before that input in Source.
This prefix remains a prerequisite after the original deadline, including when
no completion profile makes the gap compressible or another dependency protocol
prevents compression. Later Source dependencies and in-flight handlers do not
become prerequisites. Native client ACKs, Engine.IO heartbeat controls and
independent cancellation stay runnable while a business input waits; the
existing request/session budgets bound a missing prefix.

Source-proven native effects keep their existing timing authority: coalesced
observations/refreshes, APPEND regrouping, read commutation and shared setup
cannot become new hard input predecessors. They still require their native
coverage and final verification; they are not marked delivered or made optional.
Compression uses exact successful native coverage, including fully delivered
Source APPEND pieces. Partial writes cannot authorize a complete Source piece.
Process-owned subscription aliases reuse only their validated real subscription
response, while ordinary business responses retain their Case and epoch.

Idle compression requires an explicit `compressible_gap` with its Source completion time,
actual Target completion of the declared `after` inputs, and delivery of the
finite Redis prefix completed before that input in Source. Redis matching,
reservation and queued native messages do not count as delivery. A PUBLISH
response written to TCP is distinct from its later RPC callback completion.
Dependencies completed after the input, unrelated Global work and already
authorized optional dependencies cannot become prerequisites for that input.
An ambiguous same-millisecond boundary does not authorize compression.

The active request owns one monotonic timeline. Each admitted idle cut shifts
later inputs and already-supported native Redis notifications by the same amount.
Native admission still requires a unique original window, actual namespace
and subscription. Finite external ordinary notifications also support one CONNECT
followed by at most 127 same-namespace, ACK-tracked plain client events. Delivery
waits for the matching actual Target ACK of every input preceding that notification
in Source; later inputs are not prerequisites. These receipts never complete
business work or authorize fast input compression. Terminal-event completion
contracts, reused ACK IDs, unsupported inputs and ambiguous
same-millisecond boundaries retain their original unused slots.
The scheduler continues receiving WS frames and handling heartbeats while waiting.
In the ordinary Auto scheduler, independent transport cancellation keeps its mapped original deadline, even if
an earlier input is blocked; skipped inputs remain incomplete. A completion-bound
close retains its explicit `after` prerequisites and the full interval after actual
completion. Namespace/transport close gaps themselves are not compressed.
A compression-only gap without a delivery grant retains its mapped original
deadline. A business input with an undelivered finite prefix retains its
prerequisites until delivery, cancellation or the existing session deadline.

The first implementation covers Redis response/native delivery. Other dependency
protocols or explicit no-PONG programs disable compression while known Redis
prefixes still gate business inputs. Missing Source clocks, unmanaged execution
without dependency feedback, `preserve_input_timing: true`, or `recorded` mode
retain the original timeline without additional delivery-prefix gates.
Neither mode changes immutable recordings, their policy, lane
matching or dependency assertions, and `regression.yaml` stream timing remains independent.

## Closing a case and background work

Normal completion closes that interaction's actual transport and releases its
case after the existing dependency lifecycle. Source and Target remain running
to handle the next case. Each Socket.IO case uses a new logical session; HTTP
stream cases follow request boundaries regardless of HTTP connection reuse. The
10-second business-idle limit governs the primary interaction, not a separate
dependency quiet period.

An unfinished primary request that reaches its timeout fails the case; that
primary reason takes precedence over dependency errors caused by closing the
stream. A failure that closes global recording admission also wakes the recording
supervisor. The supervisor stops Source, closes retained dependency connections
with explicit engine-cleanup attribution, preserves admitted ownership through
evidence persistence, finalizes the recording and exits with an error when cases
failed. Closed admission cannot leave the recording service indefinitely running
and sending every later request to fallback. Normal EOF and fully observed client
cancellation do not stop the recording service.
An observed Source WebSocket Close likewise ends only its session. Pending
business identities remain assertion evidence while the ordinary dependency
drain and publication complete. A dependency attribution, drain, lease or
persistence failure still requests Source isolation; peer closure does not
override those safeguards.

A diagnosed, fully drained HTTP dependency capture failure after a clean primary
close is local to its case. Recorder preserves that failed evidence and releases
the slot after the ordinary dependency quiet window and successful publication;
the capture owner must also have observed a client connection ending or transport
failure. Unexplained Body drop retains Source isolation. The next request can
record using the same Source after a recoverable failure. Admission closure, lease loss,
primary timeout, incomplete inventory, engine cleanup and persistence failures
still require supervised isolation. A failed case remains failed even when the
service continues; final run reporting retains its failure count and exit status.

HTTP stream capture failures include `recording-error.json.context.http_stream`
with the exchange identity, client/server termination clocks, engine-cleanup
flag, bounded IO error kinds/errno, response byte/chunk counts and prefix-flush
state. Error text, headers and payloads are excluded from this diagnostic. Raw
socket observation under TLS preserves errors that TLS can otherwise translate;
flush failures participate in termination observation. FIN remains a write-half
close, and neither a failed write nor Body drop invents a client reset.

The optional real-client regression runs with
`TRAFFIC_E2E_TEST_PYTHON=/path/to/python-with-httpx cargo test --lib httpx_https_dependency_close -- --ignored`.
It uses loopback TLS and a temporary trusted CA. It requires an independently
observed client termination or an explicit incomplete-capture diagnosis; it never
accepts a synthesized HTTP body EOF for a cancelled dependency.

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
fails the case and closes admission, causing the recording service to shut down.

Replay uses the existing case `end` lifecycle and
`project.replay.case_dependency_post_response_window_ms` (default 10 ms).
Dependency responses retain their original case and finite delivery state;
streamed responses remain in flight through body completion. Normal case closure
does not terminate Target or require a new run for the remaining selected cases.

An observed client EOF or reset at a complete framing boundary with pending
business work uses a separate Case tail window in Recorder and managed Replay.
The primary transport ends at its actual boundary. Case admission stays open
until 15 continuous seconds without relevant dependency activity and without
accepted I/O in flight, with a five-minute observation cap. Real activity
restarts the quiet interval. The cap closes admission, then the usual bounded
drain handles already accepted I/O. A quiet or capped observation alone does
not fail the recorded Case, prove business completion, or waive any dependency
comparison. A transport end after normal business completion uses the ordinary
close path. An incomplete frame or failed transport confirmation retains its
existing failure path.

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

Primary HTTP streams can record a client close at a complete logical-message
boundary, including cancellation while business remains pending. The pending
identities remain independent assertion evidence; cancellation does not fabricate
business completion. Replay preserves the recorded client input timing unless
an explicit terminal profile establishes a completion anchor. With that anchor,
Replay waits for actual Target completion plus the full recorded gap, even when
the gap is zero. Client, server and engine close origins remain distinct. Partial
logical messages and engine-truncated capture remain unsupported. Socket.IO and
WebSocket client close actions retain their close code and reason.
For HTTP/1, TCP FIN alone closes only the request direction: the response may
continue. An actual connection reset establishes cancellation; a pure FIN with
an otherwise silent stream cannot prove that the client stopped receiving.

HTTP dependency SSE/NDJSON/raw responses are captured incrementally on both the
explicit proxy and fake-DNS HTTP/HTTPS paths. Their semantic records retain one
bounded payload plus timed byte ranges, header time and observed termination.
Version 1 still requires complete EOF. Version 2 also supports response prefixes
ending in a peer-origin EOF/reset or client cancellation. Replay preserves the
timing and requires the real Target cancellation for client-origin endings;
exhausting the recorded prefix never supplies a synthetic HTTP EOF. Buffered
rewrites, lost evidence and engine-truncated streams fail explicitly. See the
[shared termination contract](dependency-termination.md).

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

New interaction inputs and outputs are stored without additional payload
encryption. Query parameters, CONNECT payloads, business messages, request bodies,
close reasons and response headers remain readable; binary messages retain
explicit Base64 encoding. Only request headers selected by
`recorder.recording.encrypt_request_headers` use the managed project key,
including headers on Socket.IO WebSocket upgrade actions. Explicit
`redact_headers` settings keep their existing behavior. Private storage and
service isolation remain in effect.

Loaders retain authenticated in-memory decoding for historical encrypted
transcripts without rewriting them. Missing keys and failed authentication
still reject encrypted fields. Logs and ordinary reports retain their bounded
projections instead of copying transcripts. Payloads are not guessed or redacted
and then treated as replayable originals.

Primary SSE/NDJSON parsing currently requires an uncompressed response. Declared
stream requests negotiate `Accept-Encoding: identity`; a compressed stream
discovered only after dispatch fails explicitly. A declared primary stream that
returns a different or missing stream Content-Type also fails explicitly; an
ordinary JSON response cannot be interpreted as an empty successful SSE stream.
HTTP request streaming uploads,
HTTP/2 bidirectional streaming and cross-request MCP session grouping are outside
this first adapter. Ordinary HTTP body handling is unchanged.

Socket.IO Redis-adapter callback correlation does not keep a completed Redis
PUBLISH in flight until the callback arrives. A callback inside the original
Case's admission window retains that Case; a later callback is Global evidence
with its original publisher Case and exact connection/sequence reference. Replay
links it only to that publisher, validates the endpoint/channel/session/envelope,
and consumes the callback once. Newly recorded RPC PUBLISH exchanges carry
`rpc_callback_capture: bounded_window`: a sealed window with no callback replays
only the recorded PUBLISH response and emits no fabricated callback. The marker
is a bounded capture contract, not proof that a callback can never arrive. Legacy
RPC recordings without callback evidence still require fresh recording.

For recognized Python ASGI Socket.IO peers, an independently observed client
TCP EOF/reset at a complete WebSocket and Socket.IO message boundary is a normal
terminal input. Recorder stores a final `transport_end` action with `end: eof`
or `end: reset` and its original monotonic offset; it does not invent a WS CLOSE
or Engine.IO CLOSE. A bounded raw-frame monitor distinguishes complete messages
from truncated headers, payloads and unfinished fragmented messages, including
frames read ahead of the current decoded message. The original pending business
identities remain evidence and are not declared completed.

Recorder proves the exact Source SID live, forwards the actual TCP FIN/RST,
confirms its awaited application disconnect, and drains case-owned dependencies
and evidence writers before publishing or admitting the next case. Replay sends
the same physical FIN/RST at the recorded terminal input time, without waiting
for an unfinished ACK or namespace admission. FIN retains its peer-close barrier;
RST cannot provide a subsequent peer observation and retains the ordinary finite
dependency-tail obligations. Neither transport end certifies business completion.
An unexpected early Target transport loss remains a failed Replay.

A transport end inside an incomplete raw frame remains a failed
`interaction_client_transport_lost` case. When its exact Source teardown and
dependency/writer drain are confirmed, recording can continue after preserving
that failure. Existing failed recordings stay immutable and require recapture
to acquire a proven terminal input; upgrading Replay does not promote them.
Protocol/observation errors, unsupported peers, unconfirmed disconnect, cleanup
timeout, lease loss and failed persistence retain Source isolation. Diagnostics
separate client reads from input observation and record bounded transport error
categories without frame contents, URLs, SIDs or private error text.
