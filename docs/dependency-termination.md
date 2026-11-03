# Dependency termination recording and replay

Dependency failures and cancellations are observable business traffic. A call
can have no response, or only a response prefix, while its recording is complete.
Business completion, transport termination and capture integrity are separate
facts. Recorder shutdown, parse loss, capture limits and unsupported framing do
not establish a peer-origin termination.

## Shared contract

Existing `response`, `client_terminated` and `no_response` outcome strings retain
their meaning and serialization. New observations use a structured outcome:

```json
{
  "outcome": {
    "terminated": {
      "side": "server",
      "kind": "reset",
      "scope": "connection"
    }
  },
  "duration_ms": 123
}
```

`side` identifies the dependency client (Source while recording, Target during
Replay) or dependency server. `kind` and `scope` distinguish write-half EOF,
connection reset and protocol-local stream cancellation. A read EOF proves only
that the peer stopped writing. It does not prove the peer stopped reading.
The captured side is the first side observed by Recorder, not a reconstruction
of unobserved kernel or remote scheduling.

`duration_ms` is request-relative monotonic time at the observed termination.
It must not include time subsequently spent waiting for another forwarding task,
draining dependencies or writing evidence. Already delivered response prefixes
remain part of the exchange, with their protocol-supported timing and identity.

`dependency/termination` owns transport observation and explicit FIN/RST control.
Recorder's connection registry marks engine-owned cleanup before touching
sockets, including sockets wrapped by TLS. Such cleanup cannot turn an unfinished
exchange into a successful peer cancellation, even if a write-half EOF was
observed earlier.

## Recording transparency

Forward EOF and reset promptly in the observed direction. Independent forwarding
tasks or a shared output queue must not delay that propagation until Source
reaches its own timeout. Flush preceding forwarded bytes in order. A client
write-half close must still allow a server response to reach that client.

Redis's ordered response writer can receive server EOF after the client has
already reset its response direction. A close operation returning `NotConnected`
then means the socket is already closed, rather than a new capture failure.
This applies only to explicit socket close control, not response writes, and
does not establish a peer termination. Pending exchanges still require their
independently observed end and supported response-prefix evidence.

TCP reset must remain distinguishable from orderly EOF. The Linux transport
control disconnects the socket with `AF_UNSPEC`; this reaches the peer even while
split IO, TLS wrappers or recovery registration retain duplicated descriptors.
Setting `SO_LINGER` alone is insufficient while those descriptors remain alive.

Protocol adapters retain parsing, request/response correlation, pipeline and
session ownership. They decide which pending exchanges a connection event
affects and whether recorded response prefixes can be faithfully delivered.
Unsupported partial frames remain explicit failures rather than synthesized
complete responses. MySQL TLS recording and Replay retain their existing trust
boundaries; HTTPS verification remains strict.

Where a decoder consumes part of an invalid frame, a bounded raw-input capture
preserves those bytes for transparent forwarding before the actual peer FIN/RST.
That forwarding does not make the semantic recording safe. A parse error without
a peer termination continues in raw forwarding mode rather than inventing EOF.

The current native adapters fail closed for multiple unfinished exchanges sharing
a termination unless they can match the whole affected batch. Redis supports
matching such server-terminated pipeline batches. Native multi-stage half-close
sequences that deliver a partial response after the first write-half EOF require
additional event evidence and remain explicitly unsupported. Missing response
prefix timing never authorizes delivery at a guessed time.

## Replay roles

For server-origin termination, Replay delivers the recorded response prefix and
performs the recorded server action at the request-relative deadline. For
client-origin termination, Replay delivers any recorded prefix, keeps the
response open and waits for Target's own EOF/reset/cancellation. Sending an EOF
because the recorded prefix has run out would manufacture Target's behavior.

Only an observed matching termination consumes a client-terminated exchange.
Missing, early, late, differently scoped or otherwise inconsistent termination
is dirty. Verification failure is recorded before supervisor-owned resource
cleanup; a watchdog cannot close the socket and count that closure as Target's
action. Ordinary successful connection-pool lifetimes remain implementation
details; required termination applies to the affected incomplete exchanges.

## Primary HTTP streams

An external client's cancellation is an input action to the primary request.
It is distinct from Source cancelling an outgoing HTTP dependency, which Target
must independently reproduce. A primary stream can retain pending business work
and still have complete cancellation evidence. Captured pending work remains in
the independent output observation for assertion.

Without an explicit business event anchor, Replay preserves the recorded client
input timing. An explicitly configured terminal profile can instead bind the
client action to actual Target completion plus the recorded gap. Temporal
proximity alone does not establish that an arbitrary output caused cancellation.
`response.completed` is not a generic SSE protocol terminal marker.

HTTP/1 write-half EOF leaves the response direction active. A peer's TCP FIN
alone cannot distinguish closing its whole socket from shutting down only its
write half, so it does not prove response cancellation. Recorder requires an
observed connection reset or supported protocol cancellation for that claim.
A pure FIN followed by a silent response remains unproven; engine cleanup cannot
complete its cancellation evidence.

HTTP response-stream version 1 continues to require complete EOF. Version 2 can
also retain a client-reset response prefix and its observed termination;
its end does not cause Replay to emit an artificial HTTP EOF. HTTP/2 stream-local
cancellation requires an appropriate protocol adapter rather than closing every
stream on the TCP connection.

The HTTP/1 adapter buffers a complete request and models one incomplete exchange
per connection. It does not model a sequence of new pipelined requests already
buffered by Hyper behind an incomplete response. These cases require additional
HTTP parser and event-sequence support; the shared transport contract alone does
not supply that support.

## Historical evidence

Recordings remain immutable. Older unsafe or failed recordings cannot acquire
missing side, mechanism or termination-time evidence by reclassification or by
setting `replay_safe`. Re-record affected scenarios after correcting Recorder.
In particular, a duration measured after a forwarding deadlock cannot establish
the original upstream failure time.
