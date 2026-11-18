# Dependency protocol message lifecycle

This first stage extracts protocol responsibilities and validates the shared
contracts with an independent fixture provider. Redis Pub/Sub recording and
serving remain unavailable in the installed native provider. Its integration is
a separate second stage, intended to change only `traffic-protocol-redis`.

Dependency providers own native framing, handshakes, session state, correlation,
stored payload decoding and value selectors. Recording and Replay hosts own
capture identities, ownership, immutable storage, finite Source consumption,
sequence scheduling, cancellation and actual output receipts.

`RecordedExchange::input` distinguishes a real Target request from a
Source-initiated emission. An emission names an opaque native reference to an
earlier successful delivery and its recorded offset from that receipt. It has an output message and no
request message. Evidence projections likewise allow an absent request.

Recording starts each emission with `CaptureHost::begin_message`. The ledger
persists `message_started`, independently of `capture_started` for requests.
Each message retains its own attribution reservation only through actual output
and persistence. An idle subscription retains native session state, not an
unfinished startup or Case capture reservation.

Protocols can retain a successful response delivery as an emission anchor.
`RequestHost::next_message` accepts only anchors with successful receipts on the
same physical connection. It selects within the current Case or executable run
scope and, when an event journal is present, only the current Source message.
Messages participate in the same finite claims, reports and cleanup as replies.
Failed or dropped delivery never consumes a message.

`ResponseDelivery::ready` waits for Source output admission without borrowing the
socket writer. Native full-duplex sessions can continue reading and admitting
commands while earlier replies await a notification. `write` retains the actual
write/flush boundary and commits value-policy results only after real delivery.
Recorded time waits observe owner cancellation.

Stateful providers can use `execute_bound` to acquire an exclusive opaque Source
lane and continue it using a retained delivery reference. Source lane leases
prevent one native session from consuming another physical connection's state.
Protocols release the binding when their session state permits; connection exit
also releases it. Ordinary pooled request execution retains its existing path.

Providers project compact evidence, lookup identities, endpoints and notification
lane metadata through the evidence registry. Shared index builders retain only
locations, digests, paging, open native index names and opaque metadata. Provider
revisions participate in Global index reuse. Derived formats invalidate older
indexes and rebuild without changing original recordings. Source support checks
use authenticated original records rather than compact metadata.
Read-only historical index adapters are fallbacks: they cannot reserve native
execution event names or prevent a real provider from being installed later.

Requests, replies and emissions all use `ProtocolMessage` projections and the
same installed codecs and policies. Only native selectors and encoding belong
to the protocol. The fixture provider independently exercises a startup listener,
Case messages, a notification between request admission and reply delivery,
eager/lazy loading, shared identity policy and strict finite receipts.

The HTTP provider owns its upstream connector, connection observations, flush
boundaries and streaming capture. The recording binding supplies ownership,
invalidation and publication. MySQL owns SQL lookup summaries and native session
continuity analysis; shared adapters retain authenticated files and cache
publication. MySQL CLIENT_SSL and the recording-only upstream certificate policy
remain native responsibilities; HTTPS upstream trust remains strict.
