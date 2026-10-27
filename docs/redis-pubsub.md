# Redis Pub/Sub recording and replay

Recorder saves confirmed RESP2 `message`, `pmessage`, and `smessage` frames as
`redis_pub_sub_push` events in semantic dependency JSONL. Binary channel/payload
bytes remain intact. Each event identifies its Redis endpoint/session, source
connection, subscription command sequence, and elapsed time. Subscriptions keep
the existing single-subject confirmation contract. RESP3 push mode and
multi-subject subscribe commands remain unsupported.

Uncorrelated notifications are process-owned Global evidence, rather than
dependencies of whichever HTTP case is active at arrival. Replay schedules each
finite notification after its original subscription is matched and confirmed.
Unsubscribe and disconnect prevent later delivery to that subscriber. Different
channels, patterns, shard channels, and source connections remain isolated.
Replay resolves the original successful subscription by source connection and
command sequence, then checks endpoint, database, username, subscription kind,
subject, and confirmation. Missing or inconsistent subscription anchors fail
loading instead of routing a message to an arbitrary connection.

Recorder retains successful complete RESP2 subscription confirmations throughout
the process lifetime, including idle-time reconnects after HTTP readiness. A
bootstrap subscription remains ordinary Global evidence. An idle runtime
subscription uses `global_dependency_reason: pubsub_subscription`. A subscription
captured with HTTP case ownership keeps that original Case exchange and adds an
identical Global copy marked `pubsub_subscription_mirror`; this is evidence of
the same command, not another command to consume.

For loaded Global notifications, Replay resolves missing anchors from the
completed recording's immutable Case indexes without loading unrelated Case
commands or RPC publishers. A selected Case subscription and its Global mirror
share one consumption slot. A Global-referenced subscription can therefore be
matched during target startup without waiting for that Case to become active,
while its original Case attribution and command order remain intact. Consuming
the subscription once does not permit a second SUBSCRIBE from the mirror.
An explicit Global mirror also supplies the exact subscription for a selected
RPC callback when that connection has no unrelated Global notifications.
The mirror is complete evidence even if its original Case was not published.
Legacy cross-Case recovery without a mirror rejects unfulfilled business or
subscription predecessors instead of skipping their connection order.
Failed, truncated, unsupported, ambiguous, or absent confirmations remain errors.
Rebuilding an index cannot reconstruct missing historical subscription evidence;
those recordings need fresh capture after upgrading the Recorder.

Pub/Sub payloads may contain application secrets or user data, like ordinary
Redis values. They are retained exactly in the private recording artifacts; the
engine does not infer redaction or put message payloads in diagnostic reports.

## RPC adapter

The first correlation adapter supports non-binary JSON Socket.IO Redis-adapter
RPC envelopes. It is independent of application routes, event names, channel
names, and command/result schemas. The reusable Redis protocol owns RESP
framing; the adapter owns `method: emit` plus callback identity and
`method: callback` matching. It does not run Socket.IO/Engine.IO connections,
WebSocket transport, application handlers, or device commands.

At PUBLISH admission, Recorder retains attribution metadata and the adapter's
publisher host, SID, namespace, and callback ID. The completed Redis command
releases its dependency reservation without waiting for an application callback.
A matching callback on another subscribed connection keeps the original Case
only while that Case still accepts dependencies. A later callback is Global
evidence with the original publisher Case ID and exact connection/sequence
reference; it cannot reopen that Case or attach to unrelated HTTP work. Idle RPC
publishers are also retained as explicit Global protocol evidence. This does not
collect arbitrary idle PUBLISH traffic. Channel and endpoint must match; Redis
Pub/Sub itself is independent of logical database. Other publishers' callbacks
remain ordinary notifications. Only successfully forwarded pushes become replay
evidence.

New RPC PUBLISH records carry `rpc_callback_capture: bounded_window`. A sealed
observation window may contain no callback: Replay consumes the finite PUBLISH
and its recorded Redis response, without synthesizing an RPC reply or declaring
the application's task complete. Historical records without that marker still
require exactly one captured callback. Missing historical evidence, duplicate or
orphan references, unsafe/truncated payloads, inconsistent identities, and a
publisher from another Case fail loading. Expected HTTP responses never supply
missing ACKs.

When several recorded subscription generations match the same Target command,
Replay prefers exact subscription anchors required by linked RPC callbacks
within the same Case or Global ownership scope. This preference uses captured
protocol evidence and preserves session identity, exclusive connection claims,
lane predecessors, and single consumption. An unrelated earlier or later
subscription stays unused; Replay does not merge generations or redirect a
callback to a different confirmed anchor.

The target must issue its genuine PUBLISH and subscribe calls. Matching retains
the endpoint/session, channel, event, namespace, complete command data and
every non-identity field. Protocol-generated UUID-v4 hex publisher IDs, namespace
session IDs and positive callback counters use bijective bindings. A session
translation applies only to the validated room/callback SID pair in that RPC
envelope; it does not authorize arbitrary room or application-field changes.
The recorded callback result stays unchanged.

Ordinary callback-null adapter broadcasts share the same process host identity
with RPC calls. Their room, namespace, event and business data remain strict;
only a valid UUID-v4 manager host identity is translated.

A recorded `message` containing the exact bytes of a finite Source adapter PUBLISH
is its Redis self-echo. After strict Target PUBLISH admission and delivery of its
Redis response, Replay delivers that admitted Target payload through the exact
confirmed subscription and the original finite notification slot. This preserves
fresh protocol identities and explicitly authorized generated data without waiting
for the recording's pre-request subscription idle time. The slot becomes consumed
only after actual TCP delivery. Its ordinary notification timer cannot duplicate
that delivery. Unmatched application data, missing Source echoes, different
endpoint/channel identities, and duplicate ambiguous echoes
do not authorize new notifications. Each subscription retains its recorded
database and authenticated identity; Redis PUBLISH fan-out remains independent
of the publisher’s logical database. Other Global messages keep their recorded
timing and bytes. Notification indexes retain only digests and locations; the
sparse digest lookups needed by the loaded adapter publishers are prepared from
metadata before Replay publishes readiness. APIs without those publishers skip
this preparation. Each subscription's lookup is shared across the session's
Cases, while payloads are loaded only for selected echoes. Preparation runs on
a blocking worker before Target connections are admitted, so the first PUBLISH
and subsequent commands on its connection do not pay the full inventory scan.
The lookup remains an in-memory session cache; a fresh Replay prepares its own
lookup without reusing notification consumption state. Preparation failures stop
startup, and preparation counts and elapsed time are logged without payloads.

 A Case-owned callback keeps its
publisher pending until it reaches the confirmed subscriber. A late Global
callback has its own finite delivery obligation; its PUBLISH completes when the
recorded Redis response is delivered and is never consumed twice. Subscriber routing is checked at
callback delivery, so a subscription established while an RPC is pending is
valid when it is ready before the recorded ACK deadline. Missing/ambiguous subscribers, queue
failures and disconnects leave required evidence dirty. Case-owned callbacks
cannot escape their active Case. An exact late Global callback may arrive after
its publisher Case has ended; it never completes or dirties a later Case.

Explicit Source-backed request contracts may select generated RPC application
fields, including per-element times and bounded signed-URL query values. They
compose with the protocol identity adapter using comparison copies; original
request evidence, callback bindings and result delivery remain with their
existing owners. See [Generated Redis request values](redis-generated-requests.md).

The adapter accepts JSON RPC envelopes up to 1 MiB. Capture retains at most
4096 correlation records and expires abandoned metadata after 610 seconds;
those records hold no in-flight reservation.
Global notifications use a paged disk index and one ordered scheduler per
confirmed subscription; their recorded message count has no fixed ceiling.
Replay accepts at most 4096 active subscriptions, with a 256-message delivery
queue per connection and a bounded socket write deadline.
Legacy calls without captured ACKs require fresh recording. The new bounded
window marker permits observed absence while retaining the actual Redis response;
absence alone is never a synthesized timeout-response fixture.

## Validation

`cargo test pubsub` and `cargo test recorder::redis` exercise actual TCP Recorder
and Replay connections,
binary notifications, pattern/shard subscriptions, cross-connection RPC results,
identity translation, strict command data, finite consumption, missing-evidence
rejection, cancellation, and request admission ownership. Both eager and lazy
dependency loading use the same evidence contract and disposable index format.
