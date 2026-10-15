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

At PUBLISH admission, Recorder retains the original case reservation and the
adapter's publisher host, SID, namespace, and callback ID. A matching callback
on another subscribed connection carries a reference to that exact PUBLISH and
keeps its case ownership even when unrelated HTTP work starts. Channel and
endpoint must match; Redis Pub/Sub itself is independent of logical database.
Other publishers' callbacks remain ordinary notifications. Only successfully
forwarded pushes become replay evidence.

Replay requires exactly one complete callback for a successful recorded RPC
PUBLISH. Missing, duplicate, orphan, unsafe, truncated, or inconsistent callback
evidence fails loading. Historical recordings that did not retain callbacks
must be refreshed; expected HTTP responses never supply missing ACKs.

The target must issue its genuine PUBLISH and subscribe calls. Matching retains
the endpoint/session, channel, event, room, namespace, complete command data and
every non-identity field. Only protocol-generated UUID-v4 hex publisher IDs and
positive callback counters are translated, with session-wide bijective bindings.
The recorded callback result stays unchanged. A call is consumed only after its
callback reaches the confirmed subscriber. Subscriber routing is checked at
callback delivery, so a subscription established while an RPC is pending is
valid when it is ready before the recorded ACK deadline. Missing/ambiguous subscribers, queue
failures, disconnects, or case changes leave required evidence dirty.

The adapter accepts JSON RPC envelopes up to 1 MiB. Capture retains at most
4096 outstanding calls and expires abandoned reservations after 610 seconds.
Global notifications use a paged disk index and one ordered scheduler per
confirmed subscription; their recorded message count has no fixed ceiling.
Replay accepts at most 4096 active subscriptions, with a 256-message delivery
queue per connection and a bounded socket write deadline.
Calls without captured ACKs (including source RPC timeouts) require new complete
evidence; absence alone is not a timeout-response fixture.

## Validation

`cargo test pubsub` and `cargo test recorder::redis` exercise actual TCP Recorder
and Replay connections,
binary notifications, pattern/shard subscriptions, cross-connection RPC results,
identity translation, strict command data, finite consumption, missing-evidence
rejection, cancellation, and request admission ownership. Both eager and lazy
dependency loading use the same evidence contract and disposable index format.
