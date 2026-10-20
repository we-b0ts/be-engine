# Primary stream dependency tails

A primary HTTP stream can finish at the gateway while Source is still using a
dependency. This includes normal EOF and a client cancelling a partial stream.
Both are observable business outcomes. Ending the primary transport does not
prove that its dependencies have completed.

Recorder starts tracking semantic dependency requests at case admission, before
response headers can declare SSE, NDJSON or a raw stream. Adopting a primary
stream enables a tail with `recording.api_origin_dependency_idle_ms` (60 seconds
by default) and the primary request's original absolute budget. HTTP streams,
MySQL queries and Redis commands remain in flight until their real terminal
observation. A pending request with no data is still in flight. Idle starts no
earlier than primary transport completion. Setting idle to zero removes only
the quiet interval, not ownership of unfinished requests.

Primary frames return immediately. The case slot, dependency attribution and
publication barrier remain with the original case while its tail is observed.
Pooled connection lifetime, writer copies and flushes do not renew business
activity. Known process-owned traffic and unassociated Pub/Sub notifications do
not prolong the tail. Unknown traffic retains its conservative case attribution;
an absent process rule does not make complete observations a recording failure.
The idle interval is an observation boundary, not proof that no later job can
ever run. Source-proven origin rules remain necessary for stronger attribution.

After quiet, Recorder closes dependency admission atomically and waits for
evidence persistence. `case_dependency_drain_timeout_ms` is the writer cleanup
budget for these streams; it is not a deadline for business I/O. At the absolute
observation limit, Recorder quarantines admission and marks the observation
incomplete. Already admitted requests and the original case remain alive until
their evidence is recorded. Writer overruns also retain ownership until drained.
Neither condition stops Source or resets dependency sockets to obtain an ending.
An indefinitely pending dependency can therefore keep the case quarantined until
operator shutdown. API case-count quotas retain their normal completion meaning.

`dependency-tail-observation.json` version 1 stores the budget, idle interval,
outcome, completeness and finite completed dependency references. HTTP uses the
original exchange UUID; MySQL and Redis use connection UUID plus sequence.
No request or response payload is copied into this inventory. Existing recordings
and their older API-origin metadata are unchanged.

Replay actively reproduces the main client's recorded cancellation using the
existing input driver. It keeps Target, dependency mocks and case identity alive
until recorded finite dependency obligations are consumed, including streaming
delivery and real Target client termination. It uses the long absolute budget
instead of the short interaction cleanup budget for these obligations. It does
not repeat the recording idle interval or submit missing Target calls. A
dependency's recorded server close is simulated by its mock; a recorded client
close must come from Target. Missing calls or incorrect termination remain dirty.
Only explicit independent process ownership proof can waive a process dependency obligation;
waiving does not consume an exchange or complete an in-flight delivery.
API-origin report reclassification permissions do not waive finite consumption.
