# Primary stream dependency tails

A primary stream returning EOF or a supported client cancellation does not finish
already-started dependency I/O. Recorder admits dependencies at request start and
retains their original identities through real completion, peer termination or an
explicit capture failure. Response frames continue to reach the primary client
without waiting for publication.

An ordinary stream closes new dependency admission at its primary completion,
with no quiet window. Work expected to start later needs an explicit
[async completion contract](recording-api-origin-tail.md). The Case slot remains
until admitted work and persistence drain; an idle pool connection, callback
identity or writer clone is not evidence of active business work.

Run reservations cover startup, process, Case and unattributed traffic independently
of Case ownership. Stopping recording closes producers, observes process/socket
termination, drains admitted requests and writers, and seals the central manifest.
A cleanup budget cannot certify a successful business end or erase an incomplete
request. Unsupported opaque TCP/UDP data and capture gaps remain explicit debt.

The reference-only dependency inventory and central capture facts retain exact
HTTP exchange IDs and native connection/sequence/effect identities. Replay waits
for those finite obligations, including actual streaming delivery and required
Target client termination. A recorded server close is reproduced by the mock;
a recorded client close must come from Target. A request merely selected by the
matcher is not consumed. Ordinary HTTP responses also wait for real flush evidence
before completing consumption.

Ownership proof can transfer a foreign unused obligation to its real owner; it
cannot complete active I/O or remove the obligation from the whole batch. API
acceptance and one actual full-session reconciliation remain separate results.
Historical idle/API-origin recording semantics are unsupported.
