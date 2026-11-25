# Dependency Diagnosis

Start at the attempt's expected Source sequence and any retained Target
observation. Run the bounded `events` query and correlate admission, output,
and termination using `dependency_sequence`. Pass the admission sequence to
`dependency` for the protected Source request and result. If the failure
supplies a Target observation, use `target` with that attempt's report. See
[Source Session evidence commands](session-regression.md#diagnose-the-first-failure).

Check endpoint, complete request, and protocol session. Trace Source and
Target through the caller, including startup, detached work, and shutdown.
A compatible early request can wait for the shared timeline to reach it.
If the expected dependency never arrives, trace the preceding primary input,
dependency delivery, or application condition that enables it.

For a suspected capture omission, verify the exact Source endpoint and call
site. Inspect the relevant startup, ingress, or teardown events and query
available dependency records. Trace equivalent endpoints and legitimate cache
paths before concluding that a capture is missing. Return the endpoint, Source
reference, relevant sequences, and what evidence a fresh recording needs. If
the required record exists and Replay lacks support, report that specific
capability gap to the coordinator.

## Redis

Compare each recorded application command at its admission sequence. Check the
command, full arguments, preceding trigger, and corresponding reply or push at
its recorded delivery boundary. Each business command has a finite occurrence
on the timeline. Trace generated times, IDs, or tokens through Source and
Target with [rule diagnosis](api-implementer-rule-diagnosis.md).

Preserve production client and pooling behavior. Distinguish canonical Redis
connection maintenance handled by the protocol adapter from business commands.
Check endpoint, database, authentication identity, and RESP version. Retain
transaction and subscription continuity. Correlate a push with its recorded
subscription and output sequence.

## MySQL

Use the recorded SQL, bound values, connection ID, query sequence, and server
status before and after each statement. Trace proven transactions and their
required statements and terminal events. Ordinary reads in a proven read-only
span can use autocommit. Ordinary reads before the first write can also run
before Target starts its transaction. The first write anchors the remaining
statements and the recorded end to one Target connection. Locks, savepoints,
and explicit snapshot semantics retain their transaction constraints.

A proven standalone successful `UPDATE` followed by `COMMIT` can match one
autocommit `UPDATE`. Its successful delivery covers the sealed commit slot.
An explicitly started Target transaction still has to issue the recorded
commit. A write followed by `ROLLBACK` keeps its transactional end.

Replay supports compatible text and prepared SQL. Preserve real bindings,
types, NULL, duplicates, tables, ordering, and pagination. Supported
single-table comparisons can match harmless reordered pure predicates or
membership lists. Preserve boolean nesting and whole-tuple value pairing.
Check the semantic request when a preview omits later clauses. After COMMIT
or ROLLBACK, a Source ORM can issue another SELECT through attribute access,
refresh, or lazy loading. Verify the caller in Source code.

The adapter can exclude a proven SQLAlchemy/PyMySQL connection prelude,
transaction controls with no independent effect, or specific idle cleanup.
These exclusions use captured wire order, session
identity, and transaction status and appear as `session_dependency_exclusions`
in the Replay report. Ordinary application reads remain required even when
they repeat the same result. Preserve normal production driver behavior and
proven business transaction boundaries.

The recorder seals these decisions in `session-schedule.jsonl`. Use a fresh
recording to run with updated semantics when an earlier capture sealed
different decisions.

## Outbound HTTP

Use method, authority, path, query, bound headers, body, and completion from the
same exchange. Follow any dependency response headers, parts, trailers, or
terminal outcome that affect the expected next event. For a URL returned by a
dependency, trace the Source producer and the caller that consumes it. Preserve
connection and error handling, plus response framing where it affects the
application.
