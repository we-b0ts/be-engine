# Process-owned Redis

## Finite GET and initialization

A proven independent process read can be classified without turning its value
into a reusable initialization snapshot. Declare exact bounded keys and ports
under the actual Source task. Task declarations do not bind to a Source version:

```yaml
process_dependencies:
  tasks:
    actual_source_monitor:
      requests:
        - redis:
            ports: [6379]
            operation: GET
            keys: [{kind: exact, value: monitor_state}]
```

Omitting `initial_load_timeout_ms` selects finite GET behavior. Recorder forwards
each read and preserves each original response, including changing values.
Replay consumes each exchange once; an extra read remains unmatched. Complete
original single-use recordings can be reclassified without changing JSONL or
requiring recapture. Snapshot seeds and diagnostic hits cannot be converted into
finite evidence. In old Case recordings, authorized GETs stop imposing pooled
connection order on unrelated work, while retaining their Case attribution and
finite consumption. Stateful sessions and unfinished exchanges keep their
original constraints.

A positive `initial_load_timeout_ms` retains the existing GET initialization
contract: observe exact keys after readiness, capture the first successful value
as a reusable run-local snapshot, and require fresh recording when its acquisition
permission changes. Zero is invalid. Other process-owned Redis commands retain
their existing contracts.

The task name groups an authorized selector; it is not captured caller identity.
Source proof must establish process ownership for every selected occurrence in
the complete recording, including sibling APIs and Global evidence. When both a
monitor and a request path can issue the same GET/key, task names, timing,
neighbouring SQL and unused inventory cannot establish which path issued it.
Keep attribution unresolved until independent evidence disambiguates it; neither
finite GET mode nor snapshot mode supplies that missing proof.

## Finite PUBLISH

A Source-proven process publisher can declare exact channels in `keys` and
select an independent message on a shared channel using JSON conditions:

```yaml
process_dependencies:
  tasks:
    socketio-ack-probe:
      requests:
        - redis:
            ports: [6379]
            operation: PUBLISH
            keys: [{kind: exact, value: socketio}]
            when_message:
              /method: {equals: callback}
              /sid: {prefix: 'wegent-ack-probe:'}
```

Use the actual Source task name, recorded service port, and channel. Conditions
are conjunctive. `equals` compares a literal JSON value at a concrete JSON
pointer and `prefix` matches the start of a string at that pointer. Omit
`when_message` when independent Source proof covers the entire selected
channel. A complete successful Redis integer reply is required, including
zero subscribers. This declaration leaves the original request and reply
available for one Replay consumption. Incoming notifications have their own
scope and subscription evidence.

For an existing sealed recording, publish the ownership rule through Source
attribution planning, then bind the exact occurrences with the independent
Source proof. This preserves the recording and requires no acquisition refresh.
