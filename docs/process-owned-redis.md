# Process-owned Redis GET

A proven independent process read can be classified without turning its value
into a reusable initialization snapshot. Declare exact bounded keys and ports
under the actual Source task, with the policy's root `source_revision`:

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
