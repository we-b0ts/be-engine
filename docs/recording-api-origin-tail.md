# API dependency admission and asynchronous completion

Ordinary HTTP headers, frames and trailers return as they arrive. After the complete
primary response, Recorder closes new dependency admission immediately. A request
already admitted retains its original Case through real response/termination I/O
and persistence. The Case slot and publication barrier remain until that drain is
complete. No fixed 100 ms or 5 ms observation interval is used.

```yaml
recording:
  case_dependency_post_response_window_ms: 0
  case_dependency_drain_timeout_ms: 5000
```

The fixed-window setting accepts only zero. The old
`api_origin_dependency_idle_ms` setting is rejected. A process selector or an
API-origin candidate does not extend recording by an idle interval.

An API that continues work after its response declares an explicit completion
resource in the current `traffic-policy/v3` policy:

```yaml
format: traffic-policy/v3
async_api:
  POST /jobs:
    when_response: {/status: queued}
    end:
      - http: {method: POST, endpoint: 'worker.internal:80', path: /finished}
```

Dependencies are collected dynamically; the policy describes the end condition,
not a fixed dependency list. A trustworthy end observed before the response is
latched until the original Source response selects its scenario. The selected
response and successful end jointly close admission under the same lock. Existing
I/O then drains. A failed endpoint attempt remains a real retry observation and
does not falsely complete the job. A transactional MySQL end waits for its real
commit boundary.

`async-api-observation.json` version 2 separates `capture_complete`,
`business_complete`, `business_completion` and `inventory_complete`. A complete
capture of a timed-out stop is diagnostic evidence; it does not prove business
completion. Its immutable native references bind actual observed work. Replay
requires the complete effective finite inventory and real delivery/termination;
it does not submit missing Target calls or repeat a Source idle interval.

The central ledger retains calls that start after a Case closes. Without a proven
owner they enter the unattributed scope, preserving the observed Case context.
Independent Source analysis can assign them to a process task or original API.
Such a decision never manufactures a response or marks an occurrence consumed.
An existing sealed run with a complete proven end and inventory can support a new
async scope; missing work or completion creates a concrete origin capture obligation.

See [dependency attribution](dependency-attribution.md),
[stream dependency tails](recording-stream-dependency-tail.md), and the
[lifecycle design](dependency-lifecycle-design.md).
