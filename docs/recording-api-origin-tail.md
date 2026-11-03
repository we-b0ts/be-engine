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

The ordinary-response fixed-window setting accepts only zero. The old
`api_origin_dependency_idle_ms` setting is rejected. Async ending uses the
scenario contract below, without a configurable post-response window.

An API that continues work after its response declares an explicit completion
resource in the current `traffic-policy/v3` policy:

```yaml
format: traffic-policy/v3
recording:
  async_api:
    POST /jobs:
      when_response: {/status: queued}
      end:
        - http: {method: POST, endpoint: 'worker.internal:80', path: /finished}
```

Dependencies are collected dynamically; the policy describes end conditions,
not a fixed dependency list. Any successful end observed before the response is
latched until the original Source response selects its scenario. Once every end
has matched, the selected response and matches jointly close admission under the
same lock, without a silence interval; one end follows this same rule.
While some alternative ends remain unmatched, each fresh match permits a fixed one-second probe
while keeping admission open. A subsequent relevant request start cancels closure
eligibility until another fresh end matches; matching the final outstanding end
closes immediately. Another one-second silence alone
cannot close the Case. A completed probe closes only with no relevant request in flight. Closing
admission and rechecking request starts are atomic. Already admitted I/O and
writers then drain. Unambiguously process-owned requests do not cancel the probe;
unknown ownership cannot be ignored merely because it may later prove background
work. Waiting for the first or next end after the complete primary response has
no absolute deadline. If no fresh end arrives, five continuous minutes of relevant
business I/O silence and no relevant request in flight close the Case normally,
retaining an unobserved business-completion fact. Real business activity restarts
that interval; writer queues and definite process traffic do not. The interval
cannot start before the primary response completes. Source stays running and the
fallback is not a timeout failure. The primary HTTP transport timeout remains separate; explicit shutdown
or actual capture failure can interrupt observation. No
`post_window_ms` or per-rule timeout is authored.

A failed endpoint attempt remains a real retry observation and does not falsely
satisfy an end. A transactional MySQL end waits for its real commit boundary.
Redis response conditions can require native nil with
`when_response: {kind: nil}`; the default `any` still requires a complete successful
reply. PUBLISH `when_message` conditions inspect its request JSON independently.

`async-api-observation.json` version 2 separates `capture_complete`,
`business_complete`, `business_completion` and `inventory_complete`. A complete
capture of a timed-out stop is diagnostic evidence; it does not prove business
completion. Its immutable native references bind actual observed work. Replay
requires the complete effective finite inventory and real delivery/termination;
it does not submit missing Target calls or repeat a Source idle interval. Ending
metadata records a completed multiple-end probe without asserting that all
detached business work completed. A five-minute idle fallback records
`end_reason: idle`, `idle_completion: {quiet_ms: 300000}`, and unobserved business
completion. It keeps Source running and preserves the complete finite inventory
for Replay and rule analysis.

The central ledger retains calls that start after a Case closes. Without a proven
owner they enter the unattributed scope, preserving the observed Case context.
Independent Source analysis can assign them to a process task or original API.
Such a decision never manufactures a response or marks an occurrence consumed.
An existing sealed run with a complete proven end and inventory can support a new
async scope; missing work or completion creates a concrete origin capture obligation.

See [dependency attribution](dependency-attribution.md),
[stream dependency tails](recording-stream-dependency-tail.md), and the
[lifecycle design](dependency-lifecycle-design.md).
