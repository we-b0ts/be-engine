# API-origin dependency observation

Ordinary HTTP responses are forwarded as their headers and body frames arrive,
including Content-Length and chunked bodies. Response completion does not wait
for dependency drain or recording publication. A matching response-body rewrite
still buffers the response before rewriting and forwarding it. Recorder retains
the case slot and the external reservation independently until capture and
publication finish; downstream response delivery also retains its relay lease.

For primary requests matching a `process_owned` rule's `origin.api` and typed
`origin.request_body` conditions, Recorder observes a longer tail:

```yaml
recording:
  case_dependency_post_response_window_ms: 100
  api_origin_dependency_idle_ms: 60000
  case_dependency_drain_timeout_ms: 5000
```

`api_origin_dependency_idle_ms` defaults to 60000. Zero disables this additional
observation for finite APIs. Primary HTTP streams instead use the independent
[dependency tail](recording-stream-dependency-tail.md), even without an origin
rule. Other APIs with no matching origin keep the ordinary fixed post-response
window. The API-origin tail ends when its selected requests have completed and
there has been no selected activity for the configured idle interval, starting
no earlier than primary response completion. Its absolute deadline is the
primary request's original start plus `http_gateway.request_timeout_ms`; activity
never renews that deadline. Configure that timeout above the desired idle window.

Only the complete selectors of rules with a matching origin extend the window.
For example, Redis GET on one configured key template does not select every
command sent to the same Redis instance. Ordinary process-owned rules without
an API origin, unrelated keys/SQL, connection pools, recording writes and
reservation clones do not renew selected activity. Request admission and idle
closure share a lock, so a selected request arriving at closure cannot disappear
between the quiet check and closing dependency admission. Already admitted
requests still receive the bounded ordinary drain after admission closes.

The existing API-origin schema supports MySQL and Redis. Each adapter supplies
request facts; the activity clock, in-flight ownership and deadlines are shared.
This change does not expand protocol policy capabilities. A successful recorded
MySQL INSERT can bind the configured task/subtask identity online. Once uniquely
bound, requests for another identity do not extend waiting. Missing or ambiguous
capture falls back to the configured selector shape and is explicitly reported;
it does not prove that a dependency belongs to this particular task. MySQL
transaction members require a successful real transaction and matching anchor.
SQL placeholders are never guessed into an identity.

Unselected dependencies retain their existing capture, attribution and Replay
obligations. They simply do not prolong this observation. Rules are a configured
coverage scope, not a complete inventory or a background-job completion signal.
Gaps longer than the idle interval or missing rules can leave later work outside
the case; refine the rules from evidence when that coverage is needed.

`api-origin-observation.json` records the interval, absolute budget, outcome,
per-rule capture state and selection counts, and finite references to selected
semantic dependency exchanges. It contains no captured task IDs, SQL or Redis
payloads. Reaching the absolute deadline quarantines the case as an incomplete
observation. A request that remains in flight after the final drain also blocks
new case admission; Recorder does not reset Source sockets to end a tail.

Replay uses the finite selected-exchange references to retain the case until
those actual Target exchanges finish consuming their recorded counterparts,
bounded by the original request budget from Target case start. It finishes as
soon as these obligations are satisfied instead of repeating the idle interval.
It never submits Target calls or relaxes dependency matching on their behalf.
Recordings without this metadata keep the previous Replay lifecycle.

RPC callback correlation is separate from in-flight command ownership. Keeping
a possible callback identity does not keep an already completed Redis command
in flight. A callback can reacquire its original case only while that case still
accepts dependencies; a later callback retains its correlation in Global evidence
without reopening a published case.
