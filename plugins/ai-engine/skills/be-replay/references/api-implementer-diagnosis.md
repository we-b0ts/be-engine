# API Implementer Diagnosis

Start from the assigned scope, recording ID, expected sequence, and Target
attempt. Inspect the exact Source event, dependency admission, and
authenticated Target observation when available. Use the earlier events for
startup, background work, and concurrent inputs that affect this event. Later
Source events provide context for investigation and receive verification credit
when a Replay reaches them. See [evidence queries](session-regression.md#diagnose-the-first-failure).

## Diagnose the failure

| Evidence | Reference |
| --- | --- |
| Dependency mismatch, missing traffic, or protocol compatibility | [Dependency diagnosis](api-implementer-dependency-diagnosis.md) |
| Startup, local cache, rejected egress, or incomplete Replay | [Runtime diagnosis](api-implementer-runtime-diagnosis.md) |
| Generated time, ID, or token | [Rule diagnosis](api-implementer-rule-diagnosis.md) |

An observed rejection may interrupt a response and prevent later dependency
calls. Trace the earliest event that explains the failure. For a response
status mismatch, start with authentication, preconditions, configuration, and
error mapping. Trace the response body through its construction, application
state or cache, and the dependency behind it. Distinguish JSON null, absent
fields, unavailable payloads, and non-JSON responses. For array order, check
the Source ordering contract and the Target producer.

If required data is unavailable, give the coordinator the precise missing
observation and the Source code that needs it. For a known engine gap, include
the unsupported behavior, exact evidence, and change required. Keep Target
behavior compatible with production.

## Look ahead from a recorded request

Lookahead API items use `api:/case/pattern` across HTTP methods. Read the
assigned sequence list for that scope, then locate the first matching primary
request inside the supplied window. Run the queries against the canonical Target.

```sh
be-replay sequences --assignment-id UUID --scope 'api:/reports/*'
be-replay apis --case-pattern '/reports/*' --from-seq FROM --through-seq THROUGH
```

The lookup returns the actual `method`, `request_seq`, and `exchange` for
Source evidence. Query again with the same bounds and `--after-seq` set to
`next_after_sequence` until `request` is `null`. Use the `exchange` and exact
event references to read its primary response. Inspect each dependency by its
admission sequence. When explicit request links or the Source call path prove
that an unassigned dependency belongs to your API scope, return a claim with
the in-window primary request anchor and evidence. Send links to requests
before the window to the coordinator for the analyst's ownership finding.
[Claim format](session-regression.md#claim-window-dependencies)

Compare the recorded behavior with the available Target observation or the
current Target code and a focused test. Sequence proximity alone cannot
establish an owner. Sequences beyond the first failure remain ahead of the
Replay frontier until a later attempt reaches them.

## Rule Discovery From Source Diagnosis

Trace a suspected dynamic value to the Source generator or validator. Confirm
the exact field or argument, observed sequences, and supported value
relationship. See [rule diagnosis](api-implementer-rule-diagnosis.md).

Deliver the exact repair commit or rule proposal and assignment-specific test results.
[Implementation delivery](api-implementer-delivery.md)
