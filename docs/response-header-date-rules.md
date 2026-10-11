# Response header calendar dates

An exporter may return `Content-Disposition: attachment;
filename="report_2026-10-07.docx"`, with the date generated for that request.
An explicit date rule validates each date against its own request's calendar day
and preserves the rest of the header contract.

```yaml
version: 3
expected_response: assertions_only
dependency_rules: []
response_rules:
  headers:
    /api/tasks/*/export/docx:
      - header: content-disposition
        parameter: filename
        format: "%Y-%m-%d"
        timezone: "+00:00"
        source_evidence: "Exporter:filename appends the current UTC date"
```

The route omits METHOD. `header` selects a captured standard response header;
names and parameter names are case-insensitive. `parameter: filename` checks
both `filename` and `filename*` when present, including UTF-8 percent decoding
for `filename*`. Both sides must contain identical parameter sets. Omitting
`parameter` selects a scalar whole-header value.

`format` is explicit: `%Y-%m-%d`, `%Y%m%d`, `%Y/%m/%d`, `%d-%m-%Y` or
`%m-%d-%Y`. `timezone` defaults to UTC and is omitted when it is `+00:00`. A non-UTC
calendar-date rule can declare the source implementation's numeric UTC offset.
The selected value must contain exactly one valid date of that format. Each
date must equal the day at its own recorded request start, with a fixed five
second boundary window around midnight. Missing clocks, invalid dates, multiple
date candidates, duplicate parameters, malformed UTF-8 escapes and multiple
header values fail. No current-clock fallback is used.

Disposition, filename prefix/suffix/extension, other parameters and parameter
presence remain checked. Body and status assertions remain independent. A DOCX
body timestamp rule does not cover the filename; the header rule does not relax
the DOCX package. Overlapping date selectors are rejected.

## Authoring and evidence

Header assertion differences offer a `response_header_date` hint without
requiring a body codec. Assertion detail reports include mechanical
`header_date_candidates`; these do not prove current-date generation or timezone.
The worker traces the exporter and returns the selector and proof to the
coordinator:

```bash
backend-rewrite rule plan --evidence-id CURRENT_EVIDENCE_ID \
  --header-date '{"header":"content-disposition","parameter":"filename","format":"%Y-%m-%d","timezone":"+00:00"}' \
  --source-evidence 'Exporter:filename appends the current UTC date'
backend-rewrite rule apply --plan-id RETURNED_PLAN_ID
```

Plan uses completed focused Replay assertion/aggregate artifacts under the current policy. It validates every selected
observation, requires a date difference, checks assertion-detail and response
fingerprints. Apply checks policy and
evidence are unchanged, then requests fresh verification. Existing recordings
are reusable. No recorded header or target artifact is modified.

Header rules share the [policy freshness check](replay-policy.md#policy-freshness-before-rule-planning)
with dependency rules. An earlier run becomes stale after any policy edit;
follow the evidence's coordinator refresh command, then query new evidence.
Keep the recording run and header selector unchanged unless source diagnosis
requires another configuration.
