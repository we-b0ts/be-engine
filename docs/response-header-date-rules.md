# Response header calendar dates

> Authoring migration: the legacy YAML and flag-based commands below are
> historical semantic references. They are not accepted configuration or CLI
> syntax. Use the self-contained `traffic-policy/v2` rules, `project.policy`,
> and `rule plan --file … --evidence …` described in
> [unified rule contracts](unified-rule-contracts.md). The protocol, identity,
> evidence and lifecycle constraints described here remain mandatory.


An exporter may return `Content-Disposition: attachment;
filename="report_2026-10-07.docx"`, with the date generated for that request.
An explicit date rule compares the Source/Target date change with the independently
observed request-time change at day precision and preserves the rest of the header.

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
        source_evidence: "Exporter:filename appends the current UTC date"
```

The route omits METHOD. `header` selects a captured standard response header;
names and parameter names are case-insensitive. `parameter: filename` checks
both `filename` and `filename*` when present, including UTF-8 percent decoding
for `filename*`. Both sides must contain identical parameter sets. Omitting
`parameter` selects a scalar whole-header value.

`format` is explicit: `%Y-%m-%d`, `%Y%m%d`, `%Y/%m/%d`, `%d-%m-%Y` or
`%m-%d-%Y`. No timezone configuration is needed. Source and Target must have the
same timezone behavior; a rule does not compensate for environment differences.
Legacy numeric `timezone` values are validated and omitted on writing.
The selected value must contain exactly one valid date of that format. Date-only
precision allows the adjacent-day ambiguity inherent in crossing an unknown local
midnight, including a fixed five-second clock tolerance. It cannot prove the
absolute local calendar day. Related filename and filename* dates must retain
the same day change. Missing clocks, invalid dates, multiple
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
