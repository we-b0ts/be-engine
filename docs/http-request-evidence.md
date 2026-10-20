# HTTP dependency request evidence

When an outbound HTTP or HTTPS request fails matching, inspect its original
Source and independently observed Target bodies through the coordinator:

```bash
backend-rewrite evidence --api /api/v1/responses
```

Execute the returned `http-request-differences` query. A dirty HTTP cluster also
returns `http_request_differences_command`. These commands inspect finalized
evidence without advancing the workflow or modifying the target or recordings.

## Query sequence

The first page lists failed dependency requests with their physical report
index, Case, scheme, endpoint, method, path, failure reason, and retained Target
observation identity. Follow these returned commands in order:

1. `candidates_query` lists authenticated runtime candidate associations. Each
   candidate retains its original Source exchange and Target observation IDs.
   Multiple candidates remain explicit; none is presented as a successful match.
2. `differences_query` shows Source/Target body sizes and SHA256 identities,
   request clocks, content type/encoding, and a bounded page of original body
   differences. It also returns both body queries and any recorded rule trace.
3. `source_body_query` and `target_body_query` return the exact captured body in
   bounded pages. Follow `next_query.command` until `end_of_body` is true.

Every query reference contains `query_id` and `command`. Use the returned command
instead of constructing cursors. A cursor binds the API issue, attempt and exact
published report digest; a replaced report or changed issue rejects old cursors.
The API scope is checked again before request contents are read.

## Differences and rules

JSON body differences use RFC6901 pointers with escaped `/` and `~` characters.
Observations distinguish missing fields from present JSON `null`, value and type
changes, array lengths and indexed element changes. Bounded order-only detection
retains duplicate multiplicity and is a diagnostic hint, not an unordered rule.
Long strings include the first differing byte, changed ranges with exclusive end
offsets, and context near the change. Non-JSON bodies use byte differences.

The original-value walk belongs to the shared JSON diagnostic module. Rule
evaluation uses the ordinary shared value-contract comparator during Replay.
`runtime_rule_comparison` retains its selected/evaluated rule IDs, pass/fail
result, residual failure pointers/reasons and comparison-input digests. It does
not rerun today's policy against historical inputs, commit rule usage or change
matching. Original differences may be accepted by a rule; inspect the runtime
comparison separately. Its policy fingerprint is the one in the Replay report.

Historical reports and native comparison paths without a retained typed-value
trace explicitly report the trace as unavailable. The comparison-input digests
also distinguish normalized runtime inputs from the original body bytes; they
are not additional independent Target observations. Runtime traces retain at
most 64 candidate comparisons per failed request and report any omitted count.

The diagnostic walk bounds depth and examined nodes. `analysis_complete`,
`nodes_examined`, `node_limit`, `differences_found`, `total_differences` and
`next_query` describe coverage. An incomplete analysis has no exact total;
complete body access remains available for manual inspection. HTTP evidence
selection traverses the complete relevant authenticated metadata inventory,
independently of the rule-draft discovery limit of 256 observations.

## Complete body pages

Each body page includes:

- `presence`, `side`, `original_len` and the full-body `sha256`;
- `capture_truncated: false` when the protected HTTP envelope contains a
  complete body;
- byte `offset`, `returned_bytes`, `encoding` and `data`;
- `page_truncated`, `end_of_body` and the next query, when needed.

UTF-8 pages end on character boundaries. Encode each decoded JSON `data` string
as UTF-8 to reconstruct the original bytes. Binary pages encode their bytes as
base64; decode each page individually. Concatenate decoded bytes in increasing
offset order, verify contiguous offsets and total length, then verify SHA256.
An empty captured body is present and has length zero.

Bodies remain in authenticated private encrypted storage or authenticated
immutable Source references. Public Replay reports contain identities and
bounded rule diagnostics, not body contents. Only an explicitly requested
diagnostic query returns body values. Authorization/cookie headers are not
included in the envelope summary.

An independent Target observation without a Source candidate can still provide
its complete Target body. A historical report lacking protected observations,
or incomplete capture coverage, returns `presence: unavailable` with the reason
and the requirement for fresh genuine Replay. Missing data is not synthesized.
Authentication failures and corrupt artifacts fail the query instead of being
reported as an empty difference set. Legacy reports without a failure's Target
observation ID label Case/endpoint/method/path correlation as ambiguous evidence.

`backend-rewrite case dependencies` also includes HTTP(S) targets and bounded
Source request metadata, with an `evidence --api` command for Replay details.
