# SSE response value contracts

SSE data uses the same global JSON field formats as ordinary HTTP responses,
MySQL JSON-valued columns and cache payloads. An ordinary field declaration
needs no API, wire event or business JSON type selector:

```yaml
format: traffic-policy/v3
json:
  fields:
    /created_at: {kind: time, formats: [unix_seconds]}
    /response/created_at: {kind: time, formats: [unix_seconds]}
    /item_id: {kind: identity, formats: [{prefix: msg_, hex: 12}]}
    /item/id: {kind: identity, formats: [{prefix: msg_, hex: 12}]}
rules: []
```

The engine retains exact SSE framing and decodes each `data` string as complete
JSON without duplicate members. Pointers address that JSON root. Both Source
and Target missing a field passes without evaluating the format; one-sided
presence fails. Time and identity fields accept paired nulls implicitly. Non-JSON
sentinels such as `[DONE]` compare as exact bytes. Event count, order, event
names, IDs, retry values and unselected data remain strict.

Time formats preserve relative differences using independent Source and Target
HTTP request clocks. A field present in creation, progress and terminal events
needs one global pointer declaration. Sharing a format declaration does not
assert that unrelated fields came from the same clock read. Additional proven
clock relationships can retain their contextual native owner.

Identity formats validate both sides. Equal complete typed Source IDs must
remain equal Target IDs across fields, events and supported storage carriers;
different Source IDs cannot merge. The engine maintains this correspondence
internally per replay case. Prefixes are part of the complete identity value,
and numeric IDs differ from string IDs. Failed candidate pairings do not commit
identity decisions. A dependency-delivered unknown ID anchors itself, while an
established correspondence delivers the known Target ID. No generator-first
capture or authored identity group is needed.

`uuid` requires a canonical lowercase, hyphenated, non-nil UUID. `decimal`
requires a positive canonical unsigned integer, preserving the observed scalar
type. `{hex: 12}` requires exactly twelve lowercase hexadecimal characters;
`{base64url: N}` supports fixed unpadded URL-safe token lengths. Literal prefixes
are included in the format map. `string` accepts nonempty UTF-8 identity text
without controls, at most 1024 bytes including its literal prefix. Fixed IDs, externally supplied inputs,
derivations, signatures and finite consumption retain their existing checks.
See [global field formats](resource-field-contracts.md).

Per-API field rules and SSE JSON-type format declarations are retired. Native
signature or causal effects can retain their own scope without changing the
global field declaration. The default event name is `message`; envelope
comparison preserves an absent wire name versus explicit `event: message`.

Discovery groups JSON-bearing SSE slots by their explicit Source `/type` when
present and exposes observed time/unordered drafts without
plaintext values; it does not infer identity permission. Follow the
`unified_value_contract` evidence hint to the `unified_rule_candidates` query.
For response issues, discovery inspects primary responses before dependency
witnesses so a large dependency trace cannot consume the budget first.
`bounded_analysis.scan_order` reports each window's priority; the shared
256-observation and 8192-JSON-node limits still apply per scan window. Discovery
prioritizes the representative and failed Cases. Follow
`pagination.next_page.command` for omitted summaries and
`pagination.next_scan.command` to continue past the observation budget, including
later SSE frames and terminal output. Candidate and location counts describe
only the current window; `source_entry.location_count` and `summary_omitted`
expose location truncation independently of candidates. Nonresumable limits are
reported under `bounded_analysis.nonresumable_limits`.
`source_entry.locations` exposes exact
SSE selectors and authoring instructions even when no time/unordered draft is
found. Use those observed positions to trace Source generation and propose global
field formats; an empty candidate list does not mean the engine lacks SSE support.
Include needed root-relative pointers, including IDs nested in terminal output,
in the global map; scalar MySQL identities use `mysql.tables`. The Source trace
supplies concrete equality relationships, while the proposal supplies formats
and variability proof. Missing events and event
order require Target diagnosis. If
`policy_freshness.requires_fresh_replay` is true, follow its coordinator refresh
command before planning against new evidence.

Plan validates complete selected Source observations and every available
independent Target observation
through the same adapter used by Replay. A missing Target retains a fresh-Replay
obligation. Plans freeze original encrypted request/output artifacts and the
managed key; Apply rejects changed evidence/keys and never rewrites recordings.
Rule application always requires a new genuine Replay.

Nested differences use `$interaction/events/<index>/sse/data/<pointer>`;
envelope differences use the corresponding `/sse/event`, `/sse/id` or
`/sse/retry`. Indices count non-heartbeat semantic messages. Public observations
report these private fields as unavailable rather than falsely missing or
exposing decrypted data. Event count, sequence, text deltas, status, headers,
partial messages, pending actions and connection completion retain strict checks.
