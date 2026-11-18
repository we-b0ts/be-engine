# Traffic Policy

The sole policy is a strict `traffic-policy/v3` document named by the managed
project's `project.policy` path. The path is relative to the Target repository;
the default is `.traffic-e2e/policy.yaml`.

```yaml
version: 18
project:
  policy: .traffic-e2e/policy.yaml
  # Other project/source/target settings remain required as documented.
```

An empty policy is:

```yaml
format: traffic-policy/v3
rules: []
```

Declare decoded content once under `json.fields`. The same pointers cover
HTTP requests/responses, SSE data and complete JSON values in MySQL, Redis and
other supported carriers. Unknown encodings compare exact bytes. Native SQL
temporal metadata supplies ordinary time semantics when `mysql` is enabled;
`mysql.tables` adds remaining scalar formats by table pattern and column.
`redis.keys` combines scalar formats, bounded key formats and ordered command
or state declarations, without resource/database aliases. `http.headers`
declares scalar header formats with strict presence, count and order. No
header-absence waiver exists.

The engine preserves complete typed identity correspondence internally: equal
Source values require equal Target values, including across carriers. There is
no authored binding, `field_ref`, null/exact fallback, time relation or clock
group for ordinary formats. See [global field formats](resource-field-contracts.md).

Dependency lifetimes remain separate from content. `localcache.requests`
identifies finite process initialization reads; HTTP entries require a host.
`process_dependencies.tasks.<actual-Source-task-name>.requests` groups real
process work across protocols and requires root `source_revision`.
`recording.async_api` defines asynchronous Case capture boundaries: all matched
ends close admission immediately; partial matches permit a one-second probe,
and a new request requires another end or five-minute business-idle fallback.
An uncovered end saves the idle Case normally without stopping Source. Actual
capture failures and explicit stopping retain their own behavior. These are not
payload exemptions. The old root `async_api` remains a compatible input spelling;
canonical output nests it under `recording`, before optional `case_paths`.

Native rules remain for uncovered compound formats, typed PB schemas,
cryptographic transformations and additional causal checks. Multipart, DOCX,
WSS path derivation and AES envelopes retain their existing typed contracts.
Named `signatures` profiles centralize algorithms and private startup key
references. Global `kind: jwt` verifies HMAC signatures and claims across carriers;
`api` positions declare actual input re-signing and additional response nonce/expiry
checks through the existing typed owners. The old authored identity
`formats: [jwt]` syntax is rejected; use `kind: jwt`. See
[signature profiles](signature-profiles.md).

Runtime policy contains no `proof` metadata. Annotated plan proposals carry
independent Source evidence; facts are bounded to 200 UTF-8 bytes and sources to
three file references. Root `source_revision` is an immutable Source identity.
Unknown fields, duplicate declarations, unsupported combinations and conflicting
ownership reject before execution. Content rules are not first-match-wins;
`recording.async_api` explicitly selects the first matching lifecycle scenario per API.

See [unified rule contracts](unified-rule-contracts.md) for all three surfaces,
JSON/PB reuse, native examples, module boundaries, precision, evidence and plan
obligations. Domain-specific rule pages preserve historical semantic explanations;
their old configuration/commands are retired. Production loaders and authoring
APIs accept only `traffic-policy/v3`, not the former version-numbered verification
documents, `traffic-policy/v1` or split file layouts.

Workers discover bounded drafts and missing Source proof through current evidence.
Discovery prioritizes the representative and failed response Cases. Each scan
window has its own observation and JSON-node budgets; candidate and Source
binding counts describe that window, not complete recording coverage. Follow
`pagination.next_page.command` for omitted candidate/binding summaries and
`pagination.next_scan.command` for remaining primary/dependency observations.
The latter alternates surface priority and can resume within a long SSE stream.
`source_entry.binding_count` and `source_entry.summary_omitted` report bindings
separately from mechanical candidates. Nonresumable payload, authentication,
Source-cache or JSON traversal limits remain explicit under
`bounded_analysis.nonresumable_limits`; paging cannot make those observations
available. Continuation commands are bound to the active issue and reject stale
queries. Empty candidates do not establish a missing engine capability.

Bounded dependency operations also expose supported APPEND, finite nil-read
commutation, expiry-refresh and Redis state/read-back mechanisms with their
Source proof requirements. These hints identify capabilities to investigate;
they never authorize changed values, ordering or call counts.

The coordinator proposes a rule, a rule list or an authored v2 document containing
global format/lifetime declarations and any additional native rules:

```text
backend-rewrite rule plan --file rule.yaml --evidence <current-evidence-id>
backend-rewrite rule apply --plan <returned-plan-id>
```

Plan freezes complete selected immutable evidence, execution, key/schema/clock
provenance and the whole policy transaction. Apply rejects stale inputs, records
its write intent, and returns mandatory fresh Replay or Recording obligations.
Applying a rule does not certify Target correctness. Interrupted or legacy plans
use the engine-returned `rule recover` action; never edit workflow state.

To consolidate or revise existing rules, submit an explicit change proposal to
the same `rule plan --file` command:

```yaml
format: traffic-policy-change/v1
replace_rules: [old-clock-rule, old-identity-rule]
policy:
  format: traffic-policy/v3
  rules:
    # Complete replacement rules, with their own Source proof.
```

Only the named old IDs are removed. The planner rejects unknown IDs and a
response/input rule owned by another API issue. Every new or revised permission
passes the ordinary complete Source and independent Target preflight; a proposal
without explicit policy content is rejected. Resource rules can consolidate prior API scopes only
through complete resource evidence. The plan displays the old rules, expanded
replacement rules and whole-policy diff. Unselected rules remain unchanged.
Publication reuses the original policy compare-and-swap, frozen witnesses,
durable write intent and recovery, and requires fresh genuine Replay. A change
proposal is not a persisted policy format. Ordinary rule documents remain
additive: new fields are retained alongside existing declarations, and compatible
formats append in their existing order with exact duplicates removed. Omitting a
rule or field, or supplying an empty format map, never deletes existing content.
Whole-section replacement or clearing requires explicit `replace_sections` in
the change wrapper and the complete desired maps for the named sections.
`replace_rules` independently names native replacements and may be omitted for
a section-only change. Both modes remain evidence-bound and show additions and
removals in the plan before apply.
Capture HTTP consolidation must preserve the exact existing path union, Source
revision and selectors. Ordered Source-response rewrites
cannot be deleted or replaced through this value-rule transaction. Prospective
recorder configuration is checked even when no new Source effect is selected.

The compiled policy has separate runtime, acquisition and classification
fingerprints. Proof-only edits do not invent behavioral changes, while concurrent
raw policy edits still invalidate a planned transaction. Protocol identity,
finite inventory, lane/transaction order, claims, response delivery and termination
remain owned by the existing replay adapters. Payload equality never creates
permission to share, classify, renew or consume another exchange.
