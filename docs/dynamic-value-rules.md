# Case-local dynamic dependency values

A source-generated name can appear in a uniqueness SELECT, an INSERT's scalar
and JSON values, and a Redis cache key. One capture binds its recorded value to
the target's generated value. Later references are discovered in decoded
requests on explicitly allowed endpoints, without configuring each use.

This is a dependency request comparison rule. It belongs in `dependency_rules`,
with `kind: dynamic_value`; there is no separate top-level `dynamic_values`
section. Its case-local binding is shared internally across protocol adapters.
It does not bind inbound API requests or final API responses.

```yaml
version: 3
expected_response: assertions_only
dependency_rules:
  - kind: dynamic_value
    id: generated-name
    api: /api/items
    targets:
      - {host: db.internal, port: 3306}
      - {host: redis.internal, port: 6379}
    capture:
      protocol: mysql
      target: {host: db.internal, port: 3306}
      database: app
      sql: "SELECT id FROM items WHERE name=? AND user_id=?"
      value_index: 0
    source_evidence: "NameFactory:create generates a random name reused in storage and cache keys"
```

`api` is an inbound HTTP path/pattern without METHOD. Targets require exact hosts
and nonzero ports; include the capture target and every allowed reference target.
Choose one of these capture locations:

- **MySQL**: the complete business SQL template replaces literals with `?`.
  `value_index` is zero-based among its placeholders. An optional `json_pointer`
  selects a string inside the selected SQL value. Text queries and prepared
  string parameters use the same capture contract.
- **Redis**: select a `SET` or `HSET` value, an exact key and database. The index
  is zero-based among arguments after the command: `SET` value is index 1;
  `HSET` values are even indices starting at 2. An optional JSON pointer selects
  a string inside that value. Other arguments and options remain checked.
- **HTTP dependency**: select method, dependency path/pattern and exact JSON
  pointer in its request body. This method identifies the outbound capture;
  the enclosing inbound `api` remains route-only.

Alternative capture examples (include their targets in `targets`):

```yaml
capture:
  protocol: redis
  target: {host: redis.internal, port: 6379}
  database: 0
  command: SET
  key: identity:current
  argument_index: 1
# Or:
capture:
  protocol: http
  target: {host: service.internal, port: 8080}
  method: POST
  path: /items
  json_pointer: /name
```

No format declaration is required. Values must be nonempty UTF-8 strings of at
most 1024 bytes. Structured JSON requires an explicit pointer to a string;
whole objects and arrays cannot be captured as opaque identities. Optional
`format: uuid` or `format: uuid_v4` validates both captured values. Source evidence
must prove generation, lifetime and intended uses. A differing argument alone
does not prove randomness.

## Authoring and discovery

MySQL `unmatched_target` dirty clusters offer a `dynamic_value` hint. Redis and
HTTP single-string differences provide `dynamic_capture_candidates` in finalized
Replay reports and dirty-cluster evidence. These bounded witnesses contain
selectors and fingerprints, not newly logged token values. They offer the same
planner hint; source review is still required.

```bash
backend-rewrite rule plan --evidence-id CURRENT_EVIDENCE_ID \
  --dynamic-value '{"id":"generated-name","targets":[{"host":"db.internal","port":3306},{"host":"redis.internal","port":6379}],"capture":{"protocol":"mysql","target":{"host":"db.internal","port":3306},"database":"app","sql":"SELECT id FROM items WHERE name=? AND user_id=?","value_index":0}}' \
  --source-evidence 'NameFactory:create generates a random name reused in storage and cache keys'
backend-rewrite rule apply --plan-id RETURNED_PLAN_ID
```

The coordinator supplies the active API route and wraps the entry with `kind`.
Plan requires finalized evidence under the current policy, a complete same-case
recorded response, and a target capture differing only at the selected value.
JSON captures preserve unselected members. Apply checks immutable evidence and
policy fingerprints and requests fresh Replay. Existing recordings are reusable;
old reports are not retroactively changed. Other dependency planners preserve
these entries when editing the common rule list.

If another rule or a comment changed the policy since Replay, follow the
evidence's coordinator refresh command and obtain new evidence using the same
recordings before planning. Stale evidence suppresses planner hints and reports
both policy fingerprints; it does not indicate an unsupported capture or
recording version. See [policy freshness](replay-policy.md#policy-freshness-before-rule-planning).

## Runtime contract

- Capture decisions commit only after the exchange matches. A failed candidate
  cannot authorize later calls. Each source identity has one target identity;
  distinct source identities cannot collapse into one target value.
- Bindings stay within one case and rule, and reset when that case restarts.
  Global and shared cross-case exchanges cannot use them.
- Automatic references cover MySQL text literals/prepared string parameters,
  JSON string values and member names, Redis decoded arguments including key
  substrings, and HTTP dependency paths, queries and JSON bodies. Surrounding
  bytes, object members, array order and scalar types remain checked. Duplicate
  JSON members and ambiguous translations fail.
- Headers, hashes, signatures and opaque binary encodings are not inferred.
  References must follow a successful capture. Inbound and final response
  contracts continue to use their respective explicit rules.
- Finite consumption, response delivery, connection ordering, authentication,
  database and case ownership remain enforced. Redis lock/value and MySQL time
  rules retain their own validations.
- Each rule supports at most 256 distinct identities per case. Applicability
  and binding counts appear in the dependency rule report; unused applicable
  captures fail verification. Binding audits contain fingerprints. The SQL time
  planner restores only same-case bindings proven by the finalized report.

The rule changes request comparison only. It never rewrites recordings,
recorded dependency responses, target responses or expected assertions.
