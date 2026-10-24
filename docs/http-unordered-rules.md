# Unordered arrays in HTTP dependency requests

> Authoring migration: the legacy YAML and flag-based commands below are
> historical semantic references. They are not accepted configuration or CLI
> syntax. Use the self-contained `traffic-policy/v2` rules, `project.policy`,
> and `rule plan --file … --evidence …` described in
> [unified rule contracts](unified-rule-contracts.md). The protocol, identity,
> evidence and lifecycle constraints described here remain mandatory.


Use `unordered` when an outbound HTTP JSON request contains an array whose
element order has no meaning in the source contract. For example, a membership
check can send the same department IDs in a different order because the source
constructs them from a set. This is a dependency-value rule. Response
`unordered` rules do not affect outbound requests, and `cross-case` changes
exchange availability rather than array comparison.

## Configuration

The coordinator writes `.traffic-e2e/verification.yaml` through plan/apply:

```yaml
version: 3
expected_response: assertions_only
dependency_rules:
  - id: erp-department-ids
    protocol: http
    target:
      host: agent.erp.sample.test
      port: 80
    http:
      method: POST
      path: /api/open/batch-check-membership
      json:
        unordered:
          - pointer: /department_ids
            source_evidence: 'backend/app/services/share/namespace_entity_resolver.py:216 entity_ids: constructed from a set and matched by department ID'
```

`unordered` names the capability; `erp-department-ids` is one rule instance.
The endpoint selector is independent of the inbound API, so every API using
this exact dependency endpoint receives the same comparison policy. Host,
port, method and path are required; paths are exact and do not include query.
Query names, values and duplicate counts remain exact when this rule enables
a match, including when legacy global query ignores exist.

Each non-root JSON Pointer selects only its array's element order. As with
response rules, `/groups/*/department_ids` expands array elements; `*` does
not enumerate object properties. Array contents, multiplicity, types, missing
fields and all unselected fields retain ordinary JSON equality. Nested arrays
inside an element retain their order unless separately selected. Overlapping
selections are rejected. Object field order already has ordinary JSON value
semantics and needs no unordered rule.

The rule retains ordinary case plus Global inventory, finite consumption,
scheme and endpoint matching, and the normal header checks. It does not relax
the full request fingerprint required by shared `cross-case` exchanges.

## Discovery and worker handoff

1. After a failed Replay, follow `status`/`next` to the assigned worker's
   `evidence --api '<METHOD pattern>'` against the canonical target root, then
   the overview's `dirty_clusters` query.
   Discovery is available during response, dependency and Replay issues; a
   passing response is not a prerequisite.
2. An HTTP unmatched cluster exposes an `unordered` entry in `rule_hints`.
   `facts.http_unordered_candidates` contains bounded candidates with the
   source/consumer case, exact endpoint, JSON Pointer, element count and other
   array paths that still differ. Only loaded, unconsumed ordinary case/Global
   exchanges participate. The complete requests must match after correcting
   only the discovered array order differences; an endpoint alone is not proof.
3. With candidates, `applicable_rule_planners` exposes
   `kind: dependency_value`, `capability: http_json_unordered` and the current
   evidence-bound `dependency-rule plan http unordered` help command.
4. The worker inspects source construction and downstream use to prove that
   order is non-contractual. It returns the endpoint, JSON Pointer and a
   single-line source citation. It does not modify target ordering to imitate
   a recording, edit verification policy, or execute plan/apply.

Candidate capture runs only after an unmatched request and scans in-memory
exchanges, without dependency-file I/O on the request path. Reports retain
hashes and structural metadata, not request values, credentials or responses.
Discovery handles bodies up to 1 MiB and depth 32, with at most 64 candidates
per request and per public preview. A truncated preview cannot authorize a
plan; narrow and rerun the focused Replay. Old reports without these witnesses
require fresh Replay. A URL-only or array-shape-only guess cannot authorize a rule.

## Plan, apply and reexecution

The workflow coordinator uses the current dirty evidence ID:

```bash
backend-rewrite --target-root /path/to/target dependency-rule plan http unordered \
  --evidence-id <returned-evidence-id> \
  --rule-id erp-department-ids \
  --host agent.erp.sample.test --port 80 \
  --method POST --path /api/open/batch-check-membership \
  --json-pointer /department_ids \
  --source-evidence 'backend/app/services/share/namespace_entity_resolver.py:216 entity_ids: constructed from a set and matched by department ID'
```

No ownership flag, API selector, case ID, recorded value or fixture path is a
planner input. The engine resolves the recording and finalized report from
the current issue. It verifies witnesses against immutable source exchanges,
reviews the selected fields, and returns the rule diff and exact
`dependency-rule apply <plan-id>` command. One array may be selected while other
order-only array differences remain; those residuals still prevent a match.

Apply revalidates current evidence and atomically updates only dependency
rules. Repeated identical plans reuse the configured rule. Policy, report or
relevant source changes invalidate a pending plan. Follow the returned `next`
for real Replay; the old failed request received no recorded response and
cannot be retrospectively marked clean. Existing API verification becomes
stale because the endpoint rule can affect multiple APIs. Complete existing
recordings do not require a new standard recording.
