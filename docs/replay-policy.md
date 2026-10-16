# Traffic Policy

The sole policy is a strict `traffic-policy/v1` document named by the managed
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
format: traffic-policy/v1
rules: []
```

Use a self-contained rule by default. Inline resource, codec, contracts and Source
proof make the complete permission visible in one place. Value rules declare
one of `api.response`, `dependency.request`, `dependency.response`; native effects
retain their explicit identity, input, acquisition, ownership or sharing owner.
The policy is not first-match-wins. Unknown fields, unsupported combinations,
duplicate IDs and conflicting field ownership are rejected before execution.

See [unified rule contracts](unified-rule-contracts.md) for all three surfaces,
JSON/PB reuse, native examples, module boundaries, precision, evidence and plan
obligations. Domain-specific rule pages preserve historical semantic explanations;
their old configuration/commands are retired. Production loaders and authoring
APIs do not accept old version 1/2/3 policy documents or split file layouts.

Workers discover bounded drafts and missing Source proof through current evidence.
The coordinator proposes one record or a rule list:

```text
backend-rewrite rule plan --file rule.yaml --evidence <current-evidence-id>
backend-rewrite rule apply --plan <returned-plan-id>
```

Plan freezes complete selected immutable evidence, execution, key/schema/clock
provenance and the whole policy transaction. Apply rejects stale inputs, records
its write intent, and returns mandatory fresh Replay or Recording obligations.
Applying a rule does not certify Target correctness. Interrupted or legacy plans
use the engine-returned `rule recover` action; never edit workflow state.

The compiled policy has separate runtime, acquisition and classification
fingerprints. Proof-only edits do not invent behavioral changes, while concurrent
raw policy edits still invalidate a planned transaction. Protocol identity,
finite inventory, lane/transaction order, claims, response delivery and termination
remain owned by the existing replay adapters. Payload equality never creates
permission to share, classify, renew or consume another exchange.
