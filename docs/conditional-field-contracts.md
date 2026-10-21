# Conditional field contracts

A Source sibling can select whether another field's contract applies. This
selection is explicit and deterministic; it never tries multiple formats against
Target data. Conditions support one exact `relative_pointer` and either `equals`
or `not_in` with 1–32 same-type scalar values. Relative pointers take exactly one
parent step, such as `../type`; they cannot select the constrained field itself,
escape that parent, or contain wildcards. Constants may be booleans, numbers or
strings (at most 1024 bytes), with strict scalar types.

## JSON and typed Protobuf fields

```yaml
contract:
  /items/*/elapsed:
    kind: conditional
    when: {relative_pointer: ../status, equals: running}
    contract: {kind: duration, unit: seconds}
```

The Source sibling alone selects the active branch. An inactive field compares
exactly. The Target sibling must equal the corresponding Source sibling even if
another contract covers that discriminator. Missing or invalid sibling values
fail comparison. For unordered collections, the predicate follows each paired
Source/Target element, not their original array positions. Typed Protobuf
conditions require a declared scalar sibling binding compatible with the constant.
The existing `not_in` spelling retains the same behavior.

## Redis identity capture

A conditional native capture uses the same predicate relative to its selected
JSON pointer. For `RPUSH key <json>`, argument index 1 selects the first JSON
list element (index 0 is the key; the command is not part of the arguments).
The following is an effect excerpt; the enclosing rule still requires its exact
API/resource/operation/key scope, reference resources and Source proof.

```yaml
effect:
  kind: identity
  value_type: string
  capture:
    kind: redis_argument
    index: 1
    json_pointer: /id
    when: {relative_pointer: ../type, equals: text}
    derived_from: {pointer: /timestamp, prefix: text-}
    copies:
      - {pointer: /_content_key, template: 'content:{value}'}
  references:
    - resource: {protocol: redis, endpoint: 'cache.example:6379', database: 0}
```

For `type: text`, both physical payloads must independently satisfy
`id == "text-" + timestamp`; timestamp must be an integer. Explicit copied keys
must refer to their own bound identity. A separate time contract validates the
timestamp against independent request clocks; an identity relation alone grants
no timestamp permission.

For thinking/tool or other nonmatching Source kinds, this rule creates no identity
binding and grants no field change. Target type changes are rejected on both
active and inactive branches. Both arguments require complete unique-member JSON.
All capture predicates read immutable Source/Target payloads before any identity
projection. Multiple identity rules can own the same JSON location only when the
compiler proves their sibling predicates disjoint; unconditional or overlapping
claims still reject.

The predicate controls capture only. Later declared reference operations such as
SET, GET, APPEND and EXPIRE use the established case-local binding and need not
carry a JSON `type` field. The existing identity equality, injectivity, resource,
authentication, lane, command arguments and finite-consumption checks remain active.

Prefer a positive `equals: text` predicate when the Source code has a text-only
relationship. Excluding only known thinking/tool types could unintentionally
select a new unrelated block kind.

Source preflight counts only active captures, and requires complete later uses
for declared reference resources. Encrypted inbound request predicates use an
authenticated in-memory view in both API and native dependency preflight. Plans
freeze original artifacts and the managed key, keep private bytes out of public
reports, and still require genuine independent Target Replay after Apply.

These dependency bindings and SSE value bindings remain separate owners. An
identical binding label on a response field does not by itself prove the response
identity came from the corresponding dependency result.
