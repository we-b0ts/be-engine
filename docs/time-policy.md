# Built-in time semantics

Standard textual dates are ordinary engine value semantics. RFC3339,
ISO8601 naive datetime, SQL datetime and calendar dates require no field rule,
Source-code proof or provisional match. Successful checks do not produce rule
suggestions or dirty dependencies. Source alone selects the format; Target must
retain its scalar type, precision, separators and timezone representation.
Other content, member presence, array order and native protocol constraints stay
strict. Malformed or incompatible Target dates fail the original comparison.
Exact equal values retain their ordinary strict-equality result without needing
a clock; automatic temporal validation explains differing standard date values.

The same value contract applies to decoded JSON and Protobuf, supported SQL
arguments and result values, and Redis value arguments. A carrier adapter owns
decoding and native rendering; it does not implement another timestamp parser.
Protobuf still needs an admitted schema, and unknown wire content stays exact.
Numeric epochs are not automatically classified as time: they retain their
declared format or the existing provisional hypothesis and evidence workflow.

Projects configure the interpretation of naive and calendar values once, near
the top of their unified policy:

```yaml
format: traffic-policy/v3
time:
  default_utc_offset: '+08:00'
```

The default is `+08:00`. A value with an explicit RFC3339 timezone uses its own
offset. An explicit field contract retains its own timezone and relationships.
Ordinary rule additions preserve the existing project time configuration;
changing it uses an explicit `replace_sections: [time]` policy transaction.

## Comparison events

For dependency request matching, each side uses that dependency's request
initiation time. An API request timestamp is never a substitute. New MySQL and
Memcached recordings retain the precise initiation observation; older complete
envelopes can recover it from completion minus duration without changing the
recording. Missing or malformed observations remain missing.

For ordinary API response comparison, each side uses its own response completion
time. HTTP observes body EOF, Motan observes the native reply, and streaming
protocols retain independently observed event clocks. Source response completion
is captured before dependency drain; Target completion is captured before
assertion and artifact publication. A missing response event does not fall back
to request start. Explicit request-based signature and JWT relationships keep
their request clock contract.

The shared check is:

```text
delta = target_event - source_event
error = (target_value - source_value) - delta
abs(error) <= tolerance
```

The common tolerance remains five seconds. It is distinct from representation
precision and does not expand to API duration. Calendar values instead preserve
their exact local-day distance from the corresponding event's date.

Automatic recognition grants comparison semantics only. Ordinary dependency
payloads retain their original recorded bytes, including standard date strings.
An explicitly authorized input/time rewrite uses its selected contract and
preserves Source representation precision. Immutable recordings remain unchanged.
Using delivered-copy provenance to justify a differing value requires its exact
authenticated, successfully delivered time pair with an earlier delivery
observation in both executions.
Failed delivery or a speculative candidate cannot establish this provenance.

Pre-matching, ordinary comparison, rule discovery, evidence preflight and
response assertion share these event contexts. Built-in validation is counted
separately from authored rule coverage and cannot prove an unrelated rule.
Changing the project timezone changes runtime semantics and its fingerprint,
while keeping recording acquisition and dependency ownership fingerprints.
