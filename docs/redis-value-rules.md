# Redis content comparison

Redis JSON uses the same global field formats as HTTP bodies, SSE messages and
MySQL JSON cells. No Redis value rule, API selector, key-specific JSON schema or
separate unordered plan is needed:

```yaml
json:
  fields:
    /groups/*/ids: {kind: unordered}
    /created_at: {kind: time, formats: [unix_seconds]}
    /item_id: {kind: identity, formats: [uuid]}
```

The engine recognizes complete JSON with unique object members. Object member
order and whitespace do not affect comparison; arrays retain their order unless
selected by the global map. Unordered comparison preserves whole elements,
associations, types, multiplicity and every unselected business value. Both
missing fields and both null values pass; one-sided presence changes fail.

Protocol adapters identify complete stored values and retain command, endpoint,
database, authentication, physical keys, lanes and finite consumption. A value
format grants no permission to change another command argument or invocation
count. Relative TTLs remain exact; protocol-declared absolute deadlines preserve
their request-relative remaining lifetime.

Whole generated values share the internal case correspondence. Established
Target values are reused on reads; unknown historical inputs retain their Source
values. JSON identities need only the global declaration. Scalar stored values
use [Redis scalar formats](redis-scalar-formats.md); physical key relationships
remain under `redis`.

Unrecognized bytes retain exact comparison. Read-only Protobuf diagnostics may
suggest candidate repeated fields and wire-compatible types, but they do not
establish a schema, enable a decoder or authorize reordering. Known logical
protocol projections use the common content kernel; unsupported formats stay
exact until explicitly supported by the engine.

Use the Source admission sequence and corresponding authenticated Target
observation to trace Redis differences. Review the original command, complete
value and Source field semantics before changing a global `json.fields`
declaration. Verify the integrated change against the same sealed recording.
[Source session evidence](session-regression.md)
