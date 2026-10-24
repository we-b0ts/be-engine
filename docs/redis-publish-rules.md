# Redis PUBLISH payload comparison

PUBLISH JSON values use the same `json.fields` declarations as HTTP bodies,
other Redis values, and MySQL JSON cells. No PUBLISH identity rule, payload
position, channel-specific format declaration, or binding is required:

```yaml
json:
  fields:
    /host_id: {kind: identity, formats: [{hex: 32}]}
```

The engine detects JSON and checks its fields. Stable fields remain exact.
When a Source identity repeats, its complete Target value must repeat too,
including occurrences in other protocols within the same Case. Failed candidate
comparisons do not commit identity correspondence or consume recorded exchanges.

Redis channel selection, command framing, connection ordering, and finite
response consumption remain protocol responsibilities. JSON format declarations
do not change those obligations.

Unknown binary payloads, including pickle, use exact byte comparison. The engine
neither executes their deserializers nor rewrites textual UUID substrings inside
them. Source recordings remain immutable.
