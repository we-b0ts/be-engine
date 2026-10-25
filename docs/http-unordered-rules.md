# Unordered JSON arrays in HTTP traffic

Declare array ordering in the global JSON strategy:

```yaml
format: traffic-policy/v2
json:
  fields:
    /department_ids: {kind: unordered}
    /groups/*/member_ids: {kind: unordered}
```

The same paths apply to every decoded JSON carrier, including HTTP requests and
responses. APIs, endpoints and transport types do not require repeated rules.
Pairing still preserves native HTTP method, endpoint, path, query multiplicity,
headers and finite exchange consumption.

An unordered array is a multiset. Duplicate counts, element types, nested element
associations and unselected business fields remain checked. The declaration does
not make nested arrays unordered unless their paths are also declared.

Read-only HTTP diagnostics can suggest order-only differences. Review those
locations and write a proposal containing `json.fields`; use the unified
`rule plan --file ... --evidence ...` and `rule apply` transaction. Planning uses
protected original evidence and keeps a fresh Replay obligation. The former
HTTP-specific unordered planner and per-API JSON rule format are removed.
