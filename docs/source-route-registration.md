# HTTP Source route registration

Confirmed Source registration and observed traffic are different inputs.
The coordinator records confirmed routes in `http.source_routes` in the managed
Source traffic policy:

```yaml
http:
  source_routes:
  - GET /objects/*
  - POST /objects/*
  - POST /objects/upload
```

Every registration includes its uppercase HTTP method. A static registration
has no wildcard. Resolve a request against exact static registrations of its
method first, then same-method patterns. An unregistered method/path remains a
Source-analysis candidate. Observing a literal path never promotes it to a
confirmed static Source. A known GET pattern covers a later GET observation
without another confirmation, but cannot confirm POST. When POST is confirmed
with the same template, both methods share one API work item and retain separate
case membership, issues and completion gates.

Adding a wildcard cannot remove a confirmed static registration. Static and
pattern declarations can coexist, but the pattern's case membership excludes
its same-method registered static paths. Registration order does not choose
ownership. Overlapping same-method patterns remain an explicit ambiguity error.
Registrations are additive and publication is serialized; concurrent static and
pattern confirmations cannot lose either declaration.

Use the returned `case-pattern apply` command with
`BACKEND_REWRITE_SOURCE_ROUTES_JSON`, or explicitly use `--routes-json`.
The complete JSON array includes static declarations. `[]` cannot confirm an
uncovered batch. Source analysis must prove every submitted method and selector;
there is no method inference from a path-only pattern. The old `--patterns-json`
confirmation interface is unsupported. Methodless `case_path_patterns` and
recorded `api_pattern` metadata do not authorize API ownership.

The Recorder takes one registration snapshot at startup. Confirmed methods of
one canonical route share a recording directory. Unconfirmed methods remain
separate until Source analysis; new recordings use readable directory names
with a stable identity suffix, avoiding slug collisions. Query strings do not
change route ownership, but remain exact Replay inputs. Raw paths, including
trailing separators, are preserved and never aliased by registration.

Prepare snapshots confirmed registrations in a version-three group index and
validates exact case ownership. A recording directory containing different
confirmed canonical APIs is rejected; the engine never moves or edits the
published cases to split it. Old version-one/two group indexes are rejected
instead of executing legacy selection rules. Finish historical Replay with its
original engine before upgrading. This release does not automatically rekey an
installed coordinator inventory or transfer historical passing evidence.

These rules change API grouping and scheduling only. They do not change HTTP
routing in the application or relax response/dependency comparisons. JSON null,
empty strings and missing fields remain distinct.
