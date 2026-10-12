# JSON Usage

Use `brz-json` for JSON handling in target Rust projects. Keep Serde's
`Serialize` / `Deserialize` derives and field attributes. Avoid direct
dependencies, imports, and calls to `serde_json::*`, except at the existing
dynamic mutation boundaries described below. Reuse the library for field
presence/null handling, coercion, and passthrough instead of reimplementing them.

Pin a published version, for example `brz-json = "=0.0.9"`. A temporary `path`
dependency may be used for integration when requested by the user; restore the
published dependency and update the lockfile before delivery.

## Choosing Types

- Known structure: prefer a `struct` with `brz_json::from_str` / `from_slice`
  and `to_string` / `to_vec`. Use `JsonReader` for segmented HTTP input.
- Exact passthrough without inspecting the contents: use `brz_json::RawJson`,
  or `RawJsonRef<'a>` to borrow input. Add `#[serde(borrow)]` to borrowed fields
  and keep the reader alive.
- Legacy deserialization requiring Value's numeric validation and normalization:
  use `OpaqueJson`. `decode::<T>()` returns errors; `project::<T>()` explicitly
  tolerates projection mismatches. `RawJson` can preserve `1e400`, whereas
  `OpaqueJson` deserialization rejects it. Preserve this distinction when migrating.
- Dynamic keys with stable order: use `Object<T>`. Existing code that must
  mutate schema-free documents may retain `serde_json::Value` within that
  boundary. Avoid import-only migrations.

`brz-json` does not re-export `Value`, `Map`, `Number`, `json!`, or `RawValue`.
`RawJson` owns validation, exact serialization, and typed `decode::<T>()`;
`RawJsonRef` supports reader borrowing and `to_owned()`. The underlying `RawValue`
stays inside the library. Add capabilities with actual behavior when needed;
avoid speculative wrappers that only rename existing APIs.

## Missing Fields and Null

A plain `Option<T>` represents both missing and null. For update requests that
must distinguish them, use the model macro and declare the actual field type
instead of the internal `Field<T>`:

```rust
use brz_json::FieldState as _;
use serde::{Deserialize, Serialize};

#[brz_json::model]
#[derive(Default, Deserialize, Serialize)]
struct Update {
    #[json(presence)]
    title: String,
}
```

Read state and values through `title.is_missing()`, `is_null()`, `is_present()`,
`value()`, or `into_value()`. Serialization omits missing fields and retains
explicit null. Place the macro before derive; ordinary structs do not need it.
Use `#[json(presence, lenient)]` only when the source contract accepts wrong
types. A wrong type then means "present, non-null, no valid value"; it is not missing.

## Choose Compatibility Policies per Field

Use `#[serde(default, deserialize_with = "brz_json::adapters::...")]`:

| Source behavior | Adapter |
| --- | --- |
| Default on null; reject wrong types | `null_as_default` |
| Ignore wrong types / use the default | `try_decode` / `invalid_as_default` |
| Require object models; reject positional arrays | `object` / `optional_object` / `optional_objects` |
| Treat null or an empty string as absent | `nonempty_string` |
| Filter only null list items; reject other invalid items | `nonnull_items` |
| Explicit string, boolean, and numeric conversions | `integer` / `number` / `boolean` and `optional_*` |
| Explicitly truncate fractional numbers | `truncated_integer` |
| Legacy boolean rules: trim strings, accept empty strings and any signed integer | `legacy_boolean` |
| Python `bool(value)` | `PythonTruthiness` / `python_truthy` |

`default` controls missing fields; adapters handle supplied values. Do not enable
coercion globally. Tolerant decoding must still validate complete JSON and reject
syntax errors. Keep business defaults, enums, permissions, error responses, and
special Python formatting in the application. Diagnostics expose `path()` and,
when available, `byte_offset()`.

Preserve missing/null, wrong-type, empty-value, and numeric boundary semantics
during migration. Remove duplicate library capability tests only after the JSON
module covers them; retain application response and state transition tests.
