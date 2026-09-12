# Use MySQL through `brz-mysql`

Use `brz-mysql` for pooled connections, typed queries, transactions, and table
routing. Keep SQL and result types in their owning repositories. Recover the
source tables, column types, argument values, ordering, transaction boundaries,
and routing rules before implementing the target operation.

## Dependency and lifecycle

Use the latest stable release from the project's configured Cargo registry and
pin it exactly. Replace `<latest-version>` with the verified release number
without a `v` prefix; it is a placeholder, not a Cargo version expression.
Replace the old Git dependency, preserve registry configuration, and update
`Cargo.lock`.

```toml
[dependencies]
brz-mysql = { version = "=<latest-version>" }
```

MySQL metrics are built in; there is no separate `metrics` feature to enable.
Create one `MysqlService` per database dependency at startup. Retain it for the
process lifetime; clones and routed handles share its pool:

```rust,no_run
use brz_mysql::{MysqlResult, MysqlService, MysqlServiceOptions};

async fn connect(database_url: &str, max_connections: u32) -> MysqlResult<MysqlService> {
    let options = MysqlServiceOptions::default()
        .with_max_connections(max_connections);
    MysqlService::connect_with_options(database_url, options).await
}
```

Choose pool limits, acquisition timeout, charset, and timezone from the target's
runtime contract. When acquisition timeout is below `slow_acquire_threshold`,
lower that threshold too. For defaults, use `MysqlService::connect(url).await?`.
For deferred connection creation, call `connect_lazy` or
`connect_lazy_with_options` inside the Tokio runtime and keep `min_connections`
at zero. Close the parent service once, after its users stop, with
`mysql.close().await`; this closes the pool shared by all handles.

## Typed queries

Import `Mysql` and accept `&M` with `M: Mysql` in repository query functions.
`MysqlService` handles both ordinary and routed queries. Select explicit
columns with stable names or aliases and derive directly on business types.
The example schema is illustrative; substitute the source schema and operation.

```rust,no_run
use brz_mysql::{FromMysqlCol, FromMysqlRow, Mysql, MysqlResult};
use serde::Deserialize;

#[derive(Deserialize, FromMysqlCol)]
struct Metadata {
    enabled: bool,
}

#[derive(FromMysqlRow)]
struct Record {
    id: u64,
    value: String,
    #[mysql(rename = "metadata_json")]
    metadata: Metadata,
    deleted_at: Option<chrono::NaiveDateTime>,
}

async fn find<M: Mysql>(mysql: &M, id: u64) -> MysqlResult<Option<Record>> {
    mysql.fetch_optional(
        "SELECT id, value, metadata_json, deleted_at FROM records WHERE id = ?",
        (id,),
    ).await
}
```

Use `serde` with `derive` for JSON business types and `chrono` when the schema
needs its date/time types. Choose the API and result shape deliberately:

| Requirement | API or type |
| --- | --- |
| Optional row | `fetch_optional`: `None` when absent |
| Required row | `fetch_one`: `MysqlError::RowNotFound` when absent |
| Bounded collection | `fetch_all`: collects into `Vec<T>` |
| Large result | `fetch`: lazy row stream |
| Write | `execute`: returns `rows_affected` and `last_insert_id` |
| Named columns | Business struct deriving `FromMysqlRow`; `#[mysql(rename = "column")]` for aliases |
| Single column | Scalar implementing `FromMysqlCol` |
| Positional columns | Tuple of 1–16 column types, in SELECT order |
| SQL NULL | `Option<T>`; optional nullable scalar uses `Option<Option<T>>` |
| JSON column | `Deserialize` + `FromMysqlCol`, or `Json<T>` for typed reads/writes |
| Binary payload | `BinaryColumn`; `into_bytes()` avoids a payload copy for HTTP responses |

Model JSON with business structs/enums or maps with concrete value types.
Preserve numeric signedness, NULL semantics, decoding errors, and row absence.
`BinaryColumn` retains owned row storage without holding a pool slot; the driver
still buffers the complete row, so this is not incremental BLOB streaming.

## Bind values and preserve SQL semantics

Pass heterogeneous arguments as tuples: `(value,)` for one, `()` for none.
Bind values using their original types; do not interpolate them into SQL.
Preserve tuple pairing, boolean grouping, DISTINCT, result order, and pagination.

For dynamic `IN` lists, generate only placeholders and supply a homogeneous
`Vec<T>` with one value per placeholder. Handle empty input according to the
source contract before constructing SQL:

```rust,ignore
// Inside a repository function; Record is the business type above.
if ids.is_empty() {
    return Ok(Vec::<Record>::new()); // Use only if this matches source behavior.
}
let placeholders = vec!["?"; ids.len()].join(", ");
let sql = format!(
    "SELECT id, value, metadata_json, deleted_at FROM records WHERE id IN ({placeholders}) ORDER BY id"
);
let records: Vec<Record> = mysql.fetch_all(sql, ids.to_vec()).await?;
```

Keep ordinary reads on the shared pool. Do not change driver session
initialization or prepared-statement behavior to accommodate recording/replay.

## Table routing

Use the 0.0.8+ unified service API; `MysqlRoute` maps are removed. Implement the source's
key decoding and table selection for the template name supplied by the SQL:

```rust,ignore
fn resolve<'a>(
    &'a self,
    template: &'a str,
    key: &'a dyn MysqlRouteKey,
) -> MysqlResult<impl MysqlRouteOutput + 'a>;
```

Return a lightweight result implementing
`write_to(&self, out: &mut dyn std::fmt::Write) -> std::fmt::Result`, or any
`Display` type (`&str`, numbers, or a formatting struct). The SDK writes it
directly into the final SQL buffer without boxing the result or requiring an
intermediate `String`. A result may borrow the policy, template, or key.
Each distinct template is resolved/written once per statement; repeats reuse
the written value. `{{records}}` replaces a whole identifier;
`records_{{slot}}` replaces a fragment. `table_suffix` is an ordinary template name.

Retain `mysql.with_route(policy)` in the repository. Both `with_route` and `route`
return `MysqlService`, sharing the base pool. Plain SQL also works on this handle
and bypasses routing; only actual identifier templates invoke the policy.
Since 0.0.9, `route` is also on the `Mysql` trait: repositories taking `&M` with
`M: Mysql` can call `mysql.route(ByUserId(uid))` directly and get `M` back
(`fn route<K: MysqlRouteKey>(&self, key: K) -> Self`).

Explicit keys automatically implement the empty `MysqlRouteKey` marker when
`Any + Send + Sync` (therefore `'static`); no `MysqlValue` or `Clone` implementation
is needed. Use business newtypes and `key.downcast_ref::<T>()` when equal numeric
values can mean different things, such as a legacy record ID versus a user ID.
Decode and choose base/sharded tables according to the source, never guess from
an untyped number alone.

```rust,ignore
struct ByRecordId(u64);
struct ByUserId(u64);
let records = mysql.with_route(routing_policy);
records.route(ByRecordId(id)).execute(
    "UPDATE {{records}} SET value = ? WHERE id = ?", (value, id),
).await?;
records.route(ByUserId(uid)).execute(
    "DELETE FROM {{records}} WHERE user_id = ?", (uid,),
).await?;
```

`.route(key)` overrides the first SQL argument without becoming a bound argument
or mutating the original handle. Without it, the first argument remains both
the implicit key and a SQL argument. Integer/string/byte helpers remain available;
implicit borrowed strings/bytes are copied once per templated statement to meet
the `Any` contract. Explicit keys retain their concrete type.

The SDK validates identifier characters and the 64-character limit, then quotes
the rendered identifier. Never return SQL fragments. Strings/comments are not
routed; forgetting a template executes the literal table name. This supports
one database, not database sharding or fanout. Preserve source SQL mode;
rendering assumes default escaping, not `ANSI_QUOTES` or `NO_BACKSLASH_ESCAPES`.

## Transactions and row streams

Use `with_transaction` when the operation needs one connection and an atomic
commit/rollback boundary. Import `MysqlTransaction` for its query methods.
Returning `Ok` commits; returning `Err` rolls back. A standalone pool-level
`execute("ROLLBACK", ())` cannot roll back another connection's transaction.

```rust,no_run
use brz_mysql::{Mysql, MysqlResult, MysqlTransaction};

async fn update_together<M: Mysql>(
    mysql: &M, id: u64, value: &str, enabled: bool,
) -> MysqlResult<()> {
    mysql.with_transaction(async |tx| {
        tx.execute("UPDATE records SET value = ? WHERE id = ?", (value, id)).await?;
        tx.execute("UPDATE settings SET enabled = ? WHERE id = ?", (enabled, id)).await?;
        Ok(())
    }).await
}
```

A transaction on a routed handle retains one database connection. Templated
statements use their first argument as the routing key unless the service or
`tx.route(key)` supplies an explicit key. A statement-specific key overrides the
default without changing subsequent statements. Plain SQL uses the same
connection; all statements commit or roll back together.

Consume large row streams with `futures-util`; a polled stream holds a pooled
connection until it completes or is dropped:

```rust,ignore
use futures_util::{StreamExt, pin_mut};

let rows = mysql.fetch::<_, _, Record>(sql, args);
pin_mut!(rows);
while let Some(record) = rows.next().await {
    consume(record?).await?; // The application's actual consumer.
}
```

Drain or drop streams promptly. Cancellation and early stream termination affect
connection lifetime and operation metrics; do not hide failures with default
values or automatic retries that the source does not perform.
