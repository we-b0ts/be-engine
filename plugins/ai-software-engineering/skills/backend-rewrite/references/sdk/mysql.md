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
Both `MysqlService` and `ShardedMysqlService` implement the trait. Select explicit
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

Implement `MysqlRouting::resolve` using the source's key decoding and physical
table selection. Return identifiers through `MysqlRoute`:

| SQL template | Policy result |
| --- | --- |
| `records_{{table_suffix}}` | `MysqlRoute::new().with_table_suffix(&suffix)?` |
| `{{records}}` | `MysqlRoute::new().with_table("records", physical_table)?` |

Create and retain `mysql.with_route(policy)` at repository initialization. It
returns an owned `ShardedMysqlService` sharing the base pool. Pass it to the same
`M: Mysql` query functions. Routed service queries require table templates;
ordinary service queries use the base handle.

```rust,ignore
// routing_policy implements the application's actual MysqlRouting rules.
let records = mysql.with_route(routing_policy);

// Without an explicit key, the first SQL argument selects the table AND binds to ?.
let record: Option<Record> = records.fetch_optional(
    "SELECT id, value, metadata_json, deleted_at FROM {{records}} WHERE routing_key = ? AND id = ?",
    (routing_key, id),
).await?;

// An explicit key selects the table without becoming a SQL argument.
records.route(routing_key).execute(
    "UPDATE {{records}} SET value = ? WHERE id = ?",
    (value, id),
).await?;
```

Explicit `.route(key)` takes precedence over the first SQL argument and creates
an independent handle without mutating shared routing state. Retained policies
and keys must be owned/static. Supply every table mapping used by a query,
including joins. Place tokens only at identifier positions; return table names,
not SQL fragments. Routing supports tables within one database, not database
sharding or fanout. Preserve the source's SQL mode; template rendering assumes
MySQL's default quoting/escaping, not `ANSI_QUOTES` or `NO_BACKSLASH_ESCAPES`.

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
