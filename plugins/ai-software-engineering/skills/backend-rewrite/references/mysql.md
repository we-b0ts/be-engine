# Use MySQL through `brz-mysql`

Use `brz-mysql` for connection pooling, typed queries, transactions and table
routing. These examples show how to query application types, bind values and
share a service across repositories. Substitute the application's tables,
fields and routing rules in each example.

## Pin the dependency

```toml
brz-mysql = { git = "ssh://git@git.intra.demo.test:2222/platform/breeze/mysql.git", tag = "v0.0.4" }
```

## Create and share the service

Create a service at startup for each MySQL dependency and retain it for the
process lifetime. Clones and routed handles share its connection pool.

```rust,no_run
use std::time::Duration;
use brz_mysql::{MysqlResult, MysqlService, MysqlServiceOptions};

async fn connect(database_url: &str) -> MysqlResult<MysqlService> {
    let options = MysqlServiceOptions::default()
        .with_max_connections(30)
        .with_acquire_timeout(Duration::from_secs(5));
    MysqlService::connect_with_options(database_url, options).await
}
```

For defaults, use `MysqlService::connect(database_url).await?`. Options configure
pool/session settings, including charset and timezone. When reducing the
acquisition timeout below the default 2-second slow-acquire threshold, lower
`slow_acquire_threshold` too. Close the shared service once at application
shutdown with `mysql.close().await`.

To defer connecting until the first query, call the synchronous `connect_lazy`
inside the application's Tokio runtime:

```rust,no_run
use brz_mysql::{MysqlResult, MysqlService, MysqlServiceOptions};

fn connect_lazy(database_url: &str) -> MysqlResult<MysqlService> {
    MysqlService::connect_lazy(database_url)
}

fn connect_lazy_with_options(database_url: &str) -> MysqlResult<MysqlService> {
    let options = MysqlServiceOptions::default()
        .with_max_connections(30)
        .with_min_connections(0);
    MysqlService::connect_lazy_with_options(database_url, options)
}
```

Keep `min_connections` at zero (the default) to defer connection creation.
Use the returned service with the same query, routing and transaction methods
shown below.

## Read and write application types

Use statically dispatched generics (`M: Mysql`) and accept `&M` in business
query and transaction functions. Both `MysqlService` and `ShardedMysqlService`
implement this trait. Import `Mysql` when calling trait methods.
Derive `FromMysqlRow` directly on the business struct a query
returns, or implement the trait to construct that business type. Select its
required fields and use stable column names or aliases for decoding.

Pass SQL arguments as tuples; a single argument uses `(value,)`, and no
arguments use `()`. The `Record` business type below is defined once and reused
by the later collection and routing examples.

```rust,no_run
use brz_mysql::{FromMysqlCol, FromMysqlRow, Mysql, MysqlResult};
use serde::Deserialize;

#[derive(Debug, Deserialize, FromMysqlCol)]
struct Metadata {
    enabled: bool,
}

#[derive(Debug, FromMysqlRow)]
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

async fn update<M: Mysql>(mysql: &M, id: u64, value: &str) -> MysqlResult<u64> {
    let result = mysql.execute(
        "UPDATE records SET value = ? WHERE id = ?",
        (value, id),
    ).await?;
    Ok(result.rows_affected)
}
```

`fetch_optional` returns `None` for absence; `fetch_one` returns
`MysqlError::RowNotFound`. Use `fetch_all` for bounded collections and `fetch`
for streaming. Use `Option<T>` for a nullable field. Deriving `FromMysqlCol`
alongside `Deserialize` decodes a JSON column directly into that field's type.
`Json<T>` also supports typed JSON reads and writes.
Use `#[mysql(rename = "column")]` when a field and selected column differ.
The example's JSON/date types also require `serde` with `derive` and `chrono`
in the application's dependencies. Preserve the database's numeric signedness and
column types in result fields and arguments.

## Read a single column or a tuple

Choose the result shape through the return type. A scalar reads one column;
a tuple of 1 to 16 elements reads the same number of columns in SELECT order.
Both use `FromMysqlCol` for column decoding.

```rust,no_run
use brz_mysql::{Mysql, MysqlResult};
use chrono::NaiveDateTime;

async fn owner_id<M: Mysql>(mysql: &M, task_id: u64) -> MysqlResult<Option<i64>> {
    mysql.fetch_optional(
        "SELECT user_id FROM tasks WHERE id = ? LIMIT 1",
        (task_id,),
    ).await
}

async fn user_name<M: Mysql>(mysql: &M, user_id: u64)
    -> MysqlResult<Option<(u64, String)>>
{
    let row: Option<(u64, String)> = mysql.fetch_optional(
        "SELECT id, name FROM users WHERE id = ?",
        (user_id,),
    ).await?;
    Ok(row)
}

async fn user_summary<M: Mysql>(mysql: &M, user_id: u64)
    -> MysqlResult<Option<(u64, String, Option<NaiveDateTime>)>>
{
    mysql.fetch_optional(
        "SELECT id, name, deleted_at FROM users WHERE id = ?",
        (user_id,),
    ).await
}

async fn user_ids<M: Mysql>(mysql: &M, team_id: u64) -> MysqlResult<Vec<u64>> {
    mysql.fetch_all(
        "SELECT user_id FROM team_members WHERE team_id = ? ORDER BY user_id",
        (team_id,),
    ).await
}
```

`FromMysqlCol` supports `i8` through `i64`, `u8` through `u64`, `isize`/`usize`, `f32`/`f64`,
`bool`, `String`, `Vec<u8>`, Chrono's `NaiveDate`, `NaiveDateTime` and `NaiveTime`,
decimal values, JSON types and `Option<T>`. The outer `Option` returned by
`fetch_optional` represents row presence; an inner `Option<T>` represents SQL
NULL. For one nullable column, use `Option<Option<T>>` as the optional result.

## Read a JSON column as a business type

Derive `Deserialize` and `FromMysqlCol` on a JSON business type. It can be the
entire single-column result, a tuple element or a field of a `FromMysqlRow`
business struct. JSON is deserialized while decoding the column.

```rust,no_run
use brz_mysql::{FromMysqlCol, Mysql, MysqlResult};
use serde::Deserialize;

#[derive(Debug, Deserialize, FromMysqlCol)]
struct Settings {
    enabled: bool,
    labels: Vec<String>,
}

async fn settings<M: Mysql>(mysql: &M, user_id: u64) -> MysqlResult<Option<Settings>> {
    mysql.fetch_optional(
        "SELECT settings FROM users WHERE id = ?",
        (user_id,),
    ).await
}

async fn user_settings<M: Mysql>(mysql: &M, user_id: u64)
    -> MysqlResult<Option<(u64, Settings)>>
{
    mysql.fetch_optional(
        "SELECT id, settings FROM users WHERE id = ?",
        (user_id,),
    ).await
}
```

Use `FromMysqlRow` for a business struct whose fields come from named SQL
columns. Use `FromMysqlCol` for a business type stored in a single JSON column.
For flexible JSON, choose `serde_json::Value`; for an existing `Deserialize`
type, `Json<T>` provides the same typed decoding without another derive.

## Bind a dynamic list of values

For an `IN (...)` query, generate one placeholder per value and pass a homogeneous
`Vec<T>` as the arguments. Handle an empty list before building SQL. Generate
only the placeholders; bind the values instead of interpolating them.

```rust,no_run
use brz_mysql::{Mysql, MysqlResult};
// Import the application's Record business type shown above.

async fn find_many<M: Mysql>(mysql: &M, ids: &[u64]) -> MysqlResult<Vec<Record>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = vec!["?"; ids.len()].join(", ");
    let sql = format!(
        "SELECT id, value, metadata_json, deleted_at FROM records WHERE id IN ({placeholders}) ORDER BY id"
    );
    mysql.fetch_all(sql, ids.to_vec()).await
}
```

Bind each argument with its original type. A vector supplies one argument per
element; generate the same number of SQL placeholders.

Replay supports source text SQL with inline literals and target prepared SQL
with `?` parameters. For ordinary single-table SELECTs it compares IN/NOT IN
lists without requiring the same value order, and accepts reordered pure AND
conditions after binding actual values. Do not reproduce source set iteration
order or sort target inputs solely for Replay. Exact values, types, NULL and
duplicate counts remain constrained, as do tables, ordering and pagination.
This built-in compatibility composes with direct-column projection mapping;
it requires no rule or new recording. Complex expressions and positional
dynamic-parameter policies keep their existing boundaries. See
[MySQL predicate compatibility](../../../../../docs/mysql-replay.md#select-predicate-order-compatibility).

Flat tuple IN/NOT IN supports whole-tuple reordering for forms such as
`(user_id,namespace,name) IN ((?,?,?),(?,?,?))`, including source SQL built from
set iteration. Preserve each tuple's field order, paired values, types and
duplicate count; use normal bound parameters. A repair still needs the affected
immutable cases rerun; an engine revision change alone is not functional acceptance.

## Query sharded tables

`mysql.with_route(policy)` returns an owned `ShardedMysqlService` that implements
`Mysql` and shares the original pool. Create and reuse this handle, then pass it
to query functions taking `&M where M: Mysql`. Apply an explicit `.route(key)`
to the handle before passing it to a query function. Ordinary tables use the
base service through the same `Mysql` trait.

```rust,no_run
use brz_mysql::{
    Mysql, MysqlResult, MysqlRoute, MysqlRouteValue, MysqlRouting,
};

struct ExampleRouting;

impl MysqlRouting for ExampleRouting {
    fn resolve(&self, key: MysqlRouteValue<'_>) -> MysqlResult<MysqlRoute> {
        let suffix = format!("{:02}", key.as_u64()? % 16);
        MysqlRoute::new()
            .with_table_suffix(&suffix)?
            .with_table("records", format!("records_{suffix}"))
    }
}

// Import the application's Record business type shown above.

async fn find_sharded<M: Mysql>(mysql: &M, key: u64, id: u64)
    -> MysqlResult<Option<Record>>
{
    // The first SQL argument selects the physical table and binds to the first ?.
    mysql.fetch_optional(
        "SELECT id, value, metadata_json, deleted_at FROM {{records}} WHERE routing_key = ? AND id = ?",
        (key, id),
    ).await
}

async fn update_sharded<M: Mysql>(mysql: &M, id: u64, value: &str) -> MysqlResult<()> {
    mysql.execute(
        "UPDATE records_{{table_suffix}} SET value = ? WHERE id = ?",
        (value, id),
    ).await?;
    Ok(())
}

async fn use_routing<M: Mysql>(mysql: &M, key: u64, id: u64) -> MysqlResult<()> {
    let sharded = mysql.with_route(ExampleRouting);
    let record = find_sharded(&sharded, key, id).await?;
    if record.is_some() {
        // Explicit key: value remains the first bound SQL argument.
        update_sharded(&sharded.route(key), id, "updated").await?;
    }
    Ok(())
}
```

An explicit `.route(key)` takes precedence over the first SQL argument. It
returns an independent handle for that key; concurrent calls can share the
original handle. Pass owned keys when retaining handles; policies must be `'static`.
The policy defines what its key means, including any decoding of application
identifiers.

Use `records_{{table_suffix}}` with `with_table_suffix`, or `{{records}}` with
`with_table(logical, physical)`. Multiple tokens and joins are supported when
the policy supplies every mapping. Routed service queries require a table token;
plain queries use the base service. Return table identifiers from routing
policies. Place template tokens at SQL identifier positions; the renderer uses
MySQL's default quoting and escape rules.

## Run a transaction

Keep ordinary read requests on the shared pool. Source ORMs may close an
implicit read-only session with ROLLBACK. The engine allows this cleanup to be
omitted when semantic recording proves a transaction-free start, consecutive
ordinary reads, and a successful transaction end; repeated cleanup after a
confirmed COMMIT/ROLLBACK is also optional. Omitted cleanup is reported as
`allowed_unused_mysql_rollback_exchanges`. No rule is needed.

Cold source connections may also send `SET AUTOCOMMIT=0/1` before business
queries. Replay handles literal session assignments and tracks the target
connection's mode. Proven read-only source-session setup can be omitted and is
reported as `allowed_unused_mysql_autocommit_exchanges`. Do not add AUTOCOMMIT
assignments to a shared target pool just to consume source-driver setup. No
rule or new recording is needed when existing evidence contains the required
transaction status. Write-containing sessions, failed assignments and incomplete
evidence remain strict; inspect the evidence and route an engine capability
gap if ordinary driver behavior is still blocked. Preserve real business
transaction boundaries.

Do not add `mysql.execute("ROLLBACK", ())` to the end of every handler merely
to consume recording evidence. A pool can route that command to another
connection. Missing status evidence in an older recording requires fresh
recording through the coordinator workflow; unexplained failures remain an
engine investigation. Writes, locks and explicit business transactions retain
their required rollback/commit behavior, even when HTTP responses agree.

`with_transaction` commits when the closure returns `Ok` and rolls back on `Err`.
Import `MysqlTransaction` to call transaction query methods. The base service
uses the same closure API for ordinary SQL.

With table sharding, start a transaction on the shared database connection;
each statement selects its table using its own routing key:

```rust,no_run
use brz_mysql::{Mysql, MysqlResult, MysqlTransaction};

async fn update_together<M: Mysql>(mysql: &M, key: u64, other_key: u64)
    -> MysqlResult<()>
{
    mysql.with_transaction(async |tx| {
        // Route from the first bound argument.
        tx.execute(
            "UPDATE {{records}} SET value = 'updated' WHERE routing_key = ?",
            (key,),
        ).await?;

        // This statement's first argument selects another shard.
        tx.execute(
            "UPDATE {{records}} SET value = 'another value' WHERE routing_key = ?",
            (other_key,),
        ).await?;

        // Ordinary SQL also runs on this transaction's connection.
        tx.execute(
            "UPDATE settings SET enabled = ? WHERE id = ?",
            (true, 1_u64),
        ).await?;
        Ok(())
    }).await
}
```

Pass the handle from `mysql.with_route(policy)` to `update_together` for
per-statement routing by the first SQL argument. A handle with `.route(key)`
binds its explicit key for the transaction. All statements commit or roll back
together, including statements addressing different physical tables. This
release supports table sharding within one database.

## Stream rows

Add `futures-util` to the application's dependencies to consume the lazy stream.
Consume or drop it promptly: a polled stream holds a pooled connection.

```rust,no_run
use brz_mysql::{Mysql, MysqlResult};
use futures_util::{StreamExt, pin_mut};

async fn scan<M: Mysql>(mysql: &M, first_id: u64) -> MysqlResult<()> {
    let ids = mysql.fetch::<_, _, u64>(
        "SELECT id FROM records WHERE id >= ? ORDER BY id",
        (first_id,),
    );
    pin_mut!(ids);
    while let Some(id) = ids.next().await {
        println!("{}", id?);
    }
    Ok(())
}
```
