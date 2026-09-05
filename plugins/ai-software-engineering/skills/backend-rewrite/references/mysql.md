# Use MySQL through `brz-mysql`

Ordinary single-table SELECTs need not reproduce a source ORM's full column
list or generated aliases for Replay. Select the fields the business code
needs and use the names its decoder expects. The engine maps available recorded
fields into that order, resolves table aliases and preserves the remaining
query constraints. COUNT(*) and integer constants retain their expression
identity. Missing recorded fields or unsupported SQL shapes remain evidence or
engine capability issues; do not compensate by consuming recording files in
target code. See [MySQL replay compatibility](../../../../../docs/mysql-replay.md).

Use these examples to integrate MySQL into the target. Keep SQL, result types,
and routing policies in the owning repository. The example tables and routing
rules below are illustrative; substitute the application's actual schema and rules.

## Pin the dependency

```toml
brz-mysql = { git = "ssh://git@git.intra.demo.test:2222/platform/breeze/mysql.git", tag = "v0.0.2" }
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

To defer connecting until the first query, create the service with
`connect_lazy` inside the application's Tokio runtime. The call is synchronous
and needs no `.await`:

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
Invalid URLs/options fail immediately; connection or authentication errors
surface when a query needs a connection. Use the returned service with the same
query, routing, and transaction methods shown below.

## Read and write application types

Business functions can accept `&M where M: Mysql`. Import `Mysql` when calling
trait methods. Derive `FromMysqlRow` on result structs and pass SQL arguments
as tuples; a single argument uses `(value,)`, and no arguments use `()`.

```rust,no_run
use brz_mysql::{FromMysqlRow, Json, Mysql, MysqlResult};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Metadata {
    enabled: bool,
}

#[derive(Debug, FromMysqlRow)]
struct Record {
    id: u64,
    value: String,
    #[mysql(rename = "metadata_json")]
    metadata: Json<Metadata>,
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
for streaming. `Option<T>` represents SQL `NULL`; `Json<T>` reads/writes JSON.
Use `#[mysql(rename = "column")]` when a field and selected column differ.
The example's JSON/date types also require `serde` with `derive` and `chrono`
in the target's dependencies. Preserve the database's numeric signedness and
column types in result fields and arguments.

## Bind a dynamic list of values

For an `IN (...)` query, generate one placeholder per value and pass a homogeneous
`Vec<T>` as the arguments. Handle an empty list before building SQL. Generate
only the placeholders; bind the values instead of interpolating them.

```rust,no_run
use brz_mysql::{FromMysqlRow, Mysql, MysqlResult};

#[derive(FromMysqlRow)]
struct Record {
    id: u64,
    value: String,
}

async fn find_many<M: Mysql>(mysql: &M, ids: &[u64]) -> MysqlResult<Vec<Record>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = vec!["?"; ids.len()].join(", ");
    let sql = format!(
        "SELECT id, value FROM records WHERE id IN ({placeholders}) ORDER BY id"
    );
    mysql.fetch_all(sql, ids.to_vec()).await
}
```

Keep each argument's original type; numeric values do not need converting to
strings. A vector supplies separate arguments, so `IN (?)` does not expand a
vector automatically.

## Retain a routed handle in a repository

`mysql.with_route(policy)` returns an owned `ShardedMysqlService` that implements
`Mysql` and shares the original pool. Ordinary tables use the base service.

```rust,no_run
use brz_mysql::{
    FromMysqlRow, Mysql, MysqlResult, MysqlRoute, MysqlRouteValue, MysqlRouting,
    MysqlService, ShardedMysqlService,
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

#[derive(FromMysqlRow)]
struct Record {
    id: u64,
    value: String,
}

struct Repository {
    mysql: ShardedMysqlService,
}

impl Repository {
    fn new<M: Mysql>(mysql: &M) -> Self {
        Self { mysql: mysql.with_route(ExampleRouting) }
    }

    async fn find(&self, key: u64, id: u64) -> MysqlResult<Option<Record>> {
        // No .route(): the first SQL argument selects the physical table.
        // It is also bound to the first ?; no extra routing argument is added.
        self.mysql.fetch_optional(
            "SELECT id, value FROM {{records}} WHERE routing_key = ? AND id = ?",
            (key, id),
        ).await
    }

    async fn update(&self, key: u64, id: u64, value: &str) -> MysqlResult<()> {
        // Explicit key: value remains the first bound SQL argument.
        self.mysql.route(key).execute(
            "UPDATE records_{{table_suffix}} SET value = ? WHERE id = ?",
            (value, id),
        ).await?;
        Ok(())
    }
}

struct AppState {
    mysql: MysqlService,
    records: Repository,
}

fn build_state(database_url: &str) -> MysqlResult<AppState> {
    let mysql = MysqlService::connect_lazy(database_url)?;
    let records = Repository::new(&mysql);
    // Ordinary queries use state.mysql; routed queries use state.records.
    // Both retain handles to the same pool.
    Ok(AppState { mysql, records })
}
```

An explicit `.route(key)` takes precedence over the first SQL argument. It
returns an independent handle, so concurrent calls do not change the repository's
routing key. Pass owned keys when retaining handles; policies must be `'static`.
The policy defines what its key means, including any decoding of application
identifiers; the component does not infer that rule from the SQL.

Use `records_{{table_suffix}}` with `with_table_suffix`, or `{{records}}` with
`with_table(logical, physical)`. Multiple tokens and joins are supported when
the policy supplies every mapping. Routed service queries require a table token;
plain queries use the base service. Route results are validated identifiers,
not SQL fragments. Templates in strings and ordinary comments are not expanded.
Template rendering does not support `ANSI_QUOTES` or `NO_BACKSLASH_ESCAPES` modes.

## Run a transaction

`with_transaction` commits when the closure returns `Ok` and rolls back on `Err`.
Import `MysqlTransaction` to call transaction query methods. The base service
uses the same closure API for ordinary SQL.

With table sharding, each statement selects its table on the same transaction
connection. Starting a single-database transaction requires no routing key:

```rust,no_run
use brz_mysql::{Mysql, MysqlResult, MysqlTransaction, ShardedMysqlService};

async fn update_together(mysql: &ShardedMysqlService, key: u64, other_key: u64)
    -> MysqlResult<()>
{
    mysql.with_transaction(async |tx| {
        // Route from the first bound argument.
        tx.execute(
            "UPDATE {{records}} SET value = 'updated' WHERE routing_key = ?",
            (key,),
        ).await?;

        // Override the key for this statement only.
        tx.route(other_key).execute(
            "UPDATE {{records}} SET value = ? WHERE id = ?",
            ("another value", 123_u64),
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

All statements commit or roll back together, including statements addressing
different physical tables. A service-bound `.route(key)` supplies a default;
`tx.route(key)` overrides it only for that statement. This release supports
table sharding within one database; database sharding is not implemented.

## Stream rows

Add `futures-util` to the target's dependencies to consume the lazy stream.
Consume or drop it promptly: a polled stream holds a pooled connection.

```rust,no_run
use brz_mysql::{FromMysqlRow, Mysql, MysqlResult};
use futures_util::{StreamExt, pin_mut};

#[derive(FromMysqlRow)]
struct RecordId {
    id: u64,
}

async fn scan<M: Mysql>(mysql: &M, first_id: u64) -> MysqlResult<()> {
    let rows = mysql.fetch::<_, _, RecordId>(
        "SELECT id FROM records WHERE id >= ? ORDER BY id",
        (first_id,),
    );
    pin_mut!(rows);
    while let Some(row) = rows.next().await {
        let row = row?;
        println!("{}", row.id);
    }
    Ok(())
}
```
