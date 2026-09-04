# Use MySQL through `MysqlService`

Use this guide when target code accesses MySQL through `brz-mysql`. Recover the
source connection URL, pool policy, transaction boundaries, SQL, argument and
column types, and any physical table-selection rule before changing target
code. Keep repository and domain policy in the target; `MysqlService` owns the
driver, pool, parameter binding, row decoding, and physical table selection.

## Standard application shape

Create one `MysqlService` for each MySQL dependency during process startup and
retain it for the process lifetime:

```rust,no_run
use std::time::Duration;

use brz_mysql::{MysqlResult, MysqlService, MysqlServiceOptions};

async fn build_mysql(database_url: &str) -> MysqlResult<MysqlService> {
    let options = MysqlServiceOptions::default()
        .with_max_connections(30)
        .with_acquire_timeout(Duration::from_secs(1));
    MysqlService::connect_with_options(database_url, options).await
}
```

Pin the dependency to the fixed `v0.0.1` tag:

```toml
brz-mysql = { package = "brz-mysql", git = "ssh://git@git.intra.demo.test:2222/platform/breeze/mysql.git", tag = "v0.0.1" }
```

The current service uses one read/write pool, matching Wegent's present
deployment. Do not add reader selection in repositories. Future read/write
separation belongs inside `MysqlService` so consumer query signatures remain
unchanged.

## Business code uses only `Mysql`

Pass `&MysqlService` into business functions as `&M where M: Mysql`. Keep SQL
and result structs in the owning repository or feature module. Do not expose
`sqlx` types through business signatures.

Derive `FromMysqlRow` on a named struct so `fetch_one`, `fetch_optional`,
`fetch`, and `fetch_all` return application types directly:

```rust,no_run
use brz_mysql::{FromMysqlRow, Json, Mysql, MysqlResult};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct TaskConfig {
    retryable: bool,
}

#[derive(Debug, FromMysqlRow)]
struct Task {
    id: u64,
    title: String,
    #[mysql(rename = "config_json")]
    config: Json<TaskConfig>,
    deleted_at: Option<chrono::NaiveDateTime>,
}

async fn load_task<M>(mysql: &M, task_id: u64) -> MysqlResult<Task>
where
    M: Mysql,
{
    mysql
        .fetch_one(
            "SELECT id, title, config_json, deleted_at FROM tasks WHERE id = ?",
            (task_id,),
        )
        .await
}
```

Use `#[mysql(rename = "column_name")]` only when the Rust field and selected
column differ. A non-optional field rejects SQL `NULL`; `Option<T>` preserves
it. `Json<T>` serializes into the final MySQL argument buffer and decodes a JSON
column without an intermediate application string.

Arguments implement `MysqlArgs`. Use heterogeneous tuples for normal queries;
the encoder writes values directly into SQLx's final MySQL argument buffer
instead of collecting an intermediate `Vec<MysqlValue>`. Preserve exact source
numeric signedness, date/time handling, bytes versus text, decimal precision,
and NULL behavior.

## Choose the bounded result shape

- Use `fetch_optional` when no row is valid and distinct from a dependency
  error.
- Use `fetch_one` when absence is `MysqlError::RowNotFound`.
- Use lazy `fetch` for large or performance-sensitive result sets; consume or
  drop it promptly because the stream owns one pooled connection while active.
- Use `fetch_all` only when the result is known to be bounded.

The lazy stream is returned as `impl Stream`; do not box it merely to satisfy
repository plumbing.

## Keep transaction completion service-owned

Use `with_transaction` rather than exposing or wrapping begin, commit, or
rollback. Returning `Ok` commits and returning `Err` rolls back. Preserve the
source transaction's statement ordering and error mapping, and do not perform
unrelated remote I/O while holding the transaction connection.

```rust,no_run
# use brz_mysql::{MysqlResult, MysqlService};
# async fn rename(mysql: &MysqlService, task_id: u64) -> MysqlResult<()> {
mysql
    .with_transaction(async |transaction| {
        transaction
            .execute(
                "UPDATE tasks SET title = ? WHERE id = ?",
                ("new title", task_id),
            )
            .await?;
        Ok(())
    })
    .await?;
# Ok(())
# }
```

## Preserve physical table selection

When the source uses physical table partitions, configure
`MysqlTableSharding` once in `MysqlServiceOptions`. SQL names the logical table
as `{{table_name}}`; the configured selector receives the first SQL argument
and returns `Base` or `Shard(index)`. That first argument is still bound to the
first `?` placeholder. Do not add a separate routing parameter, repository
fan-out method, or dynamic physical table name.

```rust,no_run
use brz_mysql::{
    MysqlSelectorValue, MysqlServiceOptions, MysqlTableSelection,
    MysqlTableSharding,
};

let sharding = MysqlTableSharding::new(
    16,
    ["tasks"],
    |first: MysqlSelectorValue<'_>| {
        Ok(MysqlTableSelection::Shard((first.as_u64()? % 16) as u32))
    },
)?;
let options = MysqlServiceOptions::default().with_table_sharding(sharding);
# Ok::<(), brz_mysql::MysqlError>(())
```

Every query through that service must contain a configured logical-table token
and a first argument suitable for the selector. `MysqlService` precomputes and
validates physical names before replacing the token.

## Check before delivery

1. Verify the source URL, charset, timezone, pool limits, acquisition
   timeout, idle lifetime, and connection ownership.
2. Verify every SQL statement, argument type/order, selected column, NULL
   behavior, row-not-found mapping, and database error used by the target.
3. Test derived structs, JSON, binary/text and date/time values, writes,
   optional and multi-row reads, and transaction commit and rollback.
4. For table selection, test the first-argument mapping and emitted physical
   table for representative keys, including invalid selections.
5. Run the target repository checks and the owning API's Replay/Comparison
   acceptance.
