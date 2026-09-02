# Use Redis through `RedisService`

Use this guide when target code accesses Redis through `brz-redis`. Follow the
standard application shape below. Recover the source master, read replicas,
sharding rule, command semantics, timeout, and value encoding before changing
target code.

## Standard application shape

Create one `RedisService` for each Redis dependency during process startup and
retain it for the process lifetime. For the common unsharded deployment, pass
the source master and all source read replicas to `noshard_with_options`:

```rust,no_run
use std::time::Duration;

use brz_redis::{RedisResult, RedisService, RedisServiceOptions};

async fn build_redis(
    master: String,
    replicas: Vec<String>,
    timeout: Duration,
) -> RedisResult<RedisService> {
    let options = RedisServiceOptions::default().with_timeout(timeout);
    RedisService::noshard_with_options(master, replicas, options).await
}
```

Pin the dependency to the fixed `v0.0.1` tag and enable `metrics` by default:

```toml
brz-redis = { package = "redis", git = "ssh://git@git.intra.demo.test:2222/platform/breeze/redis.git", tag = "v0.0.1", features = ["metrics"] }
```

Pass source hostnames through unchanged instead of resolving them in
application code. If the source defines multiple shards, construct a sharded
service with the exact source shard membership and `ShardRouting`; do not
flatten it into an unsharded service. Use mesh or single-endpoint construction
only when that is the source dependency mode.

## Business code uses only `Redis`

Pass `&RedisService` into business functions as `&R where R: Redis`. An
application state may keep `Arc<RedisService>` and pass `redis.as_ref()`; do
not make the whole state generic. The `Redis` trait has generic methods, so do
not use `dyn Redis`.

```rust
use brz_redis::{Redis, RedisBytes, RedisResult};

async fn load_document<R>(redis: &R, key: &str) -> RedisResult<Option<RedisBytes>>
where
    R: Redis,
{
    redis.get(key).await
}
```

Choose the response type from the source data contract: use `RedisBytes` for
binary data, `String` only for UTF-8 text, and a supported integer type for a
decimal integer. Preserve `Option<V>`: `None` is a Redis nil response, while
an error is a command or dependency failure.

## Encode keys without temporary strings

Keys and values only need to implement `EncodeRedisArg`. Integers encode as
decimal text. Use `RedisKey2` or `RedisKey3` for fixed concatenations instead
of `format!` or `to_string`; the wrapper adds no separators of its own:

```rust
use brz_redis::{Redis, RedisKey3, RedisResult};

async fn load_profile<R>(redis: &R, user_id: u64) -> RedisResult<Option<String>>
where
    R: Redis,
{
    redis.get(RedisKey3("user:", user_id, ":profile")).await
}
```

Use `get_routed` or `set_routed` only when source behavior deliberately hashes
on a routing key different from the encoded Redis key. Preserve that routing
key; do not invent a new sharding rule.

For `hmget`, consume `RedisValues` in requested-field order. Missing fields
remain `None` and do not shift later values:

```rust
use brz_redis::{Redis, RedisBytes, RedisResult};

async fn load_fields<R>(
    redis: &R,
    key: &str,
) -> RedisResult<Vec<Option<RedisBytes>>>
where
    R: Redis,
{
    redis
        .hmget::<_, _, RedisBytes>(key, ["title", "owner"])
        .await?
        .collect()
}
```

## Preserve call behavior

Use ordinary typed calls by default. Add a pipeline only when the source
already batches independent commands; consume its responses in command order.
Do not pipeline a multi-shard service, and do not use a pipeline as a retry
mechanism.

Do not add endpoint selection or blind command retries in business code.
RedisService handles read failover. A failed write may already have executed,
so replay it only when source application behavior explicitly requires that
and duplicate execution is acceptable.

## Check before delivery

1. Verify master, replicas, timeout, and—when present—shard membership and
   routing match the source.
2. Test hit, nil, dependency error, and every response type and command used by
   the target.
3. Test that composite keys encode byte-for-byte like the source and routed
   calls use the source routing key.
4. If source code uses a pipeline, test response order and the target's error
   handling.
5. Run the target repository checks and the owning API's Replay/Comparison
   acceptance.
