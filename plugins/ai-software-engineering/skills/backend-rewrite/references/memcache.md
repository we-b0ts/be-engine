# Use CacheService

- [Construct from Vintage (live)](#construct-from-vintage-live)
- [Use the cache](#use-the-cache)
- [Framework behavior](#framework-behavior)

`brz-memcache::CacheService` is the application-facing memcache facade. It
builds the Java-compatible master/slave/L1 topology from a cache-service
namespace config and exposes the small [`Memcache`](#use-the-cache) contract
(`get`/`set`). Business code depends on `brz_memcache::Memcache` and treats a
`CacheService` as a `Memcache`; it never touches pools, shards, or the wire
protocol directly.

Pin the Git dependency to the project-approved revision and enable the
`service` feature (it pulls in Vintage integration):

```toml
brz-memcache = { package = "memcache", git = "ssh://git@git.intra.demo.test:2222/platform/breeze/memcache.git", rev = "<approved-revision>", features = ["service"] }
```

## Construct from Vintage (live)

For a cache whose backend follows Vintage statics-config changes, use
`CacheService::from_vintage`. This is the common production path: the source
service's `mcClient` reads one namespace of a Vintage-configured cache pool,
and the master list is fetched at startup via a Vintage `/1/config/service`
lookup.

```rust
use brz_memcache::{CacheService, CacheServiceOptions, Memcache};
use brz_vintage as vintage;

// 1. Build the Vintage client (endpoint + group come from pt-config / local
//    config, mirroring the source's mcClient bean).
let vintage_cfg = vintage::ClientConfig::new(format!("http://{vintage_host}:{vintage_port}"))?;
let vintage_client = vintage::Client::new(vintage_cfg)?;

// 2. Build a live CacheService for (group, namespace). The backend is built
//    from the first lookup and hot-swapped when this namespace's config
//    changes; unrelated namespace changes are ignored. CacheService never
//    polls — Vintage pushes updates.
let cache = CacheService::from_vintage(
    vintage_client,
    "<cache-service-group>", // group
    "<namespace>",            // namespace
    CacheServiceOptions::default(),
).await?;
```

The returned `CacheService` owns the whole driver (Vintage subscription +
apply core) for its lifetime; dropping the last clone stops the group's poll.
Business code does not name the Vintage config source type — `from_vintage`
is the entry point.

## Use the cache

The constructor returns a `CacheService`, used through the `Memcache` trait.
`CacheService` owns the full master/slave/L1 topology internally — it handles
master, master-L1, slave, and slave-L1 reads and writes (the Java-compatible
cascade: read tries L1 then master then slave with set-backs; write fans out
across tiers). The caller only calls `get`/`set` and never deals with L1 or
slave separately. The hash/distribution come from the namespace config so each
key routes to the same master the source picks.

```rust
use brz_memcache::Memcache;
use bytes::Bytes;

cache.set("user:1", Bytes::from_static(b"value")).await?;            // Ok(true)
let entry = cache.get("user:1").await?;                              // Ok(Some(CacheEntry{..}))
assert_eq!(entry.unwrap().data, Bytes::from_static(b"value"));
```

`CacheServiceOptions` carries the default expiration and the wire protocol
(`Protocol::Text` by default; `.with_protocol(Protocol::Binary)` to override).

## Framework behavior

- The backend lives behind an `ArcSwap` and is hot-swapped atomically; a
  running `get`/`set` sees the backend that was current when it loaded it.
- On a config change, the namespace is rebuilt only if the parsed config
  actually differs; a comment/format-only change does not rebuild. A rebuild
  failure (bad YAML, unreachable backend) retains the old backend — a bad
  update never breaks the live cache.
- Vintage's subscription unit is the group; the `CacheService` update unit is
  the namespace. Multiple `CacheService`es on the same `(client, group)` share
  one Vintage poll task.
