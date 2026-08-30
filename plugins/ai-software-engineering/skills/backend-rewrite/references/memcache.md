# Use memcache through `CacheService`

Use this guide when target code reads or writes memcached data through
`brz-memcache`. Follow the standard application shape below. Recover the cache
group, namespace, protocol, expiration, and timeout from source code or
configuration; do not invent them during a rewrite.

## Standard application shape

Create one `CacheService` for each cache dependency during process startup and
retain it for the process lifetime. The normal CacheService path obtains its
namespace configuration through Vintage:

```rust,no_run
use std::time::Duration;

use brz_memcache::{CacheService, CacheServiceOptions};
use brz_vintage::{Client, ClientConfig};

async fn build_cache(
    vintage_endpoint: &str,
    group: &str,
    namespace: &str,
    expiration: Duration,
) -> Result<CacheService, Box<dyn std::error::Error>> {
    let vintage = Client::new(ClientConfig::new(vintage_endpoint)?)?;
    let options = CacheServiceOptions::new(expiration.into());
    Ok(CacheService::from_vintage(vintage, group, namespace, options).await?)
}
```

Pin both dependencies to project-approved revisions and enable memcache's
`service` feature for this construction path:

```toml
brz-memcache = { package = "memcache", git = "ssh://git@git.intra.demo.test:2222/platform/breeze/memcache.git", rev = "<approved-revision>", features = ["service"] }
brz-vintage = { package = "vintage", git = "ssh://git@git.intra.demo.test:2222/platform/breeze/vintage.git", rev = "<approved-revision>" }
```

If the source explicitly uses a local mesh, one fixed endpoint, or an already
parsed fixed `CacheNamespaceConf`, preserve that construction mode. Do not
replace the source topology with a simpler constructor merely to make the
rewrite easier.

## Business code uses only `Memcache`

Pass `&CacheService` into business functions as `&M where M: Memcache`. An
application state may keep `Arc<CacheService>` and pass `cache.as_ref()`; do
not make the whole state generic and do not use the concrete service type in
business signatures.

```rust
use brz_memcache::{CacheEntry, Memcache, Result};
use bytes::Bytes;

async fn load_document<M>(cache: &M, key: &str) -> Result<Option<CacheEntry>>
where
    M: Memcache + ?Sized,
{
    cache.get(key).await
}

async fn store_document<M>(cache: &M, key: &str, value: Bytes) -> Result<bool>
where
    M: Memcache + ?Sized,
{
    cache.set(key, value).await
}
```

The normal expiration belongs in `CacheServiceOptions`, not at each call site.
Business code uses `get` and `set`; do not introduce per-write expiration or
memcached flags.

Preserve these result semantics:

- `get` returning `Ok(None)` is a cache miss; an `Err` is a dependency failure.
- `CacheEntry::data` is binary data. Decode it with the source value format;
  do not assume UTF-8.
- `set` returning `Ok(false)` is a memcached store result, not a transport
  error.

Do not select cache tiers, replicas, or shards in business code, and do not add
an endpoint retry around `get` or `set`. `CacheService` owns those decisions.

## Check before delivery

1. Verify the exact source group, namespace, protocol, expiration, and timeout.
2. Test hit, miss, dependency error, binary decoding, expiration, and both
   boolean store results used by the target.
3. For Vintage-backed configuration, test that a relevant namespace update is
   observed without changing the business call sites.
4. Run the target repository checks and the owning API's Replay/Comparison
   acceptance.
