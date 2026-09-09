# Call HTTP dependencies through `brz-http`

Use this guide when target code calls an outbound HTTP dependency through
`brz-http`. Recover the source method, URL construction, headers,
authentication, request body, timeout, redirect policy, response decoding, and
error mapping before changing target code.

## Standard application shape

Create one `Client` for each transport policy during process startup and retain
it for the process lifetime. A transport policy includes TLS identity and
roots, proxy and redirect behavior, connect and read timeouts, default headers,
DNS behavior, and connection-pool settings. One client can serve many hosts;
its underlying reqwest pool partitions connections by origin, so do not create
one client per host or per request.

Create and retain an `Endpoint` for every stable route. `Client` and `Endpoint`
are cheap to clone:

```rust,no_run
use std::time::Duration;

use brz_http::{Client, Endpoint, Result};

struct HttpDependencies {
    user_profile: Endpoint,
}

fn build_http_dependencies(user_service_url: &str) -> Result<HttpDependencies> {
    let client = Client::builder()
        .connect_timeout(Duration::from_millis(400))
        .read_timeout(Duration::from_millis(400))
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(16)
        .build()?;
    let user_profile = client.endpoint(format!("{user_service_url}/v1/profile"))?;
    Ok(HttpDependencies { user_profile })
}
```

Pin the dependency to the fixed `v0.0.2` tag. Enable `metrics` by default and
enable `json` when using the typed JSON body methods:

```toml
brz-http = { package = "http", git = "ssh://git@git.intra.demo.test:2222/platform/breeze/http.git", tag = "v0.0.2", features = ["json", "metrics"] }
```

Use `ClientBuilder::configure` for an uncommon reqwest transport option while
retaining the Breeze wrapper. Keep separately configured clients only when the
source transport policies actually differ.

## Keep metric identities stable

`Client::endpoint` derives a metric name from the URL after removing
credentials, query parameters, and fragments. It does not remove dynamic path
segments. When a route contains user IDs or other high-cardinality path values,
use `endpoint_named` with the stable source-compatible metric name:

```rust,no_run
# use brz_http::{Client, Endpoint, Result};
# fn user_profile_endpoint(
#     client: &Client,
#     base_url: &str,
#     user_id: u64,
# ) -> Result<Endpoint> {
client.endpoint_named(
    format!("{base_url}/v1/users/{user_id}"),
    "http://user-service/v1/users/:id",
)
# }
```

Prefer a retained `Endpoint` for every route known at startup. Direct
`Client::get`, `post`, `put`, `delete`, or `request` calls support genuinely
dynamic URLs, but with the `metrics` feature they register metrics while
building the request.

## Preserve request and response semantics

Build headers, query parameters, authentication, and bodies through the Breeze
request builder, then consume the response body through the Breeze `Response`:

```rust,no_run
use brz_http::{Endpoint, Result};

async fn load_profile(endpoint: &Endpoint, user_id: u64) -> Result<String> {
    endpoint
        .get()
        .query(&[("uid", user_id)])
        .send()
        .await?
        .error_for_status()?
        .text()
        .await
}
```

Receiving an HTTP 4xx or 5xx status is a completed HTTP exchange, not a
transport error. Call `error_for_status` only when the source client maps those
statuses to its error path. Otherwise inspect the status and body explicitly.
Preserve distinctions between transport failure, status failure, body read or
decode failure, and a valid empty body until the target's external error mapping
is complete.

Read the complete body with `bytes`, `text`, or `json`, or drive `chunk` until
it returns `None`. Dropping a response before EOF is treated as an incomplete
body and records a failed whole-request metric. Use `RequestBuilder::configure`
for an uncommon reqwest request option without discarding instrumentation.

Do not add retries in business code merely to mask a dependency failure.
Preserve source retry eligibility, attempt limit, backoff, total budget, and
idempotency behavior. In particular, do not automatically retry a request
whose body may already have been accepted by the remote service.

## Preserve timeout and transport policy

The default `Client` matches the api-commons `ApacheHttpClient()` transport
timeouts:

- connect timeout: 400 ms;
- per-read timeout: 400 ms, reset after each successful socket read;
- no default total-request timeout.

Recover explicit source overrides and the caller's overall deadline. Apply a
shared total timeout through `ClientBuilder::timeout`, a request-specific total
timeout through `RequestBuilder::timeout`, or retain the caller-owned deadline
when that is the established contract. Do not confuse
`pool_max_idle_per_host` with an active-connection admission limit.

Preserve source TLS roots and identity, proxy bypass rules, redirect behavior,
default headers, compression support, HTTP version requirements, and DNS
overrides. Do not use `danger_accept_invalid_certs` or disable hostname
verification to make a dependency call pass.

## Metrics behavior

With the `metrics` feature, constructing an endpoint registers two
ProfileUtil-compatible `HTTP` rows:

- `<scheme>://<host>/<path>`, with a 50 ms slow threshold, measured until
  response headers arrive;
- `all_<scheme>://<host>/<path>`, with a 200 ms slow threshold, measured until
  the response body reaches EOF.

Each logical request increments both rows once even when the underlying client
reuses a connection or follows redirects. HTTP status alone does not increment
`error_count`; transport errors, body errors, cancellation, and dropping the
body before EOF do.

Calling `Client::as_reqwest`, converting the client with `into_reqwest`, or
converting a request or response into raw reqwest escapes the instrumentation
contract. Use those escape hatches only for a proven unsupported capability,
and do not use them when the target must produce the corresponding HTTP profile
rows.
