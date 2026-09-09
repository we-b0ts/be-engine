# Call HTTP dependencies through `brz-http`

Recover the source method, URL construction, headers, authentication, body,
timeouts, redirects, response decoding, and error mapping before implementing
an outbound call. Use Breeze's client and response wrappers to retain pooling
and request metrics.

## Dependency

Use the latest stable release from the project's configured Cargo registry and
pin it exactly. Replace `<latest-version>` with the verified release number
without a `v` prefix; it is a placeholder, not a Cargo version expression.
Replace the old Git dependency, preserve registry configuration, and update
`Cargo.lock`.

```toml
[dependencies]
brz-http = { package = "brz-http", version = "=<latest-version>", features = ["metrics", "json"] }
```

Keep the explicit `package` field so the dependency is available as `brz_http::`.
Enable `metrics` for targets; retain `json` when using typed JSON methods. Enable
compression features only when required by the source transport contract.

## Create and reuse clients and endpoints

Create one `Client` per transport policy during startup and retain it for the
process lifetime. Policy includes TLS identity/roots, proxy, redirects, default
headers, timeouts, DNS, and pool settings. One client can serve many hosts;
clones share its connection pool. Do not create a client per request or per host.
Retain an `Endpoint` for each stable URL:

```rust,no_run
use brz_http::{Client, Endpoint, Result};

fn profile_endpoint(service_url: &str) -> Result<Endpoint> {
    let client = Client::builder().build()?;
    // Apply the source's explicit transport overrides before build().
    client.endpoint(format!("{service_url}/v1/profile"))
}
```

Share that client across other endpoints with the same policy. Use
`ClientBuilder::configure` and `RequestBuilder::configure` for uncommon options
while retaining the Breeze wrapper.

Default connect and per-read timeouts are each 400 ms; the read timeout resets
after each successful read. There is no default total timeout. Preserve source
overrides and the caller's deadline with `ClientBuilder::timeout` or
`RequestBuilder::timeout`. `pool_max_idle_per_host` limits idle connections,
not active requests or connection-acquisition wait time.

## Request and response behavior

Build headers, query arguments, auth, and bodies through the request builder.
Use the source's types and operations; the example returns status separately so
the caller can preserve its error mapping:

```rust,no_run
use brz_http::{Endpoint, Result, StatusCode};

async fn load_profile(endpoint: &Endpoint, user_id: u64) -> Result<(StatusCode, String)> {
    let response = endpoint.get().query(&[("uid", user_id)]).send().await?;
    let status = response.status();
    let body = response.text().await?;
    Ok((status, body))
}
```

HTTP 4xx/5xx is a completed HTTP exchange. Use `error_for_status()` only if the
source maps those statuses to an error; otherwise inspect status and body.
Keep transport failure, status failure, body/decoding failure, and a valid empty
body distinct until applying the contract's error mapping.

Use `bytes()`, `text()`, or typed `json()` to consume a complete body. For streaming,
retain the Breeze `Response` and call `chunk()` until it returns `None`; avoid
buffering a forwarded download solely to adapt its type. Dropping an unread body
records an incomplete request in metrics.

Preserve source retries, attempt limits, backoff, idempotency, TLS verification,
proxy bypass, redirect rules, compression, and HTTP version requirements. Do not
add retries or weaken certificate verification to make dependency calls pass.

## Stable metric identities

With `metrics`, endpoint creation registers two `HTTP` rows:

| Name | Timing | Slow threshold |
| --- | --- | --- |
| `<scheme>://<host>/<path>` | Until response headers arrive | 50 ms |
| `all_<scheme>://<host>/<path>` | Until body consumption completes | 200 ms |

Default names omit URL credentials, query, and fragment, but retain dynamic path
values. Use `endpoint_named` with a stable source-compatible metric name when
paths contain IDs:

```rust,ignore
let endpoint = client.endpoint_named(
    format!("{base_url}/v1/users/{user_id}"),
    "http://user-service/v1/users/:id", // Replace with the source's stable identity.
)?;
```

Prefer retained endpoints for stable URLs. Direct `Client::get/post/put/delete`
and `request` support dynamic URLs but register metrics while building requests.
Each logical request counts once per row, including pooled connections and
redirects. HTTP status alone is not a transport failure; transport/body errors,
cancellation, and dropping an unfinished body record failures.

Raw reqwest escape hatches such as `as_reqwest`, `into_reqwest`, or converting
requests/responses bypass or shorten instrumentation. Use them only for a proven
unsupported capability, not for calls that must retain these profile rows.
