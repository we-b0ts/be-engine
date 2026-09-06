# Implement inbound APIs with `http-server`

Export business methods with `#[api]` and route macros. Use this shape in
coordinator handoffs and target implementations. Let the component dispatch
routes, bind parameters, and serialize responses. Reuse business types and
keep operations in their owning modules; use the generated `Handler`.

Initialization generates a `ReadinessApi` using these same macros and starts it
with `Server::bind` / `serve_until`. Keep that endpoint and extend the server
with business API modules using `Router::new(ReadinessApi).merge(business_api)`.
Keep the generated SIGTERM/SIGINT handling and logging shutdown lifecycle.

Pin `http-server` to the fixed `v0.0.3` tag and enable `macros` in `Cargo.toml`:

```toml
[dependencies]
http-server = { git = "ssh://git@git.intra.demo.test:2222/platform/breeze/http-server.git", tag = "v0.0.3", features = ["macros"] }
http = "1"
serde = { version = "1", features = ["derive"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread", "signal"] }
futures-util = { version = "0.3", default-features = false, features = ["std"] }
```

## Export and start

Replace the illustrative method bodies with business operations. Call `serve`
from the application entrypoint with its existing authenticator; the server
uses its default configuration. Authentication verifies identity, and methods
use the injected principal for business authorization.

```rust,no_run
use std::io;

use http::StatusCode;
use http_server::{
    ApiError, ApiResult, Authenticated, Authenticator, Bytes, Redirect, Server, Stream, api,
};
use serde::{Deserialize, Serialize};

struct Actor {
    id: u64,
}

#[derive(Serialize)]
struct User<'a> {
    id: u64,
    name: &'a str,
}

#[derive(Deserialize)]
struct UpdateUser<'a> {
    name: &'a str,
}

struct UserApi;

#[api(prefix = "/v1/users", auth = required)]
impl UserApi {
    // GET /v1/users/42?q=Alice+Chen, with an optional X-Trace-ID header.
    #[http_server::get("/:id", headers(trace_id = "x-trace-id"))]
    async fn get<'a>(
        &self,
        id: u64,
        q: &'a str,
        trace_id: Option<&str>,
        actor: Authenticated<Actor>,
    ) -> User<'a> {
        let _ = (trace_id, actor.principal());
        User { id, name: q }
    }

    // PUT /v1/users/42 with application/json: {"name":"Alice Chen"}.
    #[http_server::put("/:id")]
    async fn update<'a>(
        &self,
        id: u64,
        input: UpdateUser<'a>,
        actor: Authenticated<Actor>,
    ) -> ApiResult<(StatusCode, User<'a>)> {
        if actor.principal().id != id {
            return Err(ApiError::forbidden("Cannot update another user"));
        }
        if input.name.trim().is_empty() {
            return Err(ApiError::bad_request("Name is required"));
        }
        Ok((StatusCode::OK, User { id, name: input.name }))
    }

    // Replace this illustrative stream with the HTTP client's response byte stream.
    #[http_server::get("/export")]
    async fn export(&self) -> impl Stream<Item = io::Result<Bytes>> + Send + 'static {
        futures_util::stream::iter([
            Ok(Bytes::from_static(b"id,name\n")),
            Ok(Bytes::from_static(b"42,Alice Chen\n")),
        ])
    }

    #[http_server::get("/login", auth = none)]
    async fn login(&self) -> Redirect {
        Redirect::found("/login")
    }
}

async fn serve<A: Authenticator<Principal = Actor>>(auth: A) -> http_server::Result<()> {
    let server = Server::bind_with_authenticator(
        "0.0.0.0:8080".parse().expect("valid listener address"),
        UserApi,
        auth,
    )
    .await?;
    server
        .serve_until(async {
            tokio::signal::ctrl_c().await.expect("listen for shutdown");
        })
        .await
}
```

Put path parameters first, in capture order, with matching names. Remaining
scalar parameters bind same-named Query keys; `Option<T>` makes a value
optional and `Vec<T>` receives repeated keys. Use `headers(parameter =
"header-name")` for Header bindings. Query values are decoded by the component,
so `q` above receives `Alice Chen`. A terminal `*path` capture receives the
remaining path, for example `#[get("/quota/*path")]` with `path: &str`.

Use a `Deserialize` business struct for JSON input. Its `&str` fields, decoded
Query strings, Header strings, and a raw body parameter `body: &[u8]` can be
borrowed throughout the method, including across `await`. Keep borrowed values
within the request lifetime; use owned values when work must outlive it.
For URL-encoded bodies use `Form<T>`; for file uploads use `Multipart`,
`get("file")`, and `get_all("files")` to access named fields.

Return a serializable business value directly for a 200 JSON response.
Return `(http::StatusCode, T)` to set the status, or `Result<T, E>` /
`ApiResult<T>` for fallible operations; the successful value can also be a
status/body tuple. Map existing business errors with `IntoHttpError`.
Use `Redirect::found(url)` for 302 and `Redirect::temporary(url)` for 307;
the redirect sets `Location` and has an empty body.

Use `auth = optional` with `Option<Authenticated<Actor>>` for optional identity,
and `auth = none` for public endpoints. A service with public endpoints only
starts with `Server::bind(address, api)`.

For downloads, return the HTTP client's response byte stream directly. The
stream must own the upstream response and remain valid until it finishes
(`Send + 'static`); keep the body as a stream throughout forwarding.
The component sends each chunk as it arrives, bounds read-ahead, and drops
the upstream stream when writing fails or the download times out.

Add download metadata with `HttpResponse::new(stream)`: use `.status(status)`
for the upstream status, `.header(name, value)?` for `Content-Type`,
`Content-Disposition`, `Content-Range`, or `Accept-Ranges`, and
`.content_length(length)` when the upstream supplies its exact byte length.
The component selects HTTP framing automatically and verifies a declared
length. Return upstream 206 responses with their matching `Content-Range`.

Combine API modules at startup with `Router::new(user_api).merge(other_api)`
and pass the combined handler to `Server::bind_with_authenticator`.
