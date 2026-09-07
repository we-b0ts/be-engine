# Implement inbound APIs with `http-server`

When implementing a target API, export its business methods with `#[api]` and
route macros, register it in the listener's group, and construct the
listener's handler with `handlers!(state)?`. Match the assigned API contract
for paths, methods, inputs, authentication, and responses.
Reuse business types and keep operations in their owning modules. Use the
generated `Handler` for routing, parameter binding, and response serialization.

## Configure dependencies

Use `http-server` at the fixed `v0.0.6` tag and enable `macros` in `Cargo.toml`:

```toml
[dependencies]
http-server = { git = "ssh://git@git.intra.demo.test:2222/platform/breeze/http-server.git", tag = "v0.0.6", features = ["macros"] }
http = "1"
serde = { version = "1", features = ["derive"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread", "signal"] }
futures-util = { version = "0.3", default-features = false, features = ["std"] }
```

## Declare the listener's group

Declare the default group once in the crate root, using the project's
state and authenticator types. Keep each API module in the normal Rust module
tree with `mod`; an unreferenced source file does not register an API.

Use the project's actual state type and module path; adapt the illustrative
`AppState` and `crate::state` imports below. Provide `FromState<S>` for the
exact declared type `S` (for example, `Arc<AppState>`), using the derive below
when retaining the whole state. For API-specific
dependencies or custom construction, implement the trait manually and choose
the fields you need. Keep normal Rust visibility for access between modules.

```rust,ignore
use std::sync::Arc;

use crate::auth::{Actor, AppAuth};
use crate::state::AppState;

mod user_api;

http_server::registry!(state = Arc<AppState>, auth = AppAuth);
```

Here `AppAuth` implements `Authenticator<Principal = Actor>`. For a public-only
listener, omit `auth = AppAuth` and bind it with `Server::bind`.

## Implement the API methods

Adapt the following example to the assigned contract. Replace the illustrative
types and method bodies with the target's business types and operations. Use
the project's authenticator and principal type, and enforce business
authorization inside the methods.

Use `auth = required` with `Authenticated<Actor>` when identity is required,
`auth = optional` with `Option<Authenticated<Actor>>` for optional identity,
and `auth = none` for public endpoints.

Write `#[api(...)]` to register the API in the default group. For an API whose
only field is named `state`, add `#[derive(http_server::FromState)]` to the
struct. Use the group's exact state type for that field; it may be private
and must implement `Clone`. An `Arc<AppState>` field does not require
`AppState: Clone`.

When initializing additional fields or selecting individual dependencies,
omit the derive and implement `FromState<S>` manually. Construct the API from
dependencies already initialized at startup. The example below retains the
application's shared state.

```rust,ignore
// user_api.rs
use std::{io, sync::Arc};

use http::StatusCode;
use http_server::{ApiError, ApiResult, Authenticated, Bytes, Redirect, Stream, api};
use serde::{Deserialize, Serialize};

use crate::{Actor, AppState};

#[derive(Serialize)]
struct User<'a> {
    id: u64,
    name: &'a str,
}

#[derive(Deserialize)]
struct UpdateUser<'a> {
    name: &'a str,
}

#[derive(http_server::FromState)]
struct UserApi {
    state: Arc<AppState>,
}

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
```

## Bind request inputs

Use `:name` for a single path segment, including parameters followed by a static
suffix, such as `#[http_server::get("/:id/content")]` with `id: u64`.
Put path parameters first, in capture order, with matching names. Remaining
scalar parameters bind same-named query keys; use `Option<T>` for an optional
value and `Vec<T>` for repeated keys. Use `headers(parameter = "header-name")`
for header bindings. Consume decoded query values directly; `q` above receives
`Alice Chen`. To capture the remaining path, use a terminal `*path`, for example
`#[http_server::get("/quota/*path")]` with `path: &str`.

Use a `Deserialize` business struct for JSON input. Its `&str` fields, decoded
Query strings, Header strings, and a raw body parameter `body: &[u8]` can be
borrowed throughout the method, including across `await`. Keep borrowed values
within the request lifetime; use owned values when work must outlive it.
For URL-encoded bodies use `Form<T>`; for file uploads use `Multipart`,
`get("file")`, and `get_all("files")` to access named fields.

## Return the contract's response

Return a serializable business value directly for a 200 JSON response.
Return `(http::StatusCode, T)` to set the status, or `Result<T, E>` /
`ApiResult<T>` for fallible operations; the successful value can also be a
status/body tuple. Map existing business errors with `IntoHttpError`.
Use `Redirect::found(url)` for 302 and `Redirect::temporary(url)` for 307;
the redirect sets `Location` and has an empty body.

## Forward downloads as streams

For downloads, return the HTTP client's response byte stream directly. The
stream must own the upstream response and remain valid until it finishes
(`Send + 'static`); keep the body as a stream throughout forwarding.

Add download metadata with `HttpResponse::new(stream)`: use `.status(status)`
for the upstream status, `.header(name, value)?` for `Content-Type`,
`Content-Disposition`, `Content-Range`, or `Accept-Ranges`, and
`.content_length(length)` when the upstream supplies its exact byte length.
Let the component select HTTP framing. Return upstream 206 responses with
their matching `Content-Range`.

## Connect the group to the generated server

After initializing the project's `Arc<AppState>` and authenticator, collect
the registered business APIs once. Keep the generated `ReadinessApi` endpoint
by marking its API implementation `#[api(register = false)]` (retain any
other API options) and merging its instance:

```rust,ignore
let handler = http_server::Router::new(readiness_api)
    .merge(http_server::handlers!(state)?);

let server = http_server::Server::bind_with_authenticator(address, handler, auth).await?;
```

New business APIs need their module declaration, a derived or manual
`FromState` implementation,
and `#[api(...)]`; keep the startup expression unchanged. Do not also
merge an API instance that is already registered. If readiness is itself
registered with `FromState`, omit `register = false` and use only
`let handler = http_server::handlers!(state)?;`.

Propagate `RegistryError` from `handlers!` through the existing startup error
path. Resolve conflicting routes in their owning modules: routes with equal
priority that overlap on both path and HTTP method cannot share a group.
Do not depend on registration order to choose a handler.

## Bind another group to a separate listener

Declare a named group for the second listener. Set `group = admin` on its APIs
and select it with `handlers!(state, admin)?`. Use the listener's own
authenticator type; it may differ from the default group's authenticator.

```rust,ignore
// Crate root; reuse the listener's actual state and authenticator types.
use crate::auth::AdminAuth;

http_server::registry!(group = admin, state = Arc<AppState>, auth = AdminAuth);

// On the API implementation in its module:
#[http_server::api(prefix = "/admin", group = admin, auth = required)]
impl AdminApi {
    // Annotated business methods using AdminAuth's principal type.
    // AdminApi implements FromState<Arc<AppState>>.
}

// Startup: address and admin_address are distinct configured SocketAddr values.
let handler = http_server::Router::new(readiness_api)
    .merge(http_server::handlers!(state)?);
let server = http_server::Server::bind_with_authenticator(address, handler, auth).await?;
let admin_server = http_server::Server::bind_with_authenticator(
    admin_address,
    http_server::handlers!(state, admin)?,
    admin_auth,
).await?;
```

Use a short group name for a declaration in the crate root. For a group in a
nested module, provide its full path in both the API attribute and startup:
`#[api(group = crate::listeners::admin)]` and
`handlers!(state, crate::listeners::admin)?`. A grouped API needs `group`,
without an additional `register` flag. For an API that must be constructed
and merged manually, use `#[api(..., register = false)]` and omit `group`.
Such an API does not need a group declaration or `FromState` implementation.

Each group uses one concrete state type and authenticator type. Use a
concrete API implementation for registration; leave generic API implementations
with `register = false` and construct and merge their chosen instances
explicitly.

Pass all bound listeners into the generated `serve_until` lifecycle and serve
them concurrently. Preserve its SIGTERM/SIGINT handling and logging shutdown
sequence, and propagate the same shutdown event to each listener.
