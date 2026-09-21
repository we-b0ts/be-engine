# Implement inbound APIs with `brz-http-server`

Export each API as an async free function with a route attribute. Organize related
functions in ordinary Rust modules and reuse the target's business types and
services. Match the source contract's complete paths, methods, inputs,
authentication, authorization, responses, and errors.

## Dependency

Use the latest stable release from the project's configured Cargo registry and
pin it exactly. Replace `<latest-version>` below with the verified release
number, without a `v` prefix, before building; it is a placeholder, not a Cargo
version expression. Preserve registry configuration and update `Cargo.lock`;
the lockfile entries for both `brz-http-server` and `brz-http-server-macros`
must resolve from the registry, not a local path or Git checkout.

```toml
[dependencies]
brz-http-server = { version = "=<latest-version>", features = ["macros", "metrics"] }
```

Replace the old Git dependency with this registry dependency. Use
`brz_http_server::` in Rust code. Retain supporting dependencies such as `tokio`
and `serde` as required by the target. Enable `metrics` in target dependencies
as shown above to declare the requirement for route metrics.

## Declare, implement, and bind

Declare the listener's dependencies once at the crate root. Include endpoint
modules through `mod`; a source file outside the module tree does not register
routes. The following names and service operation are illustrative: adapt them
to the target's actual owners and source behavior.

```rust,ignore
// Crate root
use std::sync::Arc;
use crate::{auth::AppAuthenticator, state::AppState, users::UserService};

mod readiness;
mod user_api;

brz_http_server::registry!(
    dependencies(state: Arc<AppState>, users: Arc<UserService>),
    auth = AppAuthenticator,
);
```

Define one route per function with its complete external path, including source
router mount prefixes. Modules do not add implicit prefixes. Route access is
secure by default: omitting `access` means `access = required`. Declare only the
dependencies that the function needs:

```rust,ignore
// user_api.rs
use brz_http_server::ApiResult;
use crate::{auth::SessionUser, users::{UpdateUser, UserService, UserView}};

#[brz_http_server::put("/v1/users/:id")]
async fn update(
    #[inject(users)] service: &UserService,
    id: u64,
    verbose: Option<bool>,
    input: UpdateUser,
    #[header("x-trace-id")] trace_id: Option<&str>,
    #[auth] actor: SessionUser,
) -> ApiResult<UserView> {
    // Use the actual source-backed operation and authorization rules.
    service.update(id, input, verbose, trace_id, &actor).await
}
```

Initialize dependencies and the authenticator before collecting routes. Supply
all declared dependencies by name and propagate startup errors:

```rust,ignore
let handler = brz_http_server::handlers!(state = app_state, users = user_service)?;
let server = brz_http_server::Server::bind_with_authenticator(address, handler, auth).await?;
```

For a public-only listener, mark every route `access = public`, omit the
registry's `auth` option, and use `Server::bind`. With no dependencies, use
`registry!()` and `handlers!()`.
Keep the generated `serve_until` lifecycle, SIGTERM/SIGINT handling, and logging
shutdown sequence. Preserve readiness's existing path, checks, response, and
auth policy; register it as a function in its module through the same collection.

## Dependency injection

- Use `#[inject(name)]` to select a declared dependency. Local parameter names
  and parameter order do not select dependencies; Rust checks their types.
  Same-type dependencies remain distinct by name.
- Prefer `&T`. It borrows the stored value, including deref coercion from `Arc<T>`.
  An owned `T` parameter clones that dependency per invocation and requires
  `Clone`. Shared `&mut T` injection is unsupported; use service synchronization.
- Stored dependencies must be `Send + Sync + 'static`. Use `Arc<T>` when startup
  code or another listener also needs ownership. Initialize services once at
  startup, not while handling requests.
- Injection parameters may appear anywhere and consume no HTTP input slots.
  Missing dependencies and type mismatches are compile-time errors. Functions
  remain directly callable with ordinary Rust arguments.

## HTTP inputs and authentication

Ignoring injected dependencies and header parameters, path parameters come first in capture order
with matching names. Bind the remaining inputs as follows:

| Input | Declaration |
| --- | --- |
| One path segment | `"/users/:id"` with `id: u64`; static suffixes are supported |
| Remaining path | Terminal `"/files/*path"` with `path: &str` |
| Query | Same-named scalar parameters; `Option<T>` for optional values, `Vec<T>` for repeated keys |
| Business header | `#[header("x-trace-id")] trace_id: Option<&str>` |
| JSON body | One business type deriving `Deserialize` |
| Other bodies | `Form<T>`, `Multipart`, or raw `&[u8]` |

`#[header]` uses the parameter name literally (without a raw identifier's `r#`
prefix); underscores are not converted to hyphens. Specify hyphenated names
explicitly. `Option<T>` permits missing headers; `T` requires a value. Header
parameters can appear anywhere. Do not use route-level `headers(...)`.

Use query values as decoded by the SDK; do not URL-decode them again. Request
strings and JSON fields can borrow across `await` and response serialization;
use owned values for work that outlives the request. Exported functions may have lifetime parameters, but
not type or const generics.

Do not expose `Authorization`, API keys, cookies, or authentication query tokens
as business-handler parameters. Read them in the group authenticator through
`AuthRequest` and inject an authenticated principal. Declare the access contract
on every handler to match the source:

| Policy | Route attribute | Identity parameter |
| --- | --- | --- |
| Required | omitted, or `access = required` | exactly one `#[auth] actor: Actor` |
| Optional | `access = optional` | exactly one `#[auth] actor: Option<Actor>` |
| Public | `access = public` | none; `#[auth]` is forbidden |

`#[auth]` is the authentication marker; do not rename it to `#[principal]` or
add arguments such as `#[auth(required)]`. The principal is owned and must be a
concrete `Send + Sync + 'static` type, not a reference. The group's authenticator
must implement `Authenticator<Actor>`. Optional auth turns only
`AuthFailure::MissingCredentials` into `None`; invalid credentials, dependency
failures, and internal failures are still rejected. For required authentication
without later identity use, declare `#[auth] _actor: Actor`. Preserve business
authorization separately.

Use one application authenticator instance per listener, not one authenticator
instance per API. Implement `Authenticator<P>` on that shared type for the
principal types the listener needs. Reuse one standard session principal for
ordinary JWT-protected APIs; introduce a distinct principal only when the source
really has a different scheme, lookup projection, failure contract, or side
effect, such as API-key/task-token fallback, an internal service token, or a
share token.

```rust,ignore
// auth.rs
use std::sync::Arc;
use brz_http_server::{AuthFailure, AuthRequest, Authenticator};
use crate::state::AppState;

pub struct SessionUser {
    pub id: i64,
    pub name: String,
}

pub struct AppAuthenticator {
    state: Arc<AppState>,
}

impl Authenticator<SessionUser> for AppAuthenticator {
    async fn authenticate<'a>(
        &'a self,
        request: AuthRequest<'a>,
    ) -> Result<SessionUser, AuthFailure> {
        let authorization = request
            .header("authorization")
            .and_then(|value| std::str::from_utf8(value).ok());
        self.state
            .sessions
            .resolve(authorization)
            .await
            .map_err(map_auth_failure)
    }

    fn reject(
        &self,
        request: AuthRequest<'_>,
        failure: AuthFailure,
        arena: &brz_http_server::EphemeralBytesArena,
    ) -> brz_http_server::Response {
        render_source_auth_failure(request, failure, arena)
    }
}
```

`AuthRequest` exposes the method, path, raw query string, headers, and peer
address. It deliberately does not expose the body. Header values are bytes;
decode only the values whose source contract is textual. Use `query()` for a
source authentication token carried in the query string and the `cookie` header
for cookie fallback. Return an owned principal and do not retain borrowed request
data after `authenticate` completes.

Authentication runs before content-type checks and path/query/header/body
binding. Compare that ordering with the source contract. If the source must
return a validation error before attempting authentication, record the mismatch
instead of silently changing observable behavior. Keep credential priority,
JWT claim rules and key rotation, database/cache traffic, last-used updates,
status codes, response bodies, and authentication headers source-compatible.
Use `Authenticator::reject` when the default `AuthFailure` response does not
match the source.

Business handlers should have business names and accept the resolved principal;
do not prefix route or inner function names with `authenticate`, and do not call
JWT/API-key parsing helpers again inside the handler.

## Responses and downloads

| Contract response | Return value |
| --- | --- |
| 200 JSON | Serializable business value |
| Explicit status | `(brz_http_server::StatusCode, T)` |
| Business failure | `ApiResult<T>` or `Result<T, E>` with `E: IntoHttpError` |
| Redirect | `Redirect::found(url)` (302) or `Redirect::temporary(url)` (307) |
| Download | `impl Stream<Item = Result<Bytes, E>> + Send + 'static`, with `E: Display + Send + 'static` |

For forwarded downloads, return the HTTP client's response byte stream owning
its upstream response. Keep it streaming. Use `HttpResponse::new(stream)` with
`.status(...)`, `.header(name, value)?`, and `.content_length(length)` to preserve
upstream metadata. Include matching `Content-Range` for 206 responses, and set
content length only when exact. Let the SDK select HTTP framing.

## Additional listeners

Modules organize code; groups select listeners. Each group declares its own
dependencies and authenticator. Use a named group only when another listener
needs a separate route collection:

```rust,ignore
// Crate root; include the admin endpoint module with mod admin_api.
brz_http_server::registry!(
    group = admin,
    dependencies(state: Arc<AppState>),
    auth = AdminAuth,
);

// On each function in admin_api.rs:
// #[brz_http_server::get("/admin/status", group = admin)]
// Declare `#[auth] actor: AdminActor` and inject state as required.

// Startup; clone shared dependencies before moving them into other listeners.
let handler = brz_http_server::handlers!(state = Arc::clone(&app_state); group = admin)?;
let admin_server = brz_http_server::Server::bind_with_authenticator(
    admin_address, handler, admin_auth,
).await?;
```

The default group is `crate::http_apis`; bare group names resolve from the crate
root. For a nested declaration, use the same full path in the route attribute
and collection, for example `group = crate::listeners::admin`. In `handlers!`,
the group selector follows a semicolon.

Serve all listeners concurrently with the same shutdown event. Propagate
`RegistryError` and resolve conflicting routes in their owning modules; do not
rely on registration order or manually merge an already registered endpoint.
