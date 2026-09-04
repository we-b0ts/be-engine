# Build inbound APIs with `http-server`

Use this guide when target code must expose an inbound HTTP API through
`http-server`. It is distinct from [http.md](http.md), which governs outbound
dependency calls through `brz-http`.

Recover the source contract before writing an API: listener address and
lifecycle, method and path template, path/query/header/body mapping, request
and response media types, authentication scheme, authorization behavior, and
every externally visible status or error body. Do not infer a public HTTP
contract from a convenient Rust DTO alone.

## Add and start the server

Pin the runtime and enable its route macros:

```toml
[dependencies]
http-server = { git = "ssh://git@git.intra.demo.test:2222/platform/breeze/http-server.git", tag = "v0.0.1", features = ["macros"] }
serde = { version = "1", features = ["derive"] }
tokio = { version = "1", features = ["macros", "net", "rt-multi-thread"] }
```

The application creates one arena and one listener during startup. Keep the
returned `Server` alive until the application's shutdown signal resolves:

```rust,no_run
use http_server::{EphemeralBytesArena, Server, ServerConfig};

# struct UserApi;
# async fn shutdown_signal() {}
# async fn run() -> http_server::Result<()> {
let server = Server::bind(
    "0.0.0.0:8080".parse().expect("valid listener address"),
    UserApi,
    ServerConfig::new(EphemeralBytesArena::new(256 * 1024)),
)
.await?;
server.serve_until(shutdown_signal()).await?;
# Ok(())
# }
```

Choose the arena capacity from the expected concurrent short-lived response
frames. Parsed request metadata and fixed-length bodies borrow the connection
buffer; JSON responses are encoded directly into arena storage. A handler must
finish before the request buffer is reused, so never retain borrowed request
data beyond the API call or return it as an unowned response body.

The first version supports bounded HTTP/1.1 fixed `Content-Length` request
bodies and sequential handling per connection. Do not add chunked uploads,
`Expect: 100-continue`, HTTP/2, WebSockets, or streaming-response assumptions
unless the source contract requires a separately implemented capability.

## Define business APIs, not transport handlers

Apply `#[api]` to an inherent implementation. It generates static dispatch and
hides `Request` from business methods. `prefix`, `consumes`, `produces`, and
`auth` belong on the API; their defaults are `""`, `json`, `json`, and `none`.
Method options inherit and may override those values.

```rust,no_run
use http_server::{ApiResult, api};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct UpdateUser<'a> {
    name: &'a str,
}

#[derive(Serialize)]
struct UserView<'a> {
    id: u64,
    name: &'a str,
}

struct UserApi;

#[api(prefix = "/v1/users")]
impl UserApi {
    #[http_server::get("/:id")]
    async fn get(&self, id: u64, verbose: Option<bool>) -> UserView<'static> {
        let _ = verbose;
        UserView { id, name: "read" }
    }

    #[http_server::post("/:id", headers(trace_id = "x-trace-id"))]
    async fn update<'a>(
        &self,
        id: u64,
        dry_run: Option<bool>,
        input: UpdateUser<'a>,
        trace_id: Option<&'a str>,
    ) -> ApiResult<UserView<'a>> {
        let _ = (dry_run, trace_id);
        Ok(UserView { id, name: input.name })
    }
}
```

The binding rules are deliberate:

- Route captures bind the first business parameters in capture order and must
  use the same names as `/:capture` segments.
- Remaining scalar parameters (`&str`, `String`, booleans, numbers, or their
  `Option` forms) bind same-named query keys.
- One remaining non-scalar parameter is the JSON body. Use borrowed
  `Deserialize<'a>` DTO fields when source behavior permits it; escaped JSON
  strings and owned fields may allocate by codec design.
- Headers are explicit with `headers(parameter = "header-name")`, because a
  scalar value is otherwise a query parameter.
- `String` deliberately allocates; use borrowed `&str` only while the value
  need not outlive the business call.

Do not add `#[path]` or `#[body]` annotations merely to restate these defaults.
Reject ambiguous method signatures at compile time instead of creating hidden
binding conventions. JSON is the operational default. `protobuf` syntax is
reserved but not implemented; do not declare it for a target API yet.

Generated transport failures are `400` for invalid bindings or JSON, `404` for
an unmatched path, `405` plus `Allow` for a matched path with the wrong method,
and `415` for a JSON body route with a non-JSON content type. Preserve any
source-specific error body contract explicitly.

## Authenticate before body decoding

Use typed authentication context rather than injecting raw credentials into
business methods. Configure an application-defined `Authenticator` when
binding the listener, then request its principal using
`Authenticated<Principal>`:

```rust,no_run
use http_server::{
    ApiResult, AuthFailure, AuthRequest, Authenticated, Authenticator,
    EphemeralBytesArena, Server, ServerConfig, api,
};
use serde::Serialize;

struct Actor {
    user_id: u64,
}

struct InternalAuth;

impl Authenticator for InternalAuth {
    type Principal = Actor;

    async fn authenticate(
        &self,
        request: AuthRequest<'_>,
    ) -> Result<Actor, AuthFailure> {
        let Some(token) = request.header("x-internal-token") else {
            return Err(AuthFailure::missing_credentials("Internal"));
        };
        if token != b"trusted" {
            return Err(AuthFailure::invalid_credentials("Internal"));
        }
        Ok(Actor { user_id: 42 })
    }
}

#[derive(Serialize)]
struct UserView {
    id: u64,
}

struct UserApi;

#[api(prefix = "/v1/users", auth = required)]
impl UserApi {
    #[http_server::get("/:id")]
    async fn get(&self, id: u64, actor: Authenticated<Actor>) -> ApiResult<UserView> {
        let _caller = actor.principal().user_id;
        Ok(UserView { id })
    }
}

# async fn shutdown_signal() {}
# async fn run() -> http_server::Result<()> {
let server = Server::bind_with_authenticator(
    "0.0.0.0:8080".parse().expect("valid listener address"),
    UserApi,
    InternalAuth,
    ServerConfig::new(EphemeralBytesArena::new(256 * 1024)),
)
.await?;
server.serve_until(shutdown_signal()).await?;
# Ok(())
# }
```

`AuthRequest` exposes only method, path, headers, and peer address. Return an
owned principal; it must not retain a borrowed header after authentication
finishes. A JWT adapter can set `type Principal = Jwt<User>`, allowing a
business method to receive `Authenticated<Jwt<User>>` without coupling the
runtime to one crypto library.

`auth = required` returns `401` with `WWW-Authenticate` for absent or invalid
credentials. `auth = optional` injects `Option<Authenticated<T>>`: it maps
missing credentials to `None`, but invalid credentials still return `401`.
Use `auth = none` for an explicit public-route override. Authentication runs
after route matching and before body decoding. Once identity is established,
authorization failures return `ApiError::forbidden(...)` (`403`); do not use
`403` for missing or invalid credentials.

## Check before delivery

1. Verify the recovered HTTP contract: exact route templates, media types,
   binding names, success and error payloads, and all status mappings.
2. Verify listener lifecycle, arena sizing, request limits, keep-alive behavior,
   and whether the source requires unsupported streaming or protocol features.
3. Verify authentication separately for absent, invalid, and valid credentials;
   verify authorization returns `403` only for an authenticated identity.
4. Exercise path, query, header, and JSON-body bindings plus `404`, `405`, and
   `415` behavior as applicable.
5. Run focused endpoint tests and the target repository's required checks.
