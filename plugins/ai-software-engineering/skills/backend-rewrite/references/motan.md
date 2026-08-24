# Expose a Motan RPC service with macros

This is an implementation guide for adding Motan to a target service, not a
reference for the Motan protocol, SDK, or Hessian capabilities. Copy the source
service's RPC contract exactly: interface path, method name, descriptor, Java
DTO class name, field names, and field order must all come from evidence rather
than inference.

Every target service uses a macro-generated adapter:

```text
#[brz_motan::export] + #[brz_motan::method] + Hessian DTO derives
```

Do not implement `ExportService`, start a raw server, read or write frames, or
encode a Motan response manually in business code. If a proven, generally
needed wire form cannot be expressed with these macros and derives, add it to
`brz-motan`; the target service must continue to use the generated adapter.

## 1. Add the macro export path

Use the project-approved Motan revision and enable `hessian2`. This feature
also enables the service-export macros; ordinary RPC methods do not need a
second export mechanism.

```toml
brz-motan = { package = "motan", git = "ssh://git@git.intra.demo.test:2222/platform/breeze/motan.git", rev = "<approved-revision>", features = ["hessian2"] }
```

Keep RPC adapters in an API-boundary module and business logic in domain
modules. One Motan interface maps to one service type annotated with
`#[brz_motan::export]`; mount all generated adapters centrally at startup.

## 2. Define DTOs with derives

Declare object DTOs only with Hessian derives: request objects derive
`HessianDecode`, response objects derive `HessianEncode`, and DTOs that travel
in both directions derive both. Every DTO must declare its real Java class
name. Use `rename` whenever the Rust and wire field names differ. Struct field
declaration order is the wire field order used for encoding.

```rust
use brz_motan::hessian2::{HessianDecode, HessianEncode};

#[derive(HessianDecode)]
#[hessian(
    crate = "brz_motan::hessian2",
    class = "com.example.api.CreateProfileRequest"
)]
struct CreateProfileRequest {
    #[hessian(rename = "displayName")]
    display_name: String,
    age: i32,
    #[hessian(bytes)]
    avatar: Vec<u8>,
}

#[derive(HessianEncode)]
#[hessian(
    crate = "brz_motan::hessian2",
    class = "com.example.api.CreateProfileResponse"
)]
struct CreateProfileResponse {
    #[hessian(rename = "profileId")]
    profile_id: i64,
    #[hessian(rename = "displayName")]
    display_name: String,
}
```

Basic scalars and collections can be positional method arguments or return
values directly; use the DTO pattern above for objects. Do not hand-write
`HessianEncode` or `HessianDecode` in application code, and do not create an
extra DTO wrapper merely to hold method arguments. Java `byte[]` maps to
`Vec<u8>` annotated with `#[hessian(bytes)]`.

## 3. Declare the interface and methods with macros

`path`, `name`, and `descriptor` are wire-contract values and must come from
the source service or recorded evidence. Method arguments map to the descriptor
in declaration order: no arguments use `"void"`; two `i64` arguments use
`"long,long"`. An exported method must take shared `&self` and return
`Result<Response, brz_motan::Error>`; it may be synchronous or `async`.

```rust
use brz_motan::Error;

struct ProfileRpcService {
    // Hold only domain services or dependencies; wire DTO details stay here.
}

#[brz_motan::export(
    path = "com.example.api.ProfileService",
    visibility = "pub(crate)",
    crate = "brz_motan"
)]
impl ProfileRpcService {
    #[brz_motan::method(name = "getProfile", descriptor = "long")]
    async fn get_profile(&self, profile_id: i64) -> Result<CreateProfileResponse, Error> {
        Ok(CreateProfileResponse {
            profile_id,
            display_name: "example".to_owned(),
        })
    }

    #[brz_motan::method(
        name = "createProfile",
        descriptor = "com.example.api.CreateProfileRequest"
    )]
    async fn create_profile(
        &self,
        request: CreateProfileRequest,
    ) -> Result<CreateProfileResponse, Error> {
        Ok(CreateProfileResponse {
            profile_id: 1,
            display_name: request.display_name,
        })
    }
}
```

The macro generates `ProfileRpcServiceExporter` and its `PATH` constant. Create
adapters only from this generated type; do not duplicate the interface string
or implement separate dispatch.

## 4. Mount and bind at startup

Read port, group, and module from application configuration. Use the generated
`Exporter::PATH` value in `interfaces` so advertised interfaces and mounted
adapters remain aligned.

```rust
use std::future::Future;

use brz_motan::{Error, ExportEndpoint, MotanExporter, ServerConfig};

async fn serve_motan(
    port: u16,
    group: String,
    module: String,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), Error> {
    let services = brz_motan::exporter!(
        ProfileRpcServiceExporter::new(ProfileRpcService {}),
    );

    let bound = MotanExporter::new(ServerConfig::default())
        .mount(services)
        .export(ExportEndpoint {
            port,
            group,
            module,
            interfaces: vec![ProfileRpcServiceExporter::PATH.to_owned()],
        })
        .bind()
        .await?;

    bound.serve_until(shutdown).await
}
```

For multiple interfaces, pass every generated `*Exporter::new(...)` to the
same `brz_motan::exporter!(...)` invocation and use each `*Exporter::PATH` in
the corresponding endpoint's `interfaces`.

## 5. Check before delivery

1. Test every DTO's encoding and decoding, covering its actual class name,
   field names, field order, and `byte[]` values.
2. Call the running exporter with each exact `(path, method, descriptor)` for
   every migrated method.
3. Run the target repository's normal tests and this API's Replay/Comparison
   acceptance.
