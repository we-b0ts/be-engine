# Expose a Motan service

- [Complete example](#complete-example)
- [DTO mapping](#dto-mapping)
- [Framework behavior](#framework-behavior)

Use the typed `brz-motan` export path for ordinary Hessian2 services. Copy the
source contract exactly: interface path, method name, Java DTO class name, and
wire field names. Pin the Git dependency to the project-approved revision and
enable the `hessian2` feature.

```toml
brz-motan = { package = "motan", git = "ssh://git@git.intra.demo.test:2222/platform/breeze/motan.git", rev = "<approved-revision>", features = ["hessian2"] }
```

The example below exposes one standard-type method and one DTO method on two
ports. `exporter!` accepts one or more service adapters, so use the same shape
when only one service is present.

## Complete example

```rust
use brz_motan::hessian2::{HessianDecode, HessianEncode};
use brz_motan::{Error, ExportEndpoint, MotanExporter, ServerConfig};

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

struct EchoService;

#[brz_motan::export(
    path = "com.example.api.EchoService",
    visibility = "pub(crate)",
    crate = "brz_motan"
)]
impl EchoService {
    #[brz_motan::method(name = "echo")]
    fn echo(&self, input: String) -> Result<String, Error> {
        Ok(input)
    }
}

struct ProfileService;

#[brz_motan::export(
    path = "com.example.api.ProfileService",
    visibility = "pub(crate)",
    crate = "brz_motan"
)]
impl ProfileService {
    #[brz_motan::method(name = "createProfile")]
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

async fn serve() -> Result<(), Error> {
    let services = brz_motan::exporter!(
        EchoServiceExporter::new(EchoService),
        ProfileServiceExporter::new(ProfileService),
    );

    let bound = MotanExporter::new(ServerConfig::default())
        .mount(services)
        .export(ExportEndpoint {
            port: 8001,
            group: "example".to_owned(),
            module: "example".to_owned(),
            interfaces: vec![EchoServiceExporter::PATH.to_owned()],
        })
        .export(ExportEndpoint {
            port: 8002,
            group: "example".to_owned(),
            module: "example".to_owned(),
            interfaces: vec![ProfileServiceExporter::PATH.to_owned()],
        })
        .bind()
        .await?;

    bound.serve_until(std::future::pending()).await
}
```

## DTO mapping

A method receives one Hessian request value. Standard values such as `String`,
`bool`, `i32`, `i64`, `f64`, `Option<T>`, and `Vec<T>` can be used directly.
For a Java object parameter, derive `HessianDecode`; for a Java object response,
derive `HessianEncode`. Derive both when the same DTO travels in both
directions. Use the exact Java class name in `class`, `rename` when the Rust
field name differs from the wire field, and `#[hessian(bytes)]` for Java
`byte[]` rather than a Hessian list of integers.

## Framework behavior

`#[brz_motan::export]` generates the request decoder, response serializer,
Motan response construction, and the adapter `PATH`. The server runtime writes
exactly one framework-owned `M_pt`; business handlers return business values
and do not construct a Motan response or set `M_pt`.

Mount the complete adapter set once, then declare each listening endpoint with
generated `Exporter::PATH` constants so the interface string is not repeated.
All endpoints currently share the mounted static route tree; `interfaces`
validates and advertises the paths assigned to an endpoint, but is not a
port-level routing allowlist.
