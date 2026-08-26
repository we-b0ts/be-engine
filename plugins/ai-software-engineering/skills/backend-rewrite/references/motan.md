# Implement Motan APIs through `brz-motan` macros

Use this guide while implementing a recorded Motan API in a target service. It
is not a Motan protocol reference or an SDK capability catalog. Start from
source and traffic evidence, then apply the patterns below. Copy the source
service's interface path, method name, descriptor, outer serialization, Java
DTO class name, field names, and field order exactly; never infer them from a
method name or payload contents.

Every target service uses a macro-generated adapter:

```text
#[brz_motan::export] + #[brz_motan::method] + DTO derives when objects are used
```

This generated-adapter path is mandatory. If a proven, generally needed wire
form cannot be expressed with these macros and derives, add it to `brz-motan`;
the target service must continue to use the generated adapter.

## 1. Follow the generated-adapter path

Reuse the target's project-approved `brz-motan` dependency. If the target does
not have one, add the approved revision and enable the feature required by the
recorded outer serialization. Product code depends only on `brz-motan`; never
add a direct codec-crate dependency.

Keep the RPC adapter in an API-boundary module and business logic in domain
modules. One Motan interface maps to one service type annotated with
`#[brz_motan::export]`. Each source method maps to one
`#[brz_motan::method]` function. Mount the generated exporters centrally at
startup.

The generated adapter owns method matching, argument decoding, response
encoding, and serialization validation. Application code must not implement
`ExportService`, add a second dispatch table, start a raw Motan server, or read
and write frames.

## 2. Put the source contract in the macro and signature

Copy `path`, `name`, `descriptor`, and any fixed `serialization` value from
source or recorded evidence. Express the business boundary in the Rust method
signature so the generated adapter can do the wire work. For a
`java.lang.String` carrying typed JSON, use `Json<Request>` and
`Json<Response>` with Serde derives. For other values, use their direct Rust
types or the DTO derives provided by `brz-motan`.

Do not manually parse a typed `Json<Request>` or serialize a typed
`Json<Response>` in the handler. Do not hand-write codec traits in application
code. If an evidence-proven wire form cannot be expressed by the macros and
provided derives, extend `brz-motan` and keep the target on the same macro path.

## 3. Declare the interface and methods with macros

`path`, `name`, and `descriptor` are wire-contract values and must come from
the source service or recorded evidence. Method arguments map to the descriptor
in declaration order: no arguments use `"void"`; two `i64` arguments use
`"long,long"`. An exported method must take shared `&self` and return
`Result<Response, brz_motan::Error>`; it may be synchronous or `async`.

Always declare the source method's descriptor in `#[brz_motan::method]`, even
when recorded requests omit it. The generated adapter handles an omitted wire
descriptor when the method name is unique. Do not add codec or
missing-descriptor compatibility options to application exports.

```rust
use brz_motan::{Error, Json};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct LookupRequest {
    #[serde(rename = "recordId")]
    record_id: i64,
}

#[derive(Serialize)]
struct LookupResponse {
    found: bool,
}

struct ExampleRpcService;

#[brz_motan::export(
    path = "com.example.api.ExampleService",
    visibility = "pub(crate)",
    crate = "brz_motan"
)]
impl ExampleRpcService {
    #[brz_motan::method(
        name = "lookupJson",
        descriptor = "java.lang.String",
        serialization = "breeze"
    )]
    async fn lookup_json(
        &self,
        request: Json<LookupRequest>,
    ) -> Result<Json<LookupResponse>, Error> {
        Ok(Json::new(LookupResponse {
            found: request.into_inner().record_id > 0,
        }))
    }
}
```

`Json<T>` changes how the generated adapter invokes business code; it does not
change the source descriptor, so the example remains `java.lang.String`.
Specify `serialization` only when the source contract fixes it. When source
evidence requires adaptive String handling, omit that attribute and let the
generated adapter mirror the request serialization.

`Json<T>` is not an instruction to the Replay comparator. Do not alter the
target signature merely to change comparison behavior; response payload
detection remains traffic-engine-owned.

The macro generates `ExampleRpcServiceExporter` and its `PATH` constant.
Create adapters only from this generated type; do not duplicate the interface
string or implement separate dispatch.

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
        ExampleRpcServiceExporter::new(ExampleRpcService),
    );

    let bound = MotanExporter::new(ServerConfig::default())
        .mount(services)
        .export(ExportEndpoint {
            port,
            group,
            module,
            interfaces: vec![ExampleRpcServiceExporter::PATH.to_owned()],
        })
        .bind()
        .await?;

    bound.serve_until(shutdown).await
}
```

For multiple interfaces, pass every generated `*Exporter::new(...)` to the
same `brz_motan::exporter!(...)` invocation and use each `*Exporter::PATH` in
the corresponding endpoint's `interfaces`.

## 5. Call a Motan1 service through a generated Vintage referer

For a Motan1 Java/Hessian dependency, declare its contract with
`#[brz_motan::referer]` and let the generated referer own Hessian argument and
response handling. Use `connect_vintage` for endpoint discovery. When the
source call carries TokenProxy-backed TAuth2, construct the generated referer
through `TokenProxyTauth2Connect`; application code must not select an endpoint,
fetch a token, build an `Authorization` attachment, or construct raw Motan
frames.

Keep the concrete generated `*Referer` in the dependency-construction layer.
Business functions must depend on the generated service trait through a generic
type parameter; they must not accept or store the concrete referer type.

```rust,no_run
use brz_motan::vintage::{Client, ClientConfig, ExciseStrategy};
use brz_motan::{Motan1RefererConfig, SessionConfig};
use brz_motan_token_proxy::{
    TokenProxyTauth2Config,
    TokenProxyTauth2Connect as _,
};

#[brz_motan::referer(
    interface = "com.example.api.EchoService",
    crate = "brz_motan"
)]
pub trait EchoService {
    #[brz_motan::method(
        name = "echo",
        descriptor = "java.lang.String"
    )]
    async fn echo(
        &self,
        message: String,
    ) -> Result<String, brz_motan::Error>;
}

/// Business code uses `T: EchoService`; it must not depend directly on
/// `EchoServiceReferer`.
async fn echo_for_business<T>(
    service: &T,
    message: String,
) -> Result<String, brz_motan::Error>
where
    T: EchoService + ?Sized,
{
    service.echo(message).await
}

async fn echo_through_motan(
    vintage_endpoint: &str,
    message: String,
) -> Result<String, Box<dyn std::error::Error>> {
    let vintage = Client::new(ClientConfig::new(vintage_endpoint)?)?;
    let referer = EchoServiceReferer::connect_vintage(
        vintage,
        ExciseStrategy::ratio(80)?,
        SessionConfig::default(),
        Motan1RefererConfig::new("SOURCE_APPLICATION", "SOURCE_GROUP"),
        TokenProxyTauth2Config::new(SOURCE_TOKEN_ID)
            .with_signing_parameter("SOURCE_PARAMETER_NAME", "SOURCE_PARAMETER_VALUE")?,
    )
    .await?;

    let result = echo_for_business(&referer, message).await;
    referer.close().await?;
    Ok(result?)
}
```

Every `SOURCE_*` value above must come from source code or recorded evidence.
The connector loads TokenProxy credentials during readiness, and the referer
injects a freshly signed attachment for every call while hiding discovery and
authentication details from the caller.

## 6. Check before delivery

1. Test each macro method through its generated exporter, including request
   decoding, handler invocation, response encoding, and error conversion.
2. For DTOs, test the source field names, defaults, nullability, numeric ranges,
   omitted fields, and any exact text that the source contract preserves.
3. Replay recorded request frames unchanged against the running exporter,
   preserving the descriptor when present and its absence when omitted.
4. Run the target repository's normal tests and this API's Replay/Comparison
   acceptance.
