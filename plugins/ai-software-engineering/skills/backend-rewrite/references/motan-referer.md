# Call Motan dependencies through `brz-motan` referers

Use this guide when target code must call a Motan dependency. Start from source
and traffic evidence. Copy the source interface path, method name, descriptor,
Java DTO class name, field names, field order, authentication policy, and
effective timeout exactly; never infer them from a method name or payload.

## Keep the generated referer at the dependency boundary

Add `brz-motan` at the fixed `v0.0.4` tag. Motan1 referers use Hessian2,
metrics, and Vintage discovery:

```toml
brz-motan = { package = "motan", git = "ssh://git@git.intra.demo.test:2222/platform/breeze/motan.git", tag = "v0.0.4", features = ["hessian2", "metrics", "vintage"] }
```

When the source uses TokenProxy-backed TAuth2, also add:

```toml
brz-motan-token-proxy = { package = "motan-token-proxy", git = "ssh://git@git.intra.demo.test:2222/platform/breeze/motan.git", tag = "v0.0.4" }
```

Starting with `v0.0.4`, TokenProxy credential loads use the same generated
Motan1 referer path as business methods. Initial loads, retries, and periodic
refreshes therefore emit `RPC_SERVICE_CLIENT`, `RPC_SERVICE_CLIENT_REAL`, both
V2 aliases, and the `token-proxy` cluster profile automatically. Application
code must not add duplicate TokenProxy metrics.

For a Motan1 Java/Hessian dependency, declare its contract with
`#[brz_motan::referer]` and let the generated referer own Hessian argument and
response handling. Create it with `MotanClient::motan1_referer` so the client
owns Vintage endpoint discovery. When the source call carries TokenProxy-backed
TAuth2, enable the auth proxy once on that process-level client; application
code must not select an endpoint, fetch a token, build an `Authorization`
attachment, construct raw Motan frames, or manage an authentication provider.

Keep the concrete generated `*Referer` in the dependency-construction layer.
Business functions must depend on the generated service trait through a generic
type parameter; they must not accept or store the concrete referer type.

```rust,no_run
use std::time::Duration;

use brz_motan::vintage::{Client, ClientConfig};
use brz_motan::{Motan1RefererOptions, MotanClient};
use brz_motan_token_proxy::{
    TokenProxyTauth2ClientExt as _,
    TokenProxyTauth2Config,
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
    request_timeout: Duration,
    message: String,
) -> Result<String, Box<dyn std::error::Error>> {
    let vintage = Client::new(ClientConfig::new(vintage_endpoint)?)?;
    let client = MotanClient::new(vintage)
        .with_auth_proxy(
            TokenProxyTauth2Config::new(SOURCE_TOKEN_ID)
                .with_signing_parameter(SOURCE_PARAMETER_NAME, SOURCE_PARAMETER_VALUE)?,
        )
        .await?;
    let options = Motan1RefererOptions::new(SOURCE_APPLICATION, SOURCE_GROUP)
        .with_request_timeout(request_timeout)
        .with_retries(SOURCE_RETRIES);
    let referer: EchoServiceReferer = match client.motan1_referer(options).await {
        Ok(referer) => referer,
        Err(error) => {
            client.close().await?;
            return Err(error.into());
        }
    };

    let result = echo_for_business(&referer, message).await;
    let referer_close = referer.close().await;
    let client_close = client.close().await;
    referer_close?;
    client_close?;
    Ok(result?)
}
```

Every `SOURCE_*` value, `request_timeout`, and retry count above must come from
source code, source configuration, or recorded operational evidence. The
client loads TokenProxy credentials during readiness, and the referer injects
a freshly signed attachment for every call while hiding discovery and
authentication details from the caller.

## Preserve Hessian Date types in collection contracts

Java `java.util.Date` is a distinct Hessian wire type, encoded with the `J` or
`K` tag; it is not a Java `Long` even though both can be represented as Unix-
epoch milliseconds in Rust. Declare Date values used as map keys, list items,
or top-level values with `brz_motan::hessian2::HessianDateMillis`. For example,
a source return type of `Map<Date, Integer>` maps to:

```rust
use std::collections::HashMap;

use brz_motan::hessian2::HessianDateMillis;

type SourceByDate = HashMap<HessianDateMillis, i32>;
```

Do not substitute `HashMap<i64, i32>`: the `i64` decoder accepts Hessian integer
and long tags, not Date tags. Use `HessianDateMillis::as_millis` only after the
wire value has been decoded, for business ordering or timestamp conversion.
For Date-valued DTO fields, continue to use `#[hessian(date)]`; that field
attribute does not apply automatically to generic collection keys or items.

## Set the request timeout explicitly

Every target integration must call `with_request_timeout`. It bounds each
physical request attempt, not the whole logical call. The SDK fallback is not
a business contract: effective Motan timeouts differ across services and may
be configured in source XML, annotations, client builders, or runtime
configuration. Preserve the source's effective attempt timeout when it is
available. With `N` retries, reserve roughly `(N + 1) * request_timeout` inside
the enclosing request's end-to-end deadline. Do not copy a timeout from an
example or silently replace missing evidence with a new value. If the source
value cannot be established, report that assumption in the worker handoff
instead of claiming exact compatibility.

Set `with_retries` from source behavior as well, including zero when the source
does not retry. A referer performs one additional attempt by default and only
retries transport/admission failures such as unavailable, overload, timeout,
closed connection, or I/O failure. The additional attempt uses a different
discovered replica when one exists. Because a timeout or connection failure
can occur after the server has executed the request, enabling retries gives
the logical call at-least-once execution semantics. Do not enable or increase
retries for a non-idempotent method without source evidence that duplicate
execution is acceptable, and do not add another application retry around the
referer.

`with_connect_timeout` controls each endpoint connection attempt during startup
or reconnect, while `with_shutdown_grace` bounds shutdown draining. Override
those operational deadlines only when source or target-runtime evidence
requires it; they are not substitutes for `with_request_timeout`.

## Share authentication and discovery ownership

Create exactly one `MotanClient` for referers that share the same TokenProxy
source and ordered signing-parameter values. Enable authentication once with
`with_auth_proxy`, then create every generated Motan1 referer through
`motan1_referer`. Omit `with_auth_proxy` when the source call is unauthenticated.
The client owns one TokenProxy discovery and credential-refresh runtime, while
each business referer still performs its own service discovery. During shutdown,
close all business referers first and close the client last. Closing one
business referer does not close the shared authentication dependency, so the
remaining referers continue to work.

`Motan1RefererOptions::new` applies the SDK's standard limits, capacities,
request envelope, one additional retry, and 80% Vintage node
threshold-protection policy. Do not duplicate those defaults in application
code. Set the evidence-proven timeout and retry count explicitly; override any
other value only when source or runtime evidence proves that the standard
policy does not apply.

## Check before delivery

1. Test every generated method's Hessian argument encoding, response decoding,
   nullability, DTO field contract, and remote-exception mapping.
2. Test timeout, unavailable, and overload behavior with the configured retry
   count; verify distinct-replica failover and the full logical-call budget.
3. When authentication is enabled, verify that all compatible referers share
   one TokenProxy discovery and one `getAllTokens` dependency.
4. Replay the relevant cases and run the target repository's normal checks.
