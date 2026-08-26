# Call Motan dependencies through `brz-motan` referers

Use this guide when target code must call a Motan dependency. Start from source
and traffic evidence. Copy the source interface path, method name, descriptor,
Java DTO class name, field names, field order, authentication policy, and
effective timeout exactly; never infer them from a method name or payload.

## Keep the generated referer at the dependency boundary

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
        .with_request_timeout(request_timeout);
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

Every `SOURCE_*` value and `request_timeout` above must come from source code,
source configuration, or recorded operational evidence. The client loads
TokenProxy credentials during readiness, and the referer injects a freshly
signed attachment for every call while hiding discovery and authentication
details from the caller.

## Set the request timeout explicitly

Every target integration must call `with_request_timeout`. The SDK fallback is
not a business contract: effective Motan timeouts differ across services and
may be configured in source XML, annotations, client builders, or runtime
configuration. Preserve the source's effective per-call timeout when it is
available and keep it within the enclosing request's end-to-end deadline. Do
not copy a timeout from an example or silently replace missing evidence with a
new value. If the source value cannot be established, report that assumption
in the worker handoff instead of claiming exact compatibility.

`with_connect_timeout` controls each endpoint connection attempt during startup
or reconnect, while `with_shutdown_grace` bounds shutdown draining. Override
those operational deadlines only when source or target-runtime evidence
requires it; they are not substitutes for `with_request_timeout`.

## Share authentication and discovery ownership

Create exactly one `MotanClient` for referers that share the same TokenProxy
source and ordered signing-parameter values. Enable authentication once with
`with_auth_proxy`, then create every generated Motan1 referer through
`motan1_referer`. Omit `with_auth_proxy` when the source call is unauthenticated.
The client performs TokenProxy discovery and `getAllTokens` once, while each
business referer still performs its own service discovery. During shutdown,
close all business referers first and close the client last. Closing one
business referer does not close the shared authentication dependency, so the
remaining referers continue to work.

`Motan1RefererOptions::new` applies the SDK's standard limits, capacities,
request envelope, and 80% Vintage node threshold-protection policy. Do not
duplicate those defaults in application code. Apart from the required request
timeout, override a value only when source or runtime evidence proves that the
standard policy does not apply.

## Check before delivery

1. Test every generated method's Hessian argument encoding, response decoding,
   nullability, DTO field contract, and remote-exception mapping.
2. Test that the configured request timeout is enforced without an implicit
   retry and remains inside the caller's end-to-end budget.
3. When authentication is enabled, verify that all compatible referers share
   one TokenProxy discovery and one `getAllTokens` dependency.
4. Replay the relevant cases and run the target repository's normal checks.
