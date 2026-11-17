//! Request-carrier bindings for the independent signed-token implementation.
use super::JwtTokenLocation;
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use serde_json::Value;
pub use traffic_jwt::Algorithm;
#[cfg(test)]
pub(crate) use traffic_jwt::sign;
pub use traffic_jwt::{Token, contract, nonce};
pub(crate) use traffic_protocol_http::query_token as url_query;

pub fn request_timestamp(request: &Value) -> Result<DateTime<Utc>> {
    request["timestamp"]
        .as_str()
        .context("JWT request rule requires the original recording timestamp")?
        .parse()
        .context("invalid JWT request recording timestamp")
}

pub fn request_token(request: &Value, location: &JwtTokenLocation) -> Result<Option<String>> {
    match location {
        JwtTokenLocation::BearerHeader { header } => header_token(request, header, true),
        JwtTokenLocation::RawHeader { raw_header } => header_token(request, raw_header, false),
        JwtTokenLocation::QueryParameter { query_param } => {
            let Some(uri) = request["uri"].as_str() else {
                return Ok(None);
            };
            Ok(url_query::query_token_range(uri, query_param)?.map(|(_, token)| token))
        }
        JwtTokenLocation::SocketIoConnect { socketio_connect } => {
            super::socketio_connect::token(request, socketio_connect)
        }
    }
}

pub(crate) fn replace_request_token(
    request: &mut Value,
    location: &JwtTokenLocation,
    token: String,
) -> Result<()> {
    match location {
        JwtTokenLocation::SocketIoConnect { socketio_connect } => {
            super::socketio_connect::replace(request, socketio_connect, token)
        }
        JwtTokenLocation::RawHeader { raw_header } => {
            if let Some(headers) = request["headers"].as_object_mut() {
                for (key, values) in headers {
                    if key.eq_ignore_ascii_case(raw_header) {
                        values[0] = Value::String(token);
                        return Ok(());
                    }
                }
            }
            bail!("JWT header disappeared during transformation")
        }
        JwtTokenLocation::BearerHeader { header } => {
            if let Some(headers) = request["headers"].as_object_mut() {
                for (key, values) in headers {
                    if key.eq_ignore_ascii_case(header) {
                        let scheme = values[0]
                            .as_str()
                            .and_then(|v| v.split_once(' '))
                            .map(|v| v.0)
                            .context("JWT header changed during transformation")?
                            .to_string();
                        values[0] = Value::String(format!("{scheme} {token}"));
                        return Ok(());
                    }
                }
            }
            bail!("JWT header disappeared during transformation")
        }
        JwtTokenLocation::QueryParameter { query_param } => {
            let uri = request["uri"]
                .as_str()
                .context("JWT request URI disappeared during transformation")?;
            let (range, original) = url_query::query_token_range(uri, query_param)?
                .context("JWT query parameter disappeared during transformation")?;
            ensure!(
                !original.is_empty(),
                "JWT query parameter changed during transformation"
            );
            let mut rewritten = String::with_capacity(uri.len() - range.len() + token.len());
            rewritten.push_str(&uri[..range.start]);
            rewritten.push_str(&token);
            rewritten.push_str(&uri[range.end..]);
            request["uri"] = Value::String(rewritten);
            Ok(())
        }
    }
}

fn header_token(request: &Value, name: &str, bearer: bool) -> Result<Option<String>> {
    let Some(headers) = request["headers"].as_object() else {
        return Ok(None);
    };
    let values = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Ok(None);
    }
    ensure!(values.len() == 1, "ambiguous JWT request header");
    let values = values[0]
        .1
        .as_array()
        .context("JWT request header must be an array")?;
    ensure!(values.len() == 1, "ambiguous JWT request header values");
    let value = values[0]
        .as_str()
        .context("JWT request header must be text")?;
    if !bearer {
        return Ok((!value.contains(char::is_whitespace)).then(|| value.to_owned()));
    }
    let Some((scheme, token)) = value.split_once(' ') else {
        return Ok(None);
    };
    Ok(scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim().to_string()))
}
