//! Authenticated native envelopes share finite message traversal with live traffic.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use traffic_protocol::evidence::{MessageEvidence, MessageSide, SourceTiming};

pub(super) fn decode(event: &Value, payload: &[u8], side: MessageSide) -> Result<MessageEvidence> {
    let value: Value = serde_json::from_slice(payload)?;
    let original: recorded::RecordedExchange = serde_json::from_value(event.clone())?;
    let (scheme, endpoint) = original.identity()?;
    ensure!(
        value["endpoint"] == serde_json::to_value(&endpoint)?
            && value["scheme"] == serde_json::to_value(scheme)?,
        "HTTP witness endpoint or transport changed"
    );
    let body = |name: &str| -> Result<Bytes> {
        Ok(STANDARD
            .decode(
                value[name]
                    .as_str()
                    .context("HTTP witness body is absent")?,
            )?
            .into())
    };
    let method = value["method"]
        .as_str()
        .context("HTTP witness method is absent")?
        .to_ascii_uppercase();
    let uri: hyper::Uri = value["uri"]
        .as_str()
        .context("HTTP witness URI is absent")?
        .parse()?;
    if let Some(authority) = uri.authority() {
        let port = authority.port_u16().unwrap_or(match scheme {
            recorded::HttpScheme::Http => 80,
            recorded::HttpScheme::Https => 443,
        });
        ensure!(
            traffic_protocol::observation::normalize_host(authority.host()) == endpoint.host
                && port == endpoint.port,
            "HTTP witness URI authority differs from its endpoint"
        );
    }
    if let Some(actual) = uri.scheme_str() {
        ensure!(
            recorded::HttpScheme::from_recorded(actual)? == scheme,
            "HTTP witness URI transport differs from its endpoint"
        );
    }
    let request = Arc::new(RequestMessage {
        method: method.clone(),
        uri: uri
            .path_and_query()
            .map_or("/", |path| path.as_str())
            .to_owned(),
        headers: serde_json::from_value(value["request_headers"].clone())?,
        body: body("request_body")?,
    });
    let response = if side == MessageSide::Response {
        ensure!(
            value["outcome"] == "response" && value["error"].is_null(),
            "HTTP witness requires a complete response"
        );
        Some(Arc::new(ResponseMessage {
            status: u16::try_from(
                value["response_status"]
                    .as_u64()
                    .context("HTTP witness status is absent")?,
            )?,
            headers: serde_json::from_value(value["response_headers"].clone())?,
            body: body("response_body")?,
            head_request: method == "HEAD",
        })
            as Arc<dyn traffic_protocol::message::ProtocolMessage>)
    } else {
        None
    };
    Ok(MessageEvidence {
        request: Some(request),
        response,
        timing: SourceTiming::Request {
            started_at: value["request_started_at"]
                .as_str()
                .map(str::parse)
                .transpose()?,
            completed_at: value["response_delivered_at"]
                .as_str()
                .map(str::parse)
                .transpose()?,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_decoding_preserves_live_http_locations_and_transport_identity() {
        let capture =
            |value| serde_json::json!({"encoding":"utf8", "data":value, "truncated":false});
        let event = serde_json::json!({
            "event_type":"http_exchange", "id":uuid::Uuid::nil(), "scheme":"http", "authority":"api.test:80",
            "method":"POST", "uri":"http://api.test/items?mode=one", "request_headers":{"x-test":["same"]},
            "request_body":capture("{\"id\":7}"), "response_status":200, "response_headers":{},
            "response_body":capture("{\"id\":7}")
        });
        let exchange = Native.recorded_exchange(&event).unwrap().unwrap();
        let record = serde_json::from_value(event.clone()).unwrap();
        for side in [MessageSide::Request, MessageSide::Response] {
            let payload =
                serde_json::to_vec(&crate::witness::from_record(&record, side).unwrap()).unwrap();
            let decoded = Native.decode_evidence(&event, &payload, side).unwrap();
            let before = exchange
                .request()
                .expect("native request")
                .project()
                .unwrap();
            let after = decoded.request.as_ref().unwrap().project().unwrap();
            assert_eq!(before.structure, after.structure);
            assert!(
                before
                    .values
                    .iter()
                    .all(|(path, value)| value.bytes == after.values[path].bytes)
            );
            if let Some(response) = decoded.response {
                let before = exchange.response.project().unwrap();
                let after = response.project().unwrap();
                assert_eq!(before.structure, after.structure);
                assert_eq!(before.values["/body"].bytes, after.values["/body"].bytes);
            }
            let mut changed: Value = serde_json::from_slice(&payload).unwrap();
            changed["endpoint"]["host"] = serde_json::json!("other.test");
            assert!(
                Native
                    .decode_evidence(&event, &serde_json::to_vec(&changed).unwrap(), side)
                    .is_err()
            );
        }
    }
}
