//! Matching the HTTP exchange when a WebSocket opening handshake ends in HTTP.
use super::*;
use crate::message::RequestView;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use traffic_protocol::message::{ProjectedMessage, ProjectedValue, ProtocolMessage};

pub(super) fn recorded_request(
    request: RequestMessage,
    status: u16,
    headers: &crate::headers::HeaderSnapshot,
    has_stream: bool,
) -> Arc<dyn ProtocolMessage> {
    if !(200..600).contains(&status) || !has_websocket_offer(&request) {
        return Arc::new(request);
    }
    Arc::new(WebSocketOffer {
        request: Arc::new(request),
        refusal_http_defaults: status == 400 && !has_stream && identity_refusal(headers),
        alternative: None,
    })
}

pub(super) fn target_request(request: RequestMessage, http11: bool) -> Arc<dyn ProtocolMessage> {
    if !http11 || !has_websocket_offer(&request) {
        return Arc::new(request);
    }
    let request = Arc::new(request);
    Arc::new(WebSocketOffer {
        refusal_http_defaults: false,
        alternative: Some(Box::new(WebSocketOffer {
            request: request.clone(),
            refusal_http_defaults: true,
            alternative: None,
        })),
        request,
    })
}

fn identity_refusal(headers: &crate::headers::HeaderSnapshot) -> bool {
    let headers = crate::headers::normalized(headers);
    !["vary", "upgrade", "sec-websocket-accept", "sec-websocket-extensions", "sec-websocket-protocol"]
        .iter().any(|name| headers.contains_key(*name))
        && !connection_upgrade(&headers)
        && headers.get("content-encoding").is_none_or(|values| {
            matches!(values.as_slice(), [coding] if coding.eq_ignore_ascii_case("identity"))
        })
}

fn has_websocket_offer(request: &RequestMessage) -> bool {
    if request.method != "GET"
        || !request.body.is_empty()
        || !request
            .headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("upgrade"))
    {
        return false;
    }
    let headers = crate::headers::normalized(&request.headers);
    let single = |name| match headers.get(name).map(Vec::as_slice) {
        Some([value]) => Some(value.as_str()),
        _ => None,
    };
    single("upgrade").is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        && single("sec-websocket-version") == Some("13")
        && connection_upgrade(&headers)
        && single("sec-websocket-key").is_some_and(|key| {
            key.len() == 24 && STANDARD.decode(key).is_ok_and(|nonce| nonce.len() == 16)
        })
}

fn connection_upgrade(headers: &crate::headers::HeaderSnapshot) -> bool {
    headers.get("connection").is_some_and(|values| {
        values
            .iter()
            .flat_map(|value| value.split(','))
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
    })
}

struct WebSocketOffer {
    request: Arc<RequestMessage>,
    refusal_http_defaults: bool,
    alternative: Option<Box<Self>>,
}

impl ProtocolMessage for WebSocketOffer {
    fn exact_request_alternative(&self) -> Option<&dyn ProtocolMessage> {
        self.alternative
            .as_deref()
            .map(|alternative| alternative as &dyn ProtocolMessage)
    }

    fn project(&self) -> Result<ProjectedMessage> {
        let mut projection = self.request.project_request(RequestView::WebSocket)?;
        projection.structure["websocket_offer"] = Value::Bool(true);
        // The opening handshake generates a fresh nonce on each connection.
        projection.values.insert(
            "/headers/sec-websocket-key/0".into(),
            ProjectedValue::bytes("websocket-nonce"),
        );
        if self.refusal_http_defaults {
            // The Source refusal supports the default media preference.
            projection.structure["websocket_refusal_http_defaults"] = Value::Bool(true);
            let headers = projection.structure["headers"]
                .as_object_mut()
                .expect("HTTP header projection");
            let accept = "/headers/accept/0";
            if headers.get("accept").and_then(Value::as_u64) == Some(1)
                && projection
                    .values
                    .get(accept)
                    .is_some_and(|value| value.bytes == b"*/*".as_slice())
            {
                headers.remove("accept");
                projection.values.remove(accept);
            }
        }
        Ok(projection)
    }

    fn locate(&self, selector: &Value) -> Result<Vec<String>> {
        let mut locations = self
            .request
            .request_locations(selector, RequestView::WebSocket)?;
        if self.refusal_http_defaults {
            let projection = self.project()?;
            locations.retain(|location| projection.values.contains_key(location));
        }
        Ok(locations)
    }

    fn evidence(&self, selector: &Value) -> Result<Value> {
        self.request.evidence(selector)
    }
}
