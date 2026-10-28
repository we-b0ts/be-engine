//! Python ASGI may echo WS CLOSE before its Engine.IO disconnect work is done.
//! Its live, upgraded SID returns NOOP until disconnect completes. Engine.IO
//! CLOSE can leave a closed SID; a WS CLOSE can remove that same SID instead.
use super::*;

/// Construction proves this exact Source SID was live before forwarding CLOSE.
pub(super) struct ApplicationClose {
    uri: hyper::Uri,
    headers: hyper::HeaderMap,
    sid: String,
}

impl ApplicationClose {
    pub(super) async fn prepare(session: &SessionRef) -> Result<Option<Self>> {
        let socket_io = session
            .observation
            .lock()
            .expect("interaction observation poisoned")
            .protocol()
            == crate::interaction::model::Protocol::SocketIo;
        let asgi = session
            .response
            .lock()
            .expect("interaction response poisoned")
            .as_ref()
            .and_then(|(_, headers)| headers.get(hyper::header::SERVER))
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                let name = value.split('/').next().unwrap_or(value);
                name.eq_ignore_ascii_case("uvicorn") || name.eq_ignore_ascii_case("hypercorn")
            });
        if !socket_io || !asgi {
            return Ok(None);
        }
        let sid = session
            .sid
            .lock()
            .expect("interaction SID poisoned")
            .clone()
            .context("ASGI close confirmation requires the live Engine.IO SID")?;
        let upstream = transport::build_upstream_uri(&session.upstream, &session.original_uri)?;
        let mut url = url::Url::parse(&upstream.to_string())?;
        let query = url
            .query_pairs()
            .filter(|(key, _)| !matches!(key.as_ref(), "sid" | "transport" | "EIO"))
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();
        url.query_pairs_mut()
            .clear()
            .extend_pairs(query)
            .append_pair("EIO", "4")
            .append_pair("transport", "websocket")
            .append_pair("sid", &sid);
        let headers = session
            .request_headers
            .iter()
            .filter(|(name, _)| {
                !matches!(
                    name.as_str(),
                    "host" | "connection" | "upgrade" | "content-length" | "transfer-encoding"
                ) && !name.as_str().starts_with("sec-websocket-")
            })
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        let probe = Self {
            uri: url.as_str().parse()?,
            headers,
            sid,
        };
        let response = probe.state(session).await?;
        if response.state != State::Open {
            return Err(ConfirmationFailure::response("before_close", response).into());
        }
        Ok(Some(probe))
    }

    /// Call only after forwarding CLOSE to the Source that passed the live probe.
    pub(super) async fn wait_after_close(&self, session: &SessionRef) -> Result<()> {
        loop {
            let response = self.state(session).await?;
            match response.state {
                // Python Engine.IO awaits its disconnect handler before setting
                // closed or removing the SID from the native session registry.
                // Removal here concerns the previously proven live SID, not an
                // arbitrary unknown session or an automatic WS close echo.
                State::Disconnected | State::Removed => return Ok(()),
                State::Open => tokio::time::sleep(std::time::Duration::from_millis(25)).await,
                State::Unsupported => {
                    return Err(ConfirmationFailure::response("after_close", response).into());
                }
            }
        }
    }

    async fn state(&self, session: &SessionRef) -> Result<ProbeResponse> {
        let mut request = Request::builder()
            .method("GET")
            .uri(self.uri.clone())
            .body(Full::new(Bytes::new()))?;
        *request.headers_mut() = self.headers.clone();
        let response =
            session
                .state
                .client()
                .request(request)
                .await
                .context(ConfirmationFailure {
                    phase: "probe_request",
                    http_status: None,
                    outcome: "request_failed",
                })?;
        let status = response.status();
        let bytes = http_body_util::Limited::new(response.into_body(), 2048)
            .collect()
            .await
            .map_err(|_| ConfirmationFailure {
                phase: "probe_response",
                http_status: Some(status.as_u16()),
                outcome: "body_unavailable_or_over_limit",
            })?
            .to_bytes();
        Ok(ProbeResponse {
            state: native_state(status, &bytes, &self.sid),
            status,
        })
    }
}

fn native_state(status: StatusCode, body: &[u8], sid: &str) -> State {
    if status == StatusCode::OK && body == b"6" {
        return State::Open;
    }
    if status == StatusCode::BAD_REQUEST
        && let Ok(message) = serde_json::from_slice::<String>(body)
    {
        if message == format!("Invalid session {sid}") {
            return State::Removed;
        }
        if message == format!("'Session is disconnected' {sid}")
            || message == format!("Session is disconnected {sid}")
        {
            return State::Disconnected;
        }
    }
    State::Unsupported
}

struct ProbeResponse {
    state: State,
    status: StatusCode,
}

/// Safe for WARN diagnostics: never retain the probe URI, SID or response body.
#[derive(Debug)]
pub(super) struct ConfirmationFailure {
    phase: &'static str,
    http_status: Option<u16>,
    outcome: &'static str,
}

impl ConfirmationFailure {
    fn response(phase: &'static str, response: ProbeResponse) -> Self {
        Self {
            phase,
            http_status: Some(response.status.as_u16()),
            outcome: match response.state {
                State::Open => "live",
                State::Disconnected => "disconnected",
                State::Removed => "session_removed",
                State::Unsupported => "unsupported_response",
            },
        }
    }
}

impl std::fmt::Display for ConfirmationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "ASGI Engine.IO close confirmation failed: phase={}, status={:?}, outcome={}",
            self.phase, self.http_status, self.outcome
        )
    }
}

impl std::error::Error for ConfirmationFailure {}

#[derive(Debug, PartialEq, Eq)]
enum State {
    Open,
    Disconnected,
    Removed,
    Unsupported,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_close_status_requires_exact_sid_json_message_and_http_status() {
        for (message, expected) in [
            ("Invalid session live-sid", State::Removed),
            ("'Session is disconnected' live-sid", State::Disconnected),
            ("Session is disconnected live-sid", State::Disconnected),
            ("Invalid session live-sid-other", State::Unsupported),
            ("Invalid session other-live-sid", State::Unsupported),
            ("Session is disconnected live-sid-other", State::Unsupported),
            ("Invalid session live-sid extra", State::Unsupported),
            ("Bad Request", State::Unsupported),
        ] {
            let body = serde_json::to_vec(message).unwrap();
            assert_eq!(
                native_state(StatusCode::BAD_REQUEST, &body, "live-sid"),
                expected
            );
            assert_eq!(
                native_state(StatusCode::OK, &body, "live-sid"),
                State::Unsupported
            );
            assert_eq!(
                native_state(StatusCode::INTERNAL_SERVER_ERROR, &body, "live-sid"),
                State::Unsupported
            );
        }
        for body in [
            b"Invalid session live-sid".as_slice(),
            br#"{"error":"Invalid session live-sid"}"#,
            br#"["Invalid session live-sid"]"#,
            b"6",
        ] {
            assert_eq!(
                native_state(StatusCode::BAD_REQUEST, body, "live-sid"),
                State::Unsupported
            );
        }
        assert_eq!(native_state(StatusCode::OK, b"6", "live-sid"), State::Open);
        assert_eq!(
            native_state(StatusCode::OK, b"6\n", "live-sid"),
            State::Unsupported
        );
    }
}
