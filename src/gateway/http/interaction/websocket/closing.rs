//! Python ASGI may echo WS CLOSE before its Engine.IO disconnect work is done.
//! Its live, upgraded SID returns NOOP until closed, then a disconnected error.
use super::*;

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
        anyhow::ensure!(
            probe.state(session).await? == State::Open,
            "ASGI Engine.IO live-session NOOP confirmation is unavailable; cleanup capture cannot be certified"
        );
        Ok(Some(probe))
    }

    pub(super) async fn wait(&self, session: &SessionRef) -> Result<()> {
        loop {
            match self.state(session).await? {
                State::Closed => return Ok(()),
                State::Open => tokio::time::sleep(std::time::Duration::from_millis(25)).await,
                State::Unsupported => anyhow::bail!(
                    "ASGI Engine.IO close confirmation changed before application completion"
                ),
            }
        }
    }

    async fn state(&self, session: &SessionRef) -> Result<State> {
        let mut request = Request::builder()
            .method("GET")
            .uri(self.uri.clone())
            .body(Full::new(Bytes::new()))?;
        *request.headers_mut() = self.headers.clone();
        let response = session
            .state
            .client()
            .request(request)
            .await
            .context("ASGI Engine.IO close status request failed")?;
        let status = response.status();
        let bytes = http_body_util::Limited::new(response.into_body(), 2048)
            .collect()
            .await
            .map_err(|_| {
                anyhow::anyhow!("ASGI close status response is unavailable or exceeds its bound")
            })?
            .to_bytes();
        Ok(if status == StatusCode::OK && bytes.as_ref() == b"6" {
            State::Open
        } else if status == StatusCode::BAD_REQUEST
            && std::str::from_utf8(&bytes).is_ok_and(|text| {
                text.contains(&self.sid) && text.contains("Session is disconnected")
            })
        {
            State::Closed
        } else {
            State::Unsupported
        })
    }
}

#[derive(PartialEq, Eq)]
enum State {
    Open,
    Closed,
    Unsupported,
}
