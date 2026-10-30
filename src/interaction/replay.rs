//! Target input execution. This owner never opens expected-response evidence.
mod feedback;
mod http;
mod socketio;
pub(crate) mod timing;
pub(crate) use feedback::{Feedback, NativeEvent, NativeEventSink};

use anyhow::Result;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, StatusCode};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use std::time::Duration;

use super::model::{InputTranscript, OutputObservation, Protocol};
use crate::recorder::HeaderMapSnapshot;

type HttpClient = Client<HttpConnector, Full<Bytes>>;

pub(crate) struct ReplayResponse {
    pub(crate) started_at: chrono::DateTime<chrono::Utc>,
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMapSnapshot,
    pub(crate) body: Bytes,
    pub(crate) observation: OutputObservation,
}

pub(crate) async fn execute(
    client: &HttpClient,
    origin: &str,
    request: Request<Full<Bytes>>,
    transcript: &InputTranscript,
    header_timeout: Duration,
    body_limit: usize,
    feedback: Feedback,
) -> Result<ReplayResponse> {
    transcript.validate()?;
    match transcript.protocol {
        Protocol::SocketIo | Protocol::WebSocket => {
            socketio::execute_with_feedback(
                client,
                origin,
                request,
                transcript,
                header_timeout,
                feedback,
            )
            .await
        }
        _ => {
            http::execute_with_feedback(
                client,
                request,
                transcript,
                header_timeout,
                body_limit,
                feedback.dependency_failure,
            )
            .await
        }
    }
}

pub(super) fn elapsed_ms(started: tokio::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}
