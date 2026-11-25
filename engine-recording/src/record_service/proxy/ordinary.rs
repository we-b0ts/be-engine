//! Existing bounded HTTP relay and gateway ticket completion.

use super::*;

impl<R: Redis + Clone + 'static> Relay<R> {
    pub(super) async fn handle_ordinary(
        &self,
        mut request: Request<Incoming>,
    ) -> Response<RelayBody> {
        let deadline = tokio::time::Instant::now() + self.timeout;
        let ticket = if self.reservations.is_some() {
            match AdmissionTicket::from_headers(request.headers()) {
                Ok(Some(ticket)) if Some(ticket.scope()) == self.scope.as_deref() => Some(ticket),
                _ => return response(StatusCode::NOT_FOUND, "recording admission required"),
            }
        } else {
            None
        };
        request.headers_mut().remove(ADMISSION_SCOPE_HEADER);
        request.headers_mut().remove(ADMISSION_TOKEN_HEADER);
        let Ok(permit) = self.slot.clone().try_acquire_owned() else {
            // Do not release an identical replay of the currently executing token.
            return response(StatusCode::NOT_FOUND, "recorder busy");
        };
        let mut permit = Some(permit);
        if let (Some(reservations), Some(ticket)) = (&self.reservations, &ticket) {
            match reservations.owns(ticket).await {
                Ok(true) => {}
                _ => return response(StatusCode::NOT_FOUND, "reservation unavailable"),
            }
        }
        if !self.ready.load(Ordering::SeqCst) {
            self.release(&ticket).await;
            return response(StatusCode::NOT_FOUND, "recorder unavailable");
        }
        let (mut parts, body) = request.into_parts();
        let body =
            match tokio::time::timeout_at(deadline, Limited::new(body, self.max_body).collect())
                .await
            {
                Ok(Ok(body)) => body.to_bytes(),
                _ => {
                    self.release(&ticket).await;
                    return response(StatusCode::NOT_FOUND, "request cannot be recorded");
                }
            };
        let mut uri = self.origin.clone().into_parts();
        uri.path_and_query = parts.uri.path_and_query().cloned();
        parts.uri = match hyper::Uri::from_parts(uri) {
            Ok(uri) => uri,
            Err(_) => {
                self.release(&ticket).await;
                return response(StatusCode::NOT_FOUND, "invalid request URI");
            }
        };
        remove_hop_headers(&mut parts.headers);
        parts.headers.insert(
            hyper::header::TE,
            hyper::header::HeaderValue::from_static("trailers"),
        );
        parts.headers.insert(
            hyper::header::CONNECTION,
            hyper::header::HeaderValue::from_static("TE"),
        );
        if !self.ready.load(Ordering::SeqCst) {
            self.release(&ticket).await;
            return response(StatusCode::NOT_FOUND, "recorder unavailable");
        }
        let transports = parts.extensions.remove::<transport::TransportTasks>();
        let request = Request::from_parts(parts, full(body));
        let operation = tokio::time::timeout_at(deadline, async {
            let response = match self.client.request(request).await {
                Ok(response) => response,
                Err(error) if error.is_connect() => return Ok(None),
                Err(error) => return Err(anyhow::Error::new(error)),
            };
            if self.interactions.is_some() && response.headers().contains_key(wire::CASE_ID) {
                return Ok(Some((
                    self.adopt_interaction_response(
                        response,
                        permit.take().expect("relay admission"),
                        ticket.clone(),
                        transports,
                        deadline,
                    ),
                    true,
                )));
            }
            let (mut parts, body) = response.into_parts();
            let body = body.collect().await?.to_bytes();
            remove_hop_headers(&mut parts.headers);
            wire::strip_private(&mut parts.headers);
            Ok(Some((Response::from_parts(parts, full(body)), false)))
        });
        let result = match self.with_pending_renewal(&ticket, operation).await {
            Ok(result) => result,
            Err(()) => {
                return response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "recording reservation lost",
                );
            }
        };
        match result {
            Ok(Ok(Some((response, adopted)))) => {
                if !adopted {
                    self.release(&ticket).await;
                }
                response
            }
            Ok(Ok(None)) => {
                self.release(&ticket).await;
                response(StatusCode::NOT_FOUND, "recorder unreachable")
            }
            Ok(Err(error)) => {
                warn!(%error, "recorder response failed; reservation retained");
                if self.interactions.is_some() {
                    self.interaction_transport_failure(None);
                }
                response(StatusCode::BAD_GATEWAY, "recorder response failed")
            }
            Err(_) => {
                if self.interactions.is_some() {
                    self.interaction_transport_failure(None);
                }
                response(StatusCode::GATEWAY_TIMEOUT, "recorder request timed out")
            }
        }
    }
}
