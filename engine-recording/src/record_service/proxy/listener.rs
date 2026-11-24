//! Accepting connections and draining their owned proxy tunnels.

use super::*;
use transport::TransportTasks;

pub(in crate::record_service) async fn serve<R: Redis + Clone + 'static>(
    listener: TcpListener,
    relay: Relay<R>,
    stop: watch::Receiver<bool>,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    let mut stopping = stop.clone();
    loop {
        tokio::select! {
            changed = stopping.changed() => { changed.ok(); break; }
            joined = tasks.join_next(), if !tasks.is_empty() => { if let Some(Err(error)) = joined { warn!(%error, "recording service connection failed"); } }
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("recording service accept failed")?;
                let relay = relay.clone();
                let mut stopping = stop.clone();
                tasks.spawn(async move {
                    let observation = match crate::http::termination::ClientTermination::with_control(&stream) {
                        Ok(observation) => observation,
                        Err(error) => { warn!(%error, "failed to observe recording service client"); return; }
                    };
                    let transports = TransportTasks::default();
                    let mut case_cancel = transports.cancellation();
                    let request_transports = transports.clone();
                    let service = service_fn(move |mut request: Request<Incoming>| {
                        request.extensions_mut().insert(request_transports.clone());
                        let relay = relay.clone();
                        async move {
                            if relay.session.is_some() {
                                return Ok::<_, Infallible>(relay.handle(request).await);
                            }
                            // Preserve ordinary request completion on downstream disconnect.
                            let result = tokio::spawn(async move { relay.handle(request).await }).await;
                            Ok::<_, Infallible>(result.unwrap_or_else(|_| response(StatusCode::BAD_GATEWAY, "recording request task failed")))
                        }
                    });
                    let connection = hyper::server::conn::http1::Builder::new().half_close(true).serve_connection(TokioIo::new(stream), service).with_upgrades();
                    tokio::pin!(connection);
                    tokio::select! {
                        result = &mut connection => { if let Err(error) = result { warn!(%error, "recording service HTTP connection ended"); } }
                        _ = stopping.changed() => { connection.as_mut().graceful_shutdown(); let _ = connection.await; }
                        _ = transport::cancelled(&mut case_cancel) => {}
                        _ = observation.wait_for_cancellation() => {}
                    }
                    transports.finish().await;
                });
            }
        }
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}
