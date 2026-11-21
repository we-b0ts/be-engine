//! Configured listeners delegate connections to their registered provider.
use super::*;
use std::net::SocketAddr;
use tokio::{net::TcpListener, task::JoinSet};
use traffic_protocol::connection::Endpoint;

pub struct Route {
    pub listen: SocketAddr,
    pub endpoint: Endpoint,
}

pub async fn run(
    state: AppState,
    protocol: DependencyProtocol,
    routes: Vec<Route>,
    ready: crate::recording_control::RecordingListener,
) -> Result<()> {
    let mut listeners = Vec::with_capacity(routes.len());
    for route in routes {
        let listener = TcpListener::bind(route.listen).await?;
        tracing::info!(protocol = protocol.as_str(), listen = %route.listen,
            host = %route.endpoint.host, port = route.endpoint.port, "native recorder listening");
        listeners.push((route.endpoint, listener));
    }
    state.mark_recording_listener_ready(ready);
    let mut tasks = JoinSet::new();
    for (endpoint, listener) in listeners {
        tasks.spawn(serve(state.clone(), protocol, endpoint, listener));
    }
    match tasks.join_next().await {
        Some(result) => result.context("native recording listener task panicked")?,
        None => Ok(()),
    }
}

async fn serve(
    state: AppState,
    protocol: DependencyProtocol,
    endpoint: Endpoint,
    listener: TcpListener,
) -> Result<()> {
    loop {
        let (client, peer) = listener.accept().await?;
        let state = state.clone();
        let endpoint = endpoint.clone();
        tokio::spawn(async move {
            if let Err(error) = connected(protocol, client, peer, state, endpoint).await {
                tracing::warn!(protocol = protocol.as_str(), %error,
                    "native recording connection failed");
            }
        });
    }
}

async fn connected(
    protocol: DependencyProtocol,
    client: TcpStream,
    peer: SocketAddr,
    state: AppState,
    endpoint: Endpoint,
) -> Result<()> {
    let address = traffic_protocol::observation::format_endpoint(&endpoint.host, endpoint.port);
    let Some(upstream) = crate::recorder::connect_failure::connect_upstream(
        &state,
        &client,
        protocol.as_str(),
        (&endpoint.host, endpoint.port),
        &address,
    )
    .await?
    else {
        return Ok(());
    };
    let info = ConnectionInfo {
        endpoint,
        client_addr: Some(peer.to_string()),
        upstream_addr: Some(upstream.peer_addr()?.to_string()),
        max_frame_bytes: state.config().recording.max_body_bytes,
    };
    handle_connected(protocol, client, upstream, state, info).await
}
