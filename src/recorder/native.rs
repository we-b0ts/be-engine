//! Recording host for registered native connection drivers.
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use tokio::net::TcpStream;
use traffic_model::recording::ProtocolRef;
use traffic_protocol::{
    capture::CaptureSnapshot,
    connection::{
        CaptureExchange, CaptureHost, CaptureOutput, ConnectionInfo, NativeFuture, Operation,
    },
};

use crate::{
    AppState, access_policy::AccessDecision, active_case::DependencyTargets,
    protocols::DependencyProtocol,
};

pub(crate) async fn handle_connected(
    protocol: DependencyProtocol,
    client: TcpStream,
    upstream: TcpStream,
    state: AppState,
    info: ConnectionInfo,
) -> Result<()> {
    let native = state
        .dependency_providers()
        .provider(protocol)?
        .native_protocol()
        .context("registered dependency has no native connection capability")?;
    let session = native.capture_session(info.clone())?;
    let _connection = state
        .dependency_connections()
        .register(protocol.as_str(), &[&client, &upstream])?;
    let host = Arc::new(Host {
        state,
        protocol,
        info,
    });
    session
        .run(Box::new(client), Box::new(upstream), host)
        .await
}

struct Host {
    state: AppState,
    protocol: DependencyProtocol,
    info: ConnectionInfo,
}

impl Host {
    fn validate(&self, event: &CaptureSnapshot) -> Result<()> {
        ensure!(
            self.state
                .dependency_providers()
                .event_provider(event.payload())
                .is_some_and(|entry| entry.kind == self.protocol),
            "native capture event has a different registered owner"
        );
        Ok(())
    }
}

impl CaptureHost for Host {
    fn begin(
        &self,
        reference: ProtocolRef,
        operation: Operation,
    ) -> NativeFuture<'_, Option<Box<dyn CaptureExchange>>> {
        Box::pin(async move {
            ensure!(
                reference.protocol() == self.protocol.as_str(),
                "native capture reference changed protocol"
            );
            if self.state.access_decision(operation) == AccessDecision::Reject {
                self.state
                    .record_readonly_rejection(
                        self.protocol.as_str(),
                        operation,
                        "native_request",
                        self.info.client_addr.clone(),
                        Some(traffic_protocol::observation::format_endpoint(
                            &self.info.endpoint.host,
                            self.info.endpoint.port,
                        )),
                        "native request is rejected by the recording access policy",
                    )
                    .await;
                return Ok(None);
            }
            let targets = self.state.capture_dependency_start(reference.clone());
            ensure!(
                targets.capture.is_some(),
                "recording capture admission is closed"
            );
            Ok(Some(Box::new(Exchange {
                state: self.state.clone(),
                protocol: self.protocol,
                reference,
                targets,
            }) as Box<dyn CaptureExchange>))
        })
    }

    fn observe(&self, event: CaptureSnapshot) -> NativeFuture<'_, ()> {
        Box::pin(async move {
            self.validate(&event)?;
            self.state
                .enqueue_capture(event, self.state.capture_dependency_targets(), None, false)
        })
    }
}

struct Exchange {
    state: AppState,
    protocol: DependencyProtocol,
    reference: ProtocolRef,
    targets: DependencyTargets,
}

struct Output(super::ledger::OutputReservation);
impl CaptureOutput for Output {
    fn commit(self: Box<Self>) {
        self.0.commit();
    }
}

impl CaptureExchange for Exchange {
    fn prepare_output(
        &self,
        output: traffic_model::trace::OutputKind,
    ) -> Result<Box<dyn CaptureOutput>> {
        let reservation = self
            .targets
            .prepare_output(output)
            .context("native response has no active capture reservation")?;
        Ok(Box::new(Output(reservation)))
    }

    fn complete(self: Box<Self>, event: CaptureSnapshot) -> NativeFuture<'static, ()> {
        Box::pin(async move {
            ensure!(
                event.facts().reference == self.reference,
                "native capture completed a different request"
            );
            ensure!(
                self.state
                    .dependency_providers()
                    .event_provider(event.payload())
                    .is_some_and(|entry| entry.kind == self.protocol),
                "native capture event has a different registered owner"
            );
            self.state
                .inner
                .active_cases
                .observe_capture_tail_event(&event, &self.targets);
            self.state.enqueue_capture(event, self.targets, None, false)
        })
    }
}
