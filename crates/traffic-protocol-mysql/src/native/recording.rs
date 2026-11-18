//! Bridge native MySQL capture to the shared recording lifecycle.
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use anyhow::{Context, ensure};
use traffic_model::recording::ProtocolRef;
use traffic_protocol::{
    capture::CaptureSnapshot,
    connection::{
        CaptureExchange, CaptureHost, CaptureOutput, CaptureSession, ConnectionInfo, ConnectionIo,
        NativeFuture,
    },
};

use crate::capture::{
    MysqlQueryCompletion,
    connection::{self, CaptureDecision, CaptureObservation, CaptureRequest, ConnectionOptions},
};

pub(super) struct Capture(pub ConnectionInfo);

impl CaptureSession for Capture {
    fn run(
        self: Box<Self>,
        client: Box<dyn ConnectionIo>,
        upstream: Box<dyn ConnectionIo>,
        host: Arc<dyn CaptureHost>,
    ) -> NativeFuture<'static, ()> {
        Box::pin(async move {
            let info = self.0;
            let transport = host.transport();
            let address = traffic_protocol::observation::format_endpoint(
                &info.endpoint.host,
                info.endpoint.port,
            );
            let options = ConnectionOptions {
                context: connection::CaptureConnectionContext {
                    route_name: None,
                    listen_addr: String::new(),
                    client_addr: info.client_addr,
                    target_host: Some(info.endpoint.host),
                    target_port: Some(info.endpoint.port),
                    target_addr: Some(address.clone()),
                    upstream_addr: info.upstream_addr.unwrap_or(address),
                },
                max_body_bytes: info.max_frame_bytes,
                record_raw_packets: false,
                client_decoder: Box::new(crate::MysqlDecoder),
                server_decoder: Box::new(crate::MysqlDecoder),
                termination: transport.termination.clone(),
            };
            connection::run_io(
                client,
                upstream,
                options,
                transport,
                Arc::new(Host {
                    shared: host,
                    pending: Mutex::default(),
                }),
            )
            .await
        })
    }
}

struct Host {
    shared: Arc<dyn CaptureHost>,
    pending: Mutex<BTreeMap<u64, Box<dyn CaptureExchange>>>,
}

struct RejectedOutput;
impl CaptureOutput for RejectedOutput {
    fn commit(self: Box<Self>) {}
}

impl connection::CaptureHost for Host {
    fn accept_tls(
        &self,
        io: Box<dyn ConnectionIo>,
        _host: String,
    ) -> NativeFuture<'_, Box<dyn ConnectionIo>> {
        self.shared.accept_tls(io, Vec::new())
    }

    fn begin_request<'a>(
        &'a self,
        request: CaptureRequest<'a>,
    ) -> NativeFuture<'a, CaptureDecision> {
        Box::pin(async move {
            // Commands with no response are native session controls.
            if !request.command.expects_server_response() {
                return Ok(CaptureDecision::Admitted);
            }
            let reference =
                ProtocolRef::connection("mysql", request.connection_id, request.sequence);
            let operation =
                crate::access::analyze_command(request.command, request.prepared_sql).class;
            let Some(exchange) = self.shared.begin(reference, operation).await? else {
                return Ok(CaptureDecision::Rejected(Box::new(RejectedOutput)));
            };
            let previous = self
                .pending
                .lock()
                .expect("MySQL capture permits")
                .insert(request.sequence, exchange);
            ensure!(previous.is_none(), "duplicate MySQL capture sequence");
            Ok(CaptureDecision::Admitted)
        })
    }

    fn observe(&self, event: CaptureObservation) -> NativeFuture<'_, ()> {
        Box::pin(async move {
            let snapshot = match event {
                CaptureObservation::Connection(event) => CaptureSnapshot::capture(&event)?,
                CaptureObservation::Query(event) => CaptureSnapshot::capture(&event)?,
            };
            self.shared.observe(snapshot).await
        })
    }

    fn complete(&self, completion: MysqlQueryCompletion) -> NativeFuture<'_, ()> {
        Box::pin(async move {
            let (response_sequence, exchange_sequence) = completion.sequences();
            ensure!(
                response_sequence.is_none()
                    || exchange_sequence.is_none()
                    || response_sequence == exchange_sequence,
                "MySQL response and exchange sequences differ"
            );
            let (response, exchange) = completion.into_parts();
            if let Some(response) = &response {
                self.shared
                    .observe(CaptureSnapshot::capture(response)?)
                    .await?;
            }
            let Some(event) = exchange else {
                ensure!(
                    response.is_none(),
                    "MySQL response has no semantic exchange"
                );
                return Ok(());
            };
            let permit = self
                .pending
                .lock()
                .expect("MySQL capture permits")
                .remove(&event.query_sequence)
                .context("MySQL completion has no admitted capture")?;
            permit.complete(CaptureSnapshot::capture(&event)?).await
        })
    }

    fn prepare_output(
        &self,
        sequence: u64,
        output: traffic_model::trace::OutputKind,
    ) -> Option<Box<dyn CaptureOutput>> {
        self.pending
            .lock()
            .expect("MySQL capture permits")
            .get(&sequence)?
            .prepare_output(output)
            .ok()
    }

    fn take_no_response(&self, _sequence: u64) -> Option<Box<dyn CaptureOutput>> {
        None
    }
}
