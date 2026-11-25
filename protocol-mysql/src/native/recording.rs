//! Bridge native MySQL capture to the shared recording lifecycle.
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use anyhow::{Context, ensure};
use traffic_model::{DependencyExchangeOutcome, recording::ProtocolRef};
use traffic_protocol::{
    capture::CaptureSnapshot,
    connection::{
        BuiltinMaintenance, CaptureExchange, CaptureHost, CaptureOutput, CaptureSession,
        ConnectionInfo, ConnectionIo, NativeFuture,
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
                    requests: Mutex::default(),
                }),
            )
            .await
        })
    }
}

struct Host {
    shared: Arc<dyn CaptureHost>,
    requests: Mutex<Requests>,
}

#[derive(Default)]
struct Requests {
    omitted: u64,
    pending: BTreeMap<u64, Pending>,
}

enum Pending {
    Captured {
        permit: Box<dyn CaptureExchange>,
        sequence: u64,
    },
    Maintenance(BuiltinMaintenance),
}

struct RejectedOutput;
impl CaptureOutput for RejectedOutput {
    fn commit(self: Box<Self>) {}
}

impl connection::CaptureHost for Host {
    fn connection_id(&self) -> uuid::Uuid {
        self.shared.connection_id()
    }

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
            let operation =
                crate::access::analyze_command(request.command, request.prepared_sql).class;
            let maintenance = (request.command.command_name == "COM_PING"
                && request.payload_len == 1)
                .then(|| BuiltinMaintenance::begin(&self.shared, operation, "COM_PING"))
                .flatten();
            let pending = if let Some(maintenance) = maintenance {
                let mut requests = self.requests.lock().expect("MySQL capture permits");
                requests.omitted += 1;
                Pending::Maintenance(maintenance)
            } else {
                let sequence =
                    request.sequence - self.requests.lock().expect("MySQL capture permits").omitted;
                let reference = ProtocolRef::connection("mysql", request.connection_id, sequence);
                let Some(exchange) = self.shared.begin(reference, operation).await? else {
                    return Ok(CaptureDecision::Rejected(Box::new(RejectedOutput)));
                };
                Pending::Captured {
                    permit: exchange,
                    sequence,
                }
            };
            let previous = self
                .requests
                .lock()
                .expect("MySQL capture permits")
                .pending
                .insert(request.sequence, pending);
            ensure!(previous.is_none(), "duplicate MySQL capture sequence");
            Ok(CaptureDecision::Admitted)
        })
    }

    fn observe(&self, event: CaptureObservation) -> NativeFuture<'_, ()> {
        Box::pin(async move {
            let snapshot = match event {
                CaptureObservation::Connection(event) => CaptureSnapshot::capture(&event)?,
                CaptureObservation::Query(mut event) => {
                    let requests = self.requests.lock().expect("MySQL capture permits");
                    if matches!(
                        requests.pending.get(&event.sequence),
                        Some(Pending::Maintenance(_))
                    ) {
                        return Ok(());
                    }
                    event.sequence -= requests.omitted;
                    CaptureSnapshot::capture(&event)?
                }
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
            let (mut response, exchange) = completion.into_parts();
            let Some(mut event) = exchange else {
                if let Some(response) = &response {
                    self.shared
                        .observe(CaptureSnapshot::capture(response)?)
                        .await?;
                }
                ensure!(
                    response.is_none(),
                    "MySQL response has no semantic exchange"
                );
                return Ok(());
            };
            let permit = self
                .requests
                .lock()
                .expect("MySQL capture permits")
                .pending
                .remove(&event.query_sequence)
                .context("MySQL completion has no admitted capture")?;
            match permit {
                Pending::Captured { permit, sequence } => {
                    event.query_sequence = sequence;
                    if let Some(response) = &mut response {
                        response.query_sequence = sequence;
                        self.shared
                            .observe(CaptureSnapshot::capture(response)?)
                            .await?;
                    }
                    permit.complete(CaptureSnapshot::capture(&event)?).await
                }
                Pending::Maintenance(maintenance) => {
                    maintenance.finish(canonical_ping(&event));
                    Ok(())
                }
            }
        })
    }

    fn prepare_output(
        &self,
        sequence: u64,
        output: traffic_model::trace::OutputKind,
    ) -> Option<Box<dyn CaptureOutput>> {
        match self
            .requests
            .lock()
            .expect("MySQL capture permits")
            .pending
            .get(&sequence)?
        {
            Pending::Captured { permit, .. } => permit.prepare_output(output).ok(),
            Pending::Maintenance(_) => None,
        }
    }

    fn take_no_response(&self, _sequence: u64) -> Option<Box<dyn CaptureOutput>> {
        None
    }
}

fn canonical_ping(event: &crate::events::MysqlExchangeEvent) -> bool {
    // Preserve all transaction and autocommit state bits that Replay tracks.
    const SESSION_STATUS: u16 = 0x200b;
    let before = event
        .server_status_before
        .unwrap_or(crate::types::SERVER_STATUS_AUTOCOMMIT);
    event.outcome == DependencyExchangeOutcome::Response
        && event.response.status == "ok"
        && event.response.error_code.is_none()
        && event.parse_warnings.is_empty()
        && event
            .response
            .server_status
            .is_some_and(|after| after & SESSION_STATUS == before & SESSION_STATUS)
}
