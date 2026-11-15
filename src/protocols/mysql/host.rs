//! Adapt native MySQL observations to application-owned recording policy and receipts.
use std::sync::Arc;

use anyhow::Result;
use traffic_model::{recording::ProtocolRef, trace::OutputKind};
use traffic_protocol::connection::{CaptureOutput, NativeFuture};
use traffic_protocol_mysql::capture::{
    MysqlQueryCompletion,
    connection::{CaptureDecision, CaptureHost, CaptureObservation, CaptureRequest},
};

use super::{MysqlConnectionContext, ownership};
use crate::{
    AppState,
    access_policy::{AccessDecision, MysqlAccessContext, evaluate_mysql_access},
    active_case::DependencyTargets,
    mysql::access::analyze_command,
    protocols::recording::events::RecorderEvent,
};

pub(super) struct Host {
    state: AppState,
    context: MysqlConnectionContext,
    target: Option<String>,
    ownerships: ownership::QueryDependencyOwnerships,
}

impl Host {
    pub(super) fn new(state: AppState, context: MysqlConnectionContext) -> Self {
        let target = context
            .target_addr
            .clone()
            .or_else(|| context.target_host.clone())
            .or_else(|| Some(context.upstream_addr.clone()));
        Self {
            state,
            context,
            target,
            ownerships: Default::default(),
        }
    }
}

struct MetadataOutput {
    targets: DependencyTargets,
    terminal: &'static str,
}

impl CaptureOutput for MetadataOutput {
    fn commit(self: Box<Self>) {
        self.targets.finish_capture_metadata(self.terminal);
    }
}

impl CaptureHost for Host {
    fn server_tls_config(&self, host: &str) -> Result<Arc<rustls::ServerConfig>> {
        self.state.ca().mysql_server_config_for_host(host)
    }

    fn begin_request<'a>(
        &'a self,
        request: CaptureRequest<'a>,
    ) -> NativeFuture<'a, CaptureDecision> {
        Box::pin(async move {
            let command = request.command;
            let targets = self.state.capture_dependency_request(
                crate::protocols::recording::request::DependencyRequest::Mysql {
                    target_host: self.context.target_host.as_deref(),
                    target_port: self.context.target_port,
                    database: request.database,
                    username: request.username,
                    command: &command.command_name,
                    sql: command.query.as_deref().or(request.prepared_sql),
                },
            );
            let analysis = analyze_command(command, request.prepared_sql);
            let access = evaluate_mysql_access(
                self.state.config().recording.access_policy,
                &self.state.config().recording.access_rules,
                &analysis,
                MysqlAccessContext {
                    route_name: self.context.route_name.as_deref(),
                    target_host: self.context.target_host.as_deref(),
                    target_addr: self.context.target_addr.as_deref(),
                    database: request.database,
                },
            );
            if access.decision == AccessDecision::Reject {
                self.state
                    .record_readonly_rejection(
                        "mysql",
                        analysis.class,
                        command.command_name.clone(),
                        self.context.client_addr.clone(),
                        self.target.clone(),
                        "MySQL command is classified as a write operation",
                    )
                    .await;
                return Ok(CaptureDecision::Rejected(Box::new(MetadataOutput {
                    targets,
                    terminal: "access_policy_rejected",
                })));
            }
            if let Some(rule) = access.matched_rule {
                self.state
                    .record_access_policy_allow(
                        rule,
                        "mysql",
                        analysis.class,
                        analysis.operation_names(),
                        analysis.resource_names(request.database),
                        self.context.client_addr.clone(),
                        self.target.clone(),
                        "MySQL write matched a configured recording access rule",
                    )
                    .await;
            }
            targets.bind_protocol(ProtocolRef::connection(
                "mysql",
                request.connection_id,
                request.sequence,
            ));
            self.ownerships.insert(request.sequence, targets);
            Ok(CaptureDecision::Admitted)
        })
    }

    fn observe(&self, event: CaptureObservation) -> NativeFuture<'_, ()> {
        Box::pin(async move {
            match event {
                CaptureObservation::Connection(event) => {
                    super::record_event_and_case_dependency(
                        &self.state,
                        RecorderEvent::MysqlConnection(event),
                    )
                    .await
                }
                CaptureObservation::Query(event) => {
                    let sequence = event.sequence;
                    let targets = self.ownerships.get(sequence);
                    let result = ownership::record_event(
                        &self.state,
                        RecorderEvent::MysqlQuery(event),
                        targets,
                    )
                    .await;
                    if result.is_err() {
                        self.ownerships.take(sequence);
                    }
                    result
                }
            }
        })
    }

    fn complete(&self, completion: MysqlQueryCompletion) -> NativeFuture<'_, ()> {
        Box::pin(ownership::record_query_completion(
            &self.state,
            &self.ownerships,
            completion,
        ))
    }

    fn prepare_output(&self, sequence: u64, output: OutputKind) -> Option<Box<dyn CaptureOutput>> {
        self.ownerships
            .get(sequence)?
            .prepare_output(output)
            .map(|reservation| {
                Box::new(crate::recorder::native::Output(reservation)) as Box<dyn CaptureOutput>
            })
    }

    fn take_no_response(&self, sequence: u64) -> Option<Box<dyn CaptureOutput>> {
        Some(Box::new(MetadataOutput {
            targets: self.ownerships.take(sequence)?,
            terminal: "no_response",
        }))
    }
}
