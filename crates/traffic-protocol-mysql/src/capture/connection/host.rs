//! Protocol facts supplied to the application recording host.
use super::super::MysqlQueryCompletion;
use crate::{
    ClientCommand,
    events::{MysqlConnectionEvent, MysqlQueryEvent},
};
use anyhow::Result;
use std::sync::Arc;
use traffic_model::trace::OutputKind;
use traffic_protocol::connection::{CaptureOutput, NativeFuture};
use uuid::Uuid;

pub struct CaptureRequest<'a> {
    pub connection_id: Uuid,
    pub sequence: u64,
    pub command: &'a ClientCommand,
    pub prepared_sql: Option<&'a str>,
    pub database: Option<&'a str>,
    pub username: Option<&'a str>,
}

pub enum CaptureDecision {
    Admitted,
    Rejected(Box<dyn CaptureOutput>),
}

pub enum CaptureObservation {
    Connection(MysqlConnectionEvent),
    Query(MysqlQueryEvent),
}

/// Native transport submits facts. The host owns authorization, capture
/// lifetimes, attribution, persistence and output receipts.
pub trait CaptureHost: Send + Sync {
    fn server_tls_config(&self, host: &str) -> Result<Arc<rustls::ServerConfig>>;
    fn begin_request<'a>(
        &'a self,
        request: CaptureRequest<'a>,
    ) -> NativeFuture<'a, CaptureDecision>;
    fn observe(&self, event: CaptureObservation) -> NativeFuture<'_, ()>;
    fn complete(&self, completion: MysqlQueryCompletion) -> NativeFuture<'_, ()>;
    fn prepare_output(&self, sequence: u64, output: OutputKind) -> Option<Box<dyn CaptureOutput>>;
    fn take_no_response(&self, sequence: u64) -> Option<Box<dyn CaptureOutput>>;
}
