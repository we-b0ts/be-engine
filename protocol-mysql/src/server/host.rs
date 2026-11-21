//! Ports for request selection, wire delivery and application observations.
use traffic_protocol::connection::{ConnectionIo, NativeFuture};

use super::{Directive, Session};
use crate::{
    model::{MysqlValue, ResultRowEncoding},
    prepare::StatementMetadata,
    recorded::RecordedMysqlResponse,
};

#[derive(Clone, Copy)]
pub struct Request<'a> {
    pub command: &'a str,
    pub sql: Option<&'a str>,
    pub params: Option<&'a [MysqlValue]>,
}

pub struct Selection<D, C> {
    pub delivery: Option<D>,
    pub context: C,
}

pub trait ServerHost: Send + Sync {
    type SessionContext: Send + Sync;
    type RequestContext: Send + Sync;
    type Delivery: Send;
    type Evidence: Send + Sync;

    fn stopping(&self) -> NativeFuture<'_, bool>;

    fn response(
        delivery: &Self::Delivery,
    ) -> (
        traffic_model::DependencyExchangeOutcome,
        &RecordedMysqlResponse<Self::Evidence>,
    );

    fn select<'a>(
        &'a self,
        session: &'a Session<Self::SessionContext>,
        request: Request<'a>,
    ) -> NativeFuture<'a, Selection<Self::Delivery, Self::RequestContext>>;

    fn deliver<'a>(
        &'a self,
        io: &'a mut dyn ConnectionIo,
        session: &'a mut Session<Self::SessionContext>,
        delivery: Self::Delivery,
        encoding: ResultRowEncoding,
    ) -> NativeFuture<'a, Directive>;

    fn statement_metadata<'a>(
        &'a self,
        session: &'a Session<Self::SessionContext>,
        context: &'a Self::RequestContext,
        sql: &'a str,
    ) -> NativeFuture<'a, std::sync::Arc<StatementMetadata>>;

    fn before_builtin(
        &self,
        session: &mut Session<Self::SessionContext>,
        context: &Self::RequestContext,
        request: Request<'_>,
        response: &RecordedMysqlResponse<Self::Evidence>,
    );

    fn builtin_delivered<'a>(
        &'a self,
        session: &'a mut Session<Self::SessionContext>,
        context: &'a Self::RequestContext,
        request: Request<'a>,
        previous_status: Option<u16>,
    ) -> NativeFuture<'a, ()>;

    fn unmatched<'a>(
        &'a self,
        session: &'a Session<Self::SessionContext>,
        context: Option<&'a Self::RequestContext>,
        request: Request<'a>,
        reason: &'a str,
    ) -> NativeFuture<'a, ()>;

    fn unsupported<'a>(
        &'a self,
        session: &'a Session<Self::SessionContext>,
        request: Request<'a>,
        reason: &'a str,
    ) -> NativeFuture<'a, ()>;

    fn statement_closed<'a>(
        &'a self,
        session: &'a Session<Self::SessionContext>,
    ) -> NativeFuture<'a, ()>;

    fn warning(&self, warning: String) -> NativeFuture<'_, ()>;
}
