//! Read-only host facts used by native session constraints.
use crate::{
    recorded::RecordedMysqlExchange, session_control::OptionalSessionExchange,
    session_identity::DependencyIdentity,
};
use traffic_model::attribution::DependencyScope;
use traffic_protocol::evidence::RecordSource;

pub struct SourceExchange<'a, E> {
    pub record: &'a RecordedMysqlExchange<E>,
    pub identity: &'a DependencyIdentity,
    pub source: DependencyScope,
    pub case_id: Option<&'a str>,
    pub optional_session: Option<OptionalSessionExchange>,
}

/// The host supplies immutable Source projections and actual lifecycle facts.
/// Native constraints can inspect these facts without reserving or consuming work.
pub trait SessionContext {
    type Evidence: Clone + RecordSource;

    fn exchange(&self, index: usize) -> SourceExchange<'_, Self::Evidence>;
    fn available(&self, index: usize) -> bool;
    fn admitted(&self, index: usize) -> bool;
    fn delivered(&self, index: usize) -> bool;
}
