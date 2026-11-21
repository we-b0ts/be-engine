//! Native socket and prepared-statement state with opaque host-owned context.
use std::collections::HashMap;

use traffic_protocol::{connection::Endpoint, transport::ConnectionControl};

use crate::{
    HandshakeResponse, model::PreparedStatement, session_identity::SessionIdentity,
    types::SERVER_STATUS_AUTOCOMMIT,
};

pub struct Session<C> {
    pub control: ConnectionControl,
    pub request_started: tokio::time::Instant,
    pub target: Option<Endpoint>,
    pub database: Option<String>,
    pub username: Option<String>,
    pub next_statement_id: u32,
    pub status_flags: u16,
    pub statements: HashMap<u32, PreparedStatement>,
    pub context: C,
}

impl<C> Session<C> {
    pub fn new(
        control: ConnectionControl,
        target: Option<Endpoint>,
        login: HandshakeResponse,
        context: C,
    ) -> Self {
        Self {
            control,
            request_started: tokio::time::Instant::now(),
            target,
            database: login.database,
            username: login.username,
            next_statement_id: 1,
            status_flags: SERVER_STATUS_AUTOCOMMIT,
            statements: HashMap::new(),
            context,
        }
    }

    pub fn identity(&self) -> SessionIdentity {
        SessionIdentity {
            target: self.target.clone(),
            database: self.database.clone(),
            username: self.username.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Directive {
    Continue,
    Close,
}
