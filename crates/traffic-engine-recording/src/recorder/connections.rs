//! Live dependency sockets owned by Recorder, excluding primary requests and listeners.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::{Shutdown, TcpStream as StdTcpStream};
use std::os::fd::AsFd;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio::net::TcpStream;
use uuid::Uuid;

mod transport;
pub use transport::DependencyIo;

#[derive(Clone, Default)]
pub struct DependencyConnections(Arc<Mutex<HashMap<Uuid, Connection>>>);

struct Connection {
    protocol: &'static str,
    sockets: Vec<StdTcpStream>,
    termination: Option<crate::dependency::termination::ConnectionTermination>,
}

pub struct DependencyConnectionGuard {
    registry: DependencyConnections,
    id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct ConnectionResetReport {
    pub connections_by_protocol: BTreeMap<&'static str, usize>,
    pub errors: Vec<String>,
    // Query-level background rules do not prove exclusive ownership of a pool connection.
    pub ownership: &'static str,
}

impl DependencyConnections {
    pub fn register(
        &self,
        protocol: &'static str,
        streams: &[&TcpStream],
    ) -> io::Result<DependencyConnectionGuard> {
        self.register_inner(protocol, streams, None)
    }

    pub fn register_observed(
        &self,
        protocol: &'static str,
        streams: &[&TcpStream],
        termination: &crate::dependency::termination::ConnectionTermination,
    ) -> io::Result<DependencyConnectionGuard> {
        self.register_inner(protocol, streams, Some(termination.clone()))
    }

    fn register_inner(
        &self,
        protocol: &'static str,
        streams: &[&TcpStream],
        termination: Option<crate::dependency::termination::ConnectionTermination>,
    ) -> io::Result<DependencyConnectionGuard> {
        let sockets = streams
            .iter()
            .map(|stream| stream.as_fd().try_clone_to_owned().map(StdTcpStream::from))
            .collect::<io::Result<Vec<_>>>()?;
        let id = Uuid::new_v4();
        self.0
            .lock()
            .expect("dependency connections poisoned")
            .insert(
                id,
                Connection {
                    protocol,
                    sockets,
                    termination,
                },
            );
        Ok(DependencyConnectionGuard {
            registry: self.clone(),
            id,
        })
    }

    pub fn reset_open_connections(&self) -> ConnectionResetReport {
        let connections = self.0.lock().expect("dependency connections poisoned");
        let mut report = ConnectionResetReport {
            connections_by_protocol: BTreeMap::new(),
            errors: Vec::new(),
            ownership: "unproven_connection_scope",
        };
        // Keep sockets alive through shutdown so OS descriptor reuse cannot affect
        // a newly opened connection. Registration also waits for this lock.
        for (id, connection) in connections.iter() {
            if let Some(termination) = &connection.termination {
                termination.observe_engine_stop();
            }
            *report
                .connections_by_protocol
                .entry(connection.protocol)
                .or_default() += 1;
            for socket in &connection.sockets {
                if let Err(error) = socket.shutdown(Shutdown::Both)
                    && error.kind() != io::ErrorKind::NotConnected
                {
                    report.errors.push(format!("{id}: {error}"));
                }
            }
        }
        report
    }
}

impl Drop for DependencyConnectionGuard {
    fn drop(&mut self) {
        self.registry
            .0
            .lock()
            .expect("dependency connections poisoned")
            .remove(&self.id);
    }
}

#[cfg(test)]
mod tests;
