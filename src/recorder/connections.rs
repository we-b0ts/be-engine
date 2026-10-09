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
pub(crate) use transport::DependencyIo;

#[derive(Clone, Default)]
pub(crate) struct DependencyConnections(Arc<Mutex<HashMap<Uuid, Connection>>>);

struct Connection {
    protocol: &'static str,
    sockets: Vec<StdTcpStream>,
}

pub(crate) struct DependencyConnectionGuard {
    registry: DependencyConnections,
    id: Uuid,
}

#[derive(Debug, Serialize)]
pub(crate) struct ConnectionResetReport {
    pub(crate) connections_by_protocol: BTreeMap<&'static str, usize>,
    pub(crate) errors: Vec<String>,
    // Query-level background rules do not prove exclusive ownership of a pool connection.
    pub(crate) ownership: &'static str,
}

impl DependencyConnections {
    pub(crate) fn register(
        &self,
        protocol: &'static str,
        streams: &[&TcpStream],
    ) -> io::Result<DependencyConnectionGuard> {
        let sockets = streams
            .iter()
            .map(|stream| stream.as_fd().try_clone_to_owned().map(StdTcpStream::from))
            .collect::<io::Result<Vec<_>>>()?;
        let id = Uuid::new_v4();
        self.0
            .lock()
            .expect("dependency connections poisoned")
            .insert(id, Connection { protocol, sockets });
        Ok(DependencyConnectionGuard {
            registry: self.clone(),
            id,
        })
    }

    pub(crate) fn reset_open_connections(&self) -> ConnectionResetReport {
        let connections = self.0.lock().expect("dependency connections poisoned");
        let mut report = ConnectionResetReport {
            connections_by_protocol: BTreeMap::new(),
            errors: Vec::new(),
            ownership: "unproven_connection_scope",
        };
        // Keep sockets alive through shutdown so OS descriptor reuse cannot affect
        // a newly opened connection. Registration also waits for this lock.
        for (id, connection) in connections.iter() {
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
