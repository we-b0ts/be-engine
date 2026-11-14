//! Native server greeting, optional CLIENT_SSL upgrade and login acknowledgement.
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::TcpStream;
use traffic_protocol::{connection::ConnectionIo, transport::ConnectionControl};

use crate::{HandshakeResponse, MysqlPacket, MysqlSession, parse_handshake_response};

pub struct Connection {
    pub io: Box<dyn ConnectionIo>,
    pub decoder: MysqlSession,
    pub login: HandshakeResponse,
    pub control: ConnectionControl,
}

pub struct PendingLogin {
    connection: Connection,
    login_sequence: u8,
}

impl PendingLogin {
    pub fn login(&self) -> &HandshakeResponse {
        &self.connection.login
    }

    /// The host observes admission before the native acknowledgement is sent.
    pub async fn accept(mut self) -> Result<Connection> {
        crate::write_packet(
            self.connection.io.as_mut(),
            &MysqlPacket {
                sequence_id: self.login_sequence.wrapping_add(1),
                payload: crate::response::ok_payload(0, 0),
            },
        )
        .await?;
        Ok(self.connection)
    }
}

pub async fn negotiate(
    mut stream: TcpStream,
    mut decoder: MysqlSession,
    connection_id: u32,
    tls_config: impl FnOnce() -> Result<Arc<rustls::ServerConfig>> + Send,
) -> Result<PendingLogin> {
    let control = ConnectionControl::new(&stream)?;
    crate::write_packet(
        &mut stream,
        &crate::response::handshake_packet(connection_id),
    )
    .await?;
    let first = crate::read_packet_with_session(&mut stream, decoder.as_mut())
        .await
        .context("failed to read MySQL replay login packet")?
        .context("MySQL replay client closed before login packet")?;
    let login = parse_handshake_response(&first);
    let (io, packet): (Box<dyn ConnectionIo>, MysqlPacket) = if login.tls_requested {
        let mut stream = tokio_rustls::TlsAcceptor::from(tls_config()?)
            .accept(stream)
            .await
            .context("failed to accept MySQL replay client TLS")?;
        let packet = crate::read_packet_with_session(&mut stream, decoder.as_mut())
            .await
            .context("failed to read MySQL replay TLS login packet")?
            .context("MySQL replay TLS client closed before login packet")?;
        (Box::new(stream), packet)
    } else {
        (Box::new(stream), first)
    };
    Ok(PendingLogin {
        connection: Connection {
            io,
            decoder,
            login: parse_handshake_response(&packet),
            control,
        },
        login_sequence: packet.sequence_id,
    })
}
