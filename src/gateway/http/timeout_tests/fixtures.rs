use std::convert::Infallible;
use std::net::SocketAddr;

use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

use crate::AppState;
use crate::mysql::wire::{CLIENT_CONNECT_WITH_DB, MysqlPacket, read_packet};
use crate::protocols::mysql::{MysqlConnectionContext, handle_connected_mysql};

pub(super) async fn gateway(state: AppState) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let state = state.clone();
            connections.spawn(async move {
                let service = service_fn(move |request| {
                    let state = state.clone();
                    async move {
                        let config = state.config().http_gateway.clone();
                        Ok::<_, Infallible>(
                            super::super::handle_gateway_request(request, state, config, None)
                                .await,
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (addr, task)
}

pub(super) async fn get(addr: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}

pub(super) async fn request(stream: &mut TcpStream) {
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).await.unwrap();
        request.push(byte[0]);
    }
}

pub(super) async fn reply(stream: &mut TcpStream, body: &str) {
    stream
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
}

async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (client, accepted) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    (client.unwrap(), accepted.unwrap().0)
}

pub(super) struct MysqlClient {
    pub(super) stream: TcpStream,
    proxy: JoinHandle<anyhow::Result<()>>,
    server: JoinHandle<()>,
}

impl MysqlClient {
    pub(super) async fn connect(state: AppState) -> Self {
        let (mut client, proxy_client) = pair().await;
        let (proxy_upstream, mut server) = pair().await;
        let proxy = tokio::spawn(handle_connected_mysql(
            proxy_client,
            proxy_upstream,
            state,
            MysqlConnectionContext {
                route_name: Some("test".into()),
                listen_addr: "127.0.0.1:0".into(),
                client_addr: None,
                target_host: Some("mysql.test".into()),
                target_port: Some(3306),
                target_addr: Some("mysql.test:3306".into()),
                upstream_addr: "127.0.0.1:3306".into(),
            },
        ));
        let server = tokio::spawn(async move {
            server.write_all(&packet(0, &[0x0a])).await.unwrap();
            read_packet(&mut server).await.unwrap().unwrap();
            server.write_all(&ok(2)).await.unwrap();
            while let Some(query) = read_packet(&mut server).await.unwrap() {
                assert_eq!(query.payload[0], 3);
                server.write_all(&ok(1)).await.unwrap();
            }
        });
        read_packet(&mut client).await.unwrap().unwrap();
        let mut login = vec![0; 32];
        login[..4].copy_from_slice(&CLIENT_CONNECT_WITH_DB.to_le_bytes());
        login.extend_from_slice(b"test\0\0appdb\0");
        client.write_all(&packet(1, &login)).await.unwrap();
        read_packet(&mut client).await.unwrap().unwrap();
        Self {
            stream: client,
            proxy,
            server,
        }
    }

    pub(super) async fn query(&mut self, sql: &str) {
        self.stream
            .write_all(&packet(0, &[&[3], sql.as_bytes()].concat()))
            .await
            .unwrap();
        read_packet(&mut self.stream).await.unwrap().unwrap();
    }

    pub(super) async fn close(self) {
        drop(self.stream);
        self.proxy.await.unwrap().unwrap();
        self.server.await.unwrap();
    }
}

fn packet(sequence_id: u8, payload: &[u8]) -> Vec<u8> {
    MysqlPacket {
        sequence_id,
        payload: payload.to_vec(),
    }
    .to_wire_bytes()
}

fn ok(sequence_id: u8) -> Vec<u8> {
    packet(sequence_id, &[0, 0, 0, 2, 0, 0, 0])
}
