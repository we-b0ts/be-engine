use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn accepted_replay_tcp_connections_disable_nagle() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(TcpStream::connect(address));

        let (server, _) = accept_replay_tcp_connection(&listener).await.unwrap();
        let _client = client.await.unwrap().unwrap();

        assert!(server.nodelay().unwrap());
    }

    #[test]
    fn replay_target_requires_the_recorded_port_when_multiple_targets_are_loaded() {
        let targets = vec![
            ReplayTarget {
                host: "cache.internal".to_string(),
                port: 9447,
                fake_ip: "198.19.0.2".parse().unwrap(),
                protocol: ReplayProtocol::Redis,
            },
            ReplayTarget {
                host: "redis.internal".to_string(),
                port: 9352,
                fake_ip: "198.19.0.2".parse().unwrap(),
                protocol: ReplayProtocol::Redis,
            },
        ];

        let matched =
            replay_target_for_original(Some("198.19.0.2:9352".parse().unwrap()), &targets).unwrap();
        assert_eq!(matched.protocol, ReplayProtocol::Redis);
        assert!(
            replay_target_for_original(Some("198.19.0.2:9351".parse().unwrap()), &targets)
                .is_none()
        );
    }
}
