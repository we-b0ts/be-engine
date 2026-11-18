//! Address discovery failures do not own request admission or Source lifetime.

use super::*;
use crate::record_service::coordination::Coordination;
use crate::redis::{BufferedReader, RedisCommand, read_frame, redis_command};
use tokio::task::JoinSet;

const ADDRESS_KEY: &[u8] = b"registration-test:url";
const TICKET_KEY: &[u8] = b"registration-test:inflight:all-apis";
const POLICY_KEY: &[u8] = b"registration-test:api-policy";
const COUNTS_KEY: &[u8] = b"registration-test:api-counts";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    RejectPolicy,
    RejectCountReset,
    RejectRegistration,
    RejectRenewal,
    LoseRegistrationReply,
    TimeoutRenewal,
}

#[derive(Default)]
struct AddressState {
    policy: Option<Vec<u8>>,
    count: usize,
    startup_commands: Vec<&'static str>,
    value: Option<Vec<u8>>,
    fault: Option<Fault>,
    renewals: usize,
}

impl AddressState {
    fn reply(&mut self, command: RedisCommand) -> Option<Vec<u8>> {
        let args = command.args;
        if command.name == "GET" {
            if args[0] == POLICY_KEY || args[0] == ADDRESS_KEY {
                let value = if args[0] == POLICY_KEY {
                    &self.policy
                } else {
                    &self.value
                };
                let Some(value) = value else {
                    return Some(b"$-1\r\n".to_vec());
                };
                let mut response = format!("${}\r\n", value.len()).into_bytes();
                response.extend(value);
                response.extend(b"\r\n");
                return Some(response);
            }
            assert_eq!(args[0], TICKET_KEY);
            return Some(b"$7\r\ntoken-1\r\n".to_vec());
        }
        if command.name == "SET" {
            if args[0] == POLICY_KEY {
                assert_eq!(args.len(), 2);
                self.startup_commands.push("policy");
                if self.fault == Some(Fault::RejectPolicy) {
                    return Some(b"-ERR policy unavailable\r\n".to_vec());
                }
                self.policy = Some(args[1].clone());
                return Some(b"+OK\r\n".to_vec());
            }
            assert_eq!(args[0], ADDRESS_KEY);
            self.startup_commands.push("url");
            assert_eq!(args[2], b"NX");
            assert_eq!(args[3], b"PX");
            assert_eq!(args[4], b"30000");
            if self.fault == Some(Fault::RejectRegistration) {
                self.fault = None;
                return Some(b"-ERR registration unavailable\r\n".to_vec());
            }
            let created = self.value.is_none();
            if created {
                self.value = Some(args[1].clone());
            }
            if self.fault == Some(Fault::LoseRegistrationReply) {
                self.fault = None;
                return None;
            }
            return Some(if created {
                b"+OK\r\n".to_vec()
            } else {
                b"$-1\r\n".to_vec()
            });
        }
        if command.name == "DEL" {
            assert_eq!(args, [COUNTS_KEY]);
            self.startup_commands.push("counts");
            if self.fault == Some(Fault::RejectCountReset) {
                return Some(b"-ERR count reset unavailable\r\n".to_vec());
            }
            self.count = 0;
            return Some(b":1\r\n".to_vec());
        }
        assert_eq!(command.name, "EVAL");
        if args[2] == TICKET_KEY {
            return Some(b":1\r\n".to_vec());
        }
        assert_eq!(args[2], ADDRESS_KEY);
        let script = std::str::from_utf8(&args[0]).unwrap();
        if script.contains("PEXPIRE") {
            match self.fault {
                Some(Fault::RejectRenewal) => {
                    self.fault = None;
                    return Some(b"-ERR renewal unavailable\r\n".to_vec());
                }
                Some(Fault::TimeoutRenewal) => {
                    self.fault = None;
                    return None;
                }
                _ => {}
            }
        }
        let owned = self.value.as_ref() == Some(&args[3]);
        if owned {
            if script.contains("PEXPIRE") {
                assert_eq!(args[4], b"30000");
                self.renewals += 1;
            } else {
                assert!(script.contains("DEL"));
                self.value = None;
            }
        }
        Some(if owned { b":1\r\n" } else { b":0\r\n" }.to_vec())
    }
}

#[test]
fn startup_publishes_gateway_policy_and_resets_counts_without_touching_heartbeats() {
    runtime().block_on(async {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("api-policy.json");
        std::fs::write(&path, super::api_policy::POLICY).unwrap();
        let policy = crate::record_service::api_policy::ApiPolicy::load(&path).unwrap();
        let fixture = RegistrationFixture::new().await;
        fixture.state.lock().unwrap().count = 200;
        fixture
            .coordination
            .initialize_round(Some(&policy))
            .await
            .unwrap();
        assert_eq!(fixture.state.lock().unwrap().count, 0);
        fixture.coordination.refresh_registration().await;
        assert_eq!(
            fixture.state.lock().unwrap().startup_commands,
            ["policy", "counts", "url"]
        );
        let published: serde_json::Value =
            serde_json::from_slice(fixture.state.lock().unwrap().policy.as_ref().unwrap()).unwrap();
        assert_eq!(published["case-limit"], 200);
        assert_eq!(
            published["includes"][0],
            serde_json::json!({"path":"/api/teams/:id/skills","match":"exact"})
        );
        assert_eq!(
            published["excludes"][0],
            serde_json::json!({"path":"/internal","match":"prefix"})
        );
        // Later operator changes and new counts survive renewal and re-registration.
        fixture.state.lock().unwrap().policy = Some(b"{\"case-limit\":0}".to_vec());
        fixture.state.lock().unwrap().count = 7;
        fixture.coordination.refresh_registration().await;
        fixture.state.lock().unwrap().value = None;
        fixture.coordination.refresh_registration().await;
        fixture.coordination.unregister().await.unwrap();
        let state = fixture.state.lock().unwrap();
        assert_eq!(state.count, 7);
        assert_eq!(
            state.policy.as_deref(),
            Some(b"{\"case-limit\":0}".as_slice())
        );
        assert_eq!(state.startup_commands, ["policy", "counts", "url", "url"]);
        assert!(state.value.is_none());
    });
}

#[test]
fn startup_without_policy_resets_counts_and_replaces_previous_selection_with_all_apis() {
    runtime().block_on(async {
        let fixture = RegistrationFixture::new().await;
        fixture.state.lock().unwrap().policy =
            Some(br#"{"case-limit":0,"excludes":[{"path":"/"}]}"#.to_vec());
        fixture.state.lock().unwrap().count = 3;
        fixture.coordination.initialize_round(None).await.unwrap();
        {
            let state = fixture.state.lock().unwrap();
            let policy: serde_json::Value =
                serde_json::from_slice(state.policy.as_ref().unwrap()).unwrap();
            assert_eq!(policy, serde_json::json!({"includes":[],"excludes":[]}));
            assert_eq!(state.count, 0);
            assert_eq!(state.startup_commands, ["policy", "counts"]);
        }
    });
}

#[test]
fn startup_policy_or_count_failure_is_fatal_before_address_publication() {
    runtime().block_on(async {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("api-policy.json");
        std::fs::write(&path, super::api_policy::POLICY).unwrap();
        let policy = crate::record_service::api_policy::ApiPolicy::load(&path).unwrap();
        for fault in [Fault::RejectPolicy, Fault::RejectCountReset] {
            let fixture = RegistrationFixture::new().await;
            fixture.state.lock().unwrap().count = 11;
            fixture.fault(fault);
            assert!(
                fixture
                    .coordination
                    .initialize_round(Some(&policy))
                    .await
                    .is_err()
            );
            let state = fixture.state.lock().unwrap();
            assert!(state.value.is_none());
            assert_eq!(state.count, 11);
            assert_eq!(
                state.startup_commands,
                if fault == Fault::RejectPolicy {
                    vec!["policy"]
                } else {
                    vec!["policy", "counts"]
                }
            );
        }
        let options = OptionsCli::try_parse_from(["test", "--", "true"])
            .unwrap()
            .options;
        let direct = Coordination::connect(&options).await.unwrap();
        direct.initialize_round(None).await.unwrap();
        assert!(direct.reservations.is_none());
    });
}

struct RegistrationFixture {
    coordination: Coordination,
    state: Arc<Mutex<AddressState>>,
    server: JoinHandle<()>,
}

impl RegistrationFixture {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(AddressState::default()));
        let serving = state.clone();
        let server = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let state = serving.clone();
                connections.spawn(async move {
                    let (reader, mut writer) = stream.into_split();
                    let mut reader = BufferedReader::new(reader, 65536);
                    while let Ok(Some(frame)) = read_frame(&mut reader).await {
                        let command = redis_command(&frame.raw).unwrap();
                        let reply = state.lock().unwrap().reply(command);
                        let Some(reply) = reply else {
                            std::future::pending::<()>().await;
                            unreachable!();
                        };
                        if writer.write_all(&reply).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        let options = OptionsCli::try_parse_from([
            "test",
            "--coordination",
            "redis",
            "--redis-url",
            &format!("redis://{endpoint}/0"),
            "--advertise-url",
            "http://recorder:4080",
            "--prefix",
            "registration-test",
            "--",
            "true",
        ])
        .unwrap()
        .options;
        let coordination = Coordination::connect(&options).await.unwrap();
        Self {
            coordination,
            state,
            server,
        }
    }

    fn fault(&self, fault: Fault) {
        self.state.lock().unwrap().fault = Some(fault);
    }

    fn value(&self) -> Option<Vec<u8>> {
        self.state.lock().unwrap().value.clone()
    }

    async fn wait_for_renewal(&self) {
        // Reconnection after a real 200 ms transport timeout is the behavior under test.
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                self.coordination.refresh_registration().await;
                if self.state.lock().unwrap().renewals > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the Redis client did not reconnect and renew the address");
    }
}

impl Drop for RegistrationFixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

#[test]
fn failed_initial_registration_recovers_and_expired_address_is_recreated() {
    runtime().block_on(async {
        let fixture = RegistrationFixture::new().await;
        fixture.fault(Fault::RejectRegistration);
        fixture.coordination.refresh_registration().await;
        assert!(fixture.value().is_none());
        fixture.coordination.refresh_registration().await;
        let original = fixture.value().unwrap();
        fixture.state.lock().unwrap().value = None;
        fixture.coordination.refresh_registration().await;
        assert_eq!(fixture.value().unwrap(), original);
        fixture.coordination.unregister().await.unwrap();
        assert!(fixture.value().is_none());
    });
}

#[test]
fn address_replacement_is_neither_overwritten_nor_unregistered() {
    runtime().block_on(async {
        let fixture = RegistrationFixture::new().await;
        fixture.coordination.refresh_registration().await;
        let original = fixture.value().unwrap();
        let replacement = br#"{"url":"http://other-recorder:4080","owner":"other-owner"}"#.to_vec();
        fixture.state.lock().unwrap().value = Some(replacement.clone());
        fixture.coordination.refresh_registration().await;
        fixture.coordination.unregister().await.unwrap();
        assert_eq!(fixture.value(), Some(replacement));
        fixture.state.lock().unwrap().value = None;
        fixture.coordination.refresh_registration().await;
        assert_eq!(fixture.value(), Some(original));
    });
}

#[test]
fn lost_registration_reply_recovers_and_unregister_failure_relies_on_ttl() {
    runtime().block_on(async {
        let mut fixture = RegistrationFixture::new().await;
        fixture.fault(Fault::LoseRegistrationReply);
        fixture.coordination.refresh_registration().await;
        let original = fixture.value().unwrap();
        // SET succeeded without an acknowledgement, so renewing must recognize our owner.
        fixture.wait_for_renewal().await;
        assert_eq!(fixture.value(), Some(original.clone()));
        fixture.server.abort();
        let _ = (&mut fixture.server).await;
        assert!(fixture.coordination.unregister().await.is_err());
        assert_eq!(fixture.value(), Some(original));
    });
}

#[test]
fn registration_errors_and_timeouts_preserve_in_flight_response_and_next_request() {
    runtime().block_on(async {
        let fixture = RegistrationFixture::new().await;
        fixture.coordination.refresh_registration().await;
        let original = fixture.value().unwrap();
        let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay = proxy::Relay::new(
            fixture.coordination.reservations.clone(),
            format!("http://{}", source.local_addr().unwrap()).parse().unwrap(),
            "all-apis".into(), Duration::from_secs(3), 1024,
        );
        relay.open();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let (stop, stopped) = watch::channel(false);
        let adapter = tokio::spawn(proxy::serve(listener, relay, stopped));
        let entered = Arc::new(Notify::new());
        let finish = Arc::new(Notify::new());
        let (accepted, finish_request) = (entered.clone(), finish.clone());
        let source_task = tokio::spawn(async move {
            for sequence in 0..2 {
                let (mut stream, _) = source.accept().await.unwrap();
                assert!(read_request(&mut stream).await.starts_with("POST /api/test"));
                if sequence == 0 {
                    accepted.notify_one();
                    finish_request.notified().await;
                }
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\ncomplete").await.unwrap();
            }
        });
        let request = |origin: String| async move {
            let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
            let response = client.request(Request::post(format!("{origin}/api/test"))
                .header("x-breeze-admission-scope", "all-apis")
                .header("x-breeze-admission-token", "token-1")
                .body(Full::new(Bytes::from_static(b"request"))).unwrap()).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.into_body().collect().await.unwrap().to_bytes(), "complete");
        };
        let in_flight = tokio::spawn(request(origin.clone()));
        tokio::time::timeout(Duration::from_secs(3), entered.notified()).await.unwrap();
        fixture.fault(Fault::RejectRenewal);
        fixture.coordination.refresh_registration().await;
        fixture.fault(Fault::TimeoutRenewal);
        fixture.coordination.refresh_registration().await;
        assert!(!in_flight.is_finished());
        assert_eq!(fixture.value(), Some(original));
        finish.notify_one();
        tokio::time::timeout(Duration::from_secs(3), in_flight).await.unwrap().unwrap();
        fixture.wait_for_renewal().await;
        request(origin).await;
        source_task.await.unwrap();
        stop.send(true).unwrap();
        adapter.await.unwrap().unwrap();
    });
}
