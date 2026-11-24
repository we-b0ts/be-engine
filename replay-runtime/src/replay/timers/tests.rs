use super::super::{
    ReplayControlRequest, ReplayRuntime, session, write_test_recording_network_manifest,
};
use super::transport::{Completion, Outcome, read_frame, write_frame};
use super::*;
use crate::ReplayConfig;
use anyhow::Result;
use std::time::Duration;
use tokio::io::BufReader;
use tokio::net::UnixStream;
use tokio::time::timeout;
use traffic_replay::{EventKind, SourceEvent};

struct Fixture {
    _dir: tempfile::TempDir,
    runtime: ReplayRuntime,
    sequence: Arc<SequenceRuntime>,
    client: BufReader<UnixStream>,
    server: tokio::task::JoinHandle<Result<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let case_dir = dir.path().join("case");
        tokio::fs::create_dir(&case_dir).await.unwrap();
        tokio::fs::write(case_dir.join("dependencies.jsonl"), "")
            .await
            .unwrap();
        write_test_recording_network_manifest(&case_dir);
        let runtime = ReplayRuntime::load(
            ReplayConfig {
                case_dir,
                selected_case_ids: vec![],
                dns_listen: "127.0.0.1:0".parse().unwrap(),
                tcp_listen: "127.0.0.1:0".parse().unwrap(),
                fake_cidr: "198.18.0.0/15".into(),
                report_path: None,
                session_path: None,
                control_socket_path: None,
                ca_cert_path: Some(dir.path().join("ca.pem")),
                ca_key_path: Some(dir.path().join("ca-key.pem")),
                policy_path: None,
                http_ignore_query_params: vec![],
                process_owned_dependencies: vec![],
                allowed_unused_http: None,
            },
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();
        let config = ReplayTimerConfig {
            plan_path: dir.path().join("timers.json"),
            socket_path: dir.path().join("timers.sock"),
        };
        let case = runtime.state.lock().await.active_case_id.clone().unwrap();
        tokio::fs::write(
            &config.plan_path,
            serde_json::json!({ "cases": { (case.clone()): [{
                "site": "flush", "stream": "sse", "occurrence": 1,
                "consumed_through": 1, "before_request": 30
            }] } })
            .to_string(),
        )
        .await
        .unwrap();
        let plan = SequencePlan::compile(
            [
                (10, 1, EventKind::Request),
                (20, 1, EventKind::ResponsePart),
                (30, 2, EventKind::Request),
                (40, 2, EventKind::ResponseEnd),
                (50, 1, EventKind::ResponsePart),
                (60, 1, EventKind::ResponseEnd),
            ]
            .into_iter()
            .map(|(sequence, dependency_sequence, kind)| SourceEvent {
                sequence,
                dependency_sequence,
                kind,
                offset_micros: sequence,
            }),
        )
        .unwrap();
        let sequence = {
            let mut state = runtime.state.lock().await;
            state.timers = Timers::load(&config).await.unwrap();
            state.timers.validate_case(&case, Some(&plan)).unwrap();
            Arc::make_mut(state.case_execution_plans.get_mut(&case).unwrap()).sequence = Some(plan);
            state.activate_sequence(Some(&case));
            state.active_sequence.clone().unwrap()
        };
        let listener = Listener::bind(&config.socket_path).unwrap();
        let server = tokio::spawn(listener.run(runtime.state.clone()));
        let client = BufReader::new(UnixStream::connect(&config.socket_path).await.unwrap());
        Self {
            _dir: dir,
            runtime,
            sequence,
            client,
            server,
        }
    }

    async fn for_session() -> Self {
        let mut fixture = Self::new().await;
        let config = ReplayTimerConfig {
            plan_path: fixture._dir.path().join("session-timers.json"),
            socket_path: fixture._dir.path().join("timers.sock"),
        };
        tokio::fs::write(
            &config.plan_path,
            serde_json::json!({ "cases": { (session::TIMER_SCOPE): [{
                "site": "exit", "stream": "sse", "occurrence": 1,
                "consumed_through": 0, "before_event": 50
            }] } })
            .to_string(),
        )
        .await
        .unwrap();
        let plan = SequencePlan::compile(
            [
                (10, 0, EventKind::SessionSourceStart),
                (20, 0, EventKind::SessionStop),
                (30, 30, EventKind::Message),
                (40, 30, EventKind::ResponseEnd),
                (50, 0, EventKind::SessionSourceExit),
            ]
            .map(|(sequence, dependency_sequence, kind)| SourceEvent {
                sequence,
                dependency_sequence,
                kind,
                offset_micros: sequence,
            }),
        )
        .unwrap();
        let mut state = fixture.runtime.state.lock().await;
        state.timers = Timers::load(&config).await.unwrap();
        state
            .timers
            .validate_session(session::TIMER_SCOPE, &plan)
            .unwrap();
        state.timers.activate(Some(session::TIMER_SCOPE));
        fixture.sequence = SequenceRuntime::with_session_timing(
            plan,
            Some(Duration::ZERO),
            state.timers.event_gates(session::TIMER_SCOPE),
        );
        state.session_events = Some(session::Session::new(
            fixture.sequence.clone(),
            Duration::from_secs(2),
        ));
        drop(state);
        fixture
    }

    async fn register(&mut self, site: &str, consumed_through: u64) {
        let state = self.runtime.state.lock().await;
        let case_id = if state.session_events.is_some() {
            session::TIMER_SCOPE.to_owned()
        } else {
            state.active_case_id.clone().unwrap()
        };
        drop(state);
        write_frame(
            self.client.get_mut(),
            &Registration {
                version: 1,
                case_id,
                site: site.into(),
                stream: "sse".into(),
                occurrence: 1,
                consumed_through,
            },
        )
        .await
        .unwrap();
    }

    async fn outcome(&mut self) -> Outcome {
        timeout(Duration::from_secs(2), read_frame(&mut self.client))
            .await
            .unwrap()
            .unwrap()
    }
}

#[tokio::test]
async fn timer_wakes_at_the_existing_frontier_and_releases_only_the_real_request() {
    let mut fixture = Fixture::new().await;
    fixture.register("flush", 1).await;
    let wait = Duration::from_millis(20);
    assert!(
        timeout(wait, read_frame::<Outcome>(&mut fixture.client))
            .await
            .is_err()
    );
    let stream = fixture.sequence.admit(1).unwrap();
    let finish_by = Instant::now() + Duration::from_secs(2);
    stream.wait_delivery(finish_by).await.unwrap();
    stream.publish().unwrap();

    assert_eq!(fixture.outcome().await, Outcome::Wake);
    assert!(fixture.sequence.admit(2).is_err());
    assert!(
        timeout(wait, stream.wait_delivery(finish_by))
            .await
            .is_err()
    );

    let mut changed = fixture.sequence.subscribe();
    write_frame(fixture.client.get_mut(), &Completion::End)
        .await
        .unwrap();
    timeout(Duration::from_secs(2), changed.changed())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fixture.sequence.expected().unwrap().sequence, 30);
    let flush = fixture.sequence.admit(2).unwrap();
    assert!(fixture.sequence.admit(2).is_err());
    flush.wait_delivery(finish_by).await.unwrap();
    flush.publish().unwrap();
    stream.wait_delivery(finish_by).await.unwrap();
    stream.publish().unwrap();
    stream.wait_delivery(finish_by).await.unwrap();
    stream.publish().unwrap();
    assert!(fixture.sequence.complete());

    let state = fixture.runtime.state.lock().await;
    let events = state.timers.events();
    assert_eq!(
        serde_json::to_value(&events[0]).unwrap()["before_request"],
        30
    );
    assert_eq!(
        events.iter().map(|event| event.kind).collect::<Vec<_>>(),
        [
            TimerEventKind::Start,
            TimerEventKind::Wake,
            TimerEventKind::End
        ]
    );
    assert!(
        events
            .windows(2)
            .all(|events| events[0].offset_micros <= events[1].offset_micros)
    );
}

#[tokio::test]
async fn session_exit_wait_wakes_after_real_push_and_requires_timer_completion() {
    let mut fixture = Fixture::for_session().await;
    fixture.sequence.commit_driver(10).unwrap();
    fixture.sequence.commit_driver(20).unwrap();
    fixture.register("exit", 0).await;

    let wait: ReplayControlRequest = serde_json::from_value(serde_json::json!({
        "command": "session_wait", "sequence": 50
    }))
    .unwrap();
    let state = fixture.runtime.state.clone();
    let mut driver = tokio::spawn(async move { session::control(&wait, state).await });
    let push = fixture.sequence.admit(30).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    push.wait_delivery(deadline).await.unwrap();
    let short_wait = Duration::from_millis(20);
    assert!(
        timeout(short_wait, read_frame::<Outcome>(&mut fixture.client))
            .await
            .is_err()
    );

    push.publish().unwrap();
    assert_eq!(fixture.outcome().await, Outcome::Wake);
    assert!(timeout(short_wait, &mut driver).await.is_err());
    assert!(fixture.sequence.commit_driver(50).is_err());
    assert_eq!(fixture.sequence.progress().last_sequence, Some(40));

    write_frame(fixture.client.get_mut(), &Completion::End)
        .await
        .unwrap();
    let response = timeout(Duration::from_secs(2), driver)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response["ok"], true);
    assert!(!fixture.sequence.complete());
    fixture.sequence.commit_driver(50).unwrap();
    assert!(fixture.sequence.complete());

    let state = fixture.runtime.state.lock().await;
    let events = serde_json::to_value(state.timers.events()).unwrap();
    assert_eq!(events[2]["kind"], "timer_end");
    assert_eq!(events[2]["before_event"], 50);
    assert!(events[2].get("before_request").is_none());
}

#[test]
fn before_event_anchor_requires_an_exit_in_the_session_plan() {
    let plan: Plan = serde_json::from_value(serde_json::json!({
        "cases": { (session::TIMER_SCOPE): [{
            "site": "exit", "stream": "sse", "occurrence": 1,
            "consumed_through": 0, "before_event": 20
        }] }
    }))
    .unwrap();
    let source = SequencePlan::compile([SourceEvent {
        sequence: 20,
        dependency_sequence: 0,
        offset_micros: 20,
        kind: EventKind::SessionStop,
    }])
    .unwrap();
    assert!(
        plan.validate_case(session::TIMER_SCOPE, Some(&source))
            .is_err()
    );
    assert!(
        plan.validate_session(session::TIMER_SCOPE, &source)
            .is_err()
    );
}

#[tokio::test]
async fn unplanned_wait_uses_wall_clock_and_wrong_input_position_is_rejected() {
    let mut fixture = Fixture::new().await;
    fixture.register("unplanned", 1).await;
    assert_eq!(fixture.outcome().await, Outcome::WallClock);
    fixture.client = BufReader::new(
        UnixStream::connect(fixture._dir.path().join("timers.sock"))
            .await
            .unwrap(),
    );
    fixture.register("flush", 2).await;
    assert!(matches!(fixture.outcome().await, Outcome::Error { .. }));
    assert!(
        fixture
            .runtime
            .state
            .lock()
            .await
            .timers
            .events()
            .is_empty()
    );
}

#[tokio::test]
async fn advancing_case_epoch_cancels_wait_without_consuming_anchor() {
    let mut fixture = Fixture::new().await;
    fixture.register("flush", 1).await;
    let stream = fixture.sequence.admit(1).unwrap();
    stream
        .wait_delivery(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    stream.publish().unwrap();
    assert_eq!(fixture.outcome().await, Outcome::Wake);

    fixture.runtime.state.lock().await.advance_admission_epoch();
    assert!(matches!(fixture.outcome().await, Outcome::Error { .. }));
    assert!(fixture.sequence.admit(2).is_err());
    assert_eq!(fixture.sequence.expected().unwrap().sequence, 30);
}
