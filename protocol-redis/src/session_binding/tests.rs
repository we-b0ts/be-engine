use super::*;

#[derive(Clone)]
struct Record {
    sequence: u64,
    command: String,
    session_setup: bool,
}
impl RecordedSession for Record {
    fn connection_id(&self) -> Uuid {
        Uuid::nil()
    }
    fn sequence(&self) -> u64 {
        self.sequence
    }
    fn command(&self) -> &str {
        &self.command
    }
    fn session_setup(&self) -> bool {
        self.session_setup
    }
}

#[test]
fn subscription_boundary_keeps_unknown_state_and_unproven_starts_strict() {
    for command in ["SUBSCRIBE", "PSUBSCRIBE", "SSUBSCRIBE"] {
        let subscription = Record {
            sequence: 25,
            command: command.into(),
            session_setup: false,
        };
        let mut lane = LaneState::default();
        lane.register(&subscription);
        assert!(!lane.contains(24));
        assert!(lane.contains(25));
        assert!(lane.contains(26));
        for session_command in ["WATCH", "MULTI", "WAIT", "AUTH"] {
            let mut guarded = LaneState::default();
            guarded.register(&subscription);
            let mut session = subscription.clone();
            session.sequence = 26;
            session.command = session_command.into();
            guarded.register(&session);
            assert!(guarded.contains(24), "{session_command} remains strict");
        }
        let mut setup = subscription.clone();
        setup.session_setup = true;
        lane.register(&setup);
        assert!(lane.contains(24));
    }
    let mut unsubscribe = Record {
        sequence: 26,
        command: "UNSUBSCRIBE".into(),
        session_setup: false,
    };
    let mut subscribe = unsubscribe.clone();
    subscribe.sequence = 25;
    subscribe.command = "SUBSCRIBE".into();
    for reverse in [false, true] {
        let mut lane = LaneState::default();
        if reverse {
            lane.register(&unsubscribe);
            assert!(lane.contains(24));
        }
        lane.register(&subscribe);
        lane.register(&unsubscribe);
        assert!(!lane.contains(24));
        assert!(lane.contains(26));
    }
    unsubscribe.sequence = 24;
    let mut lane = LaneState::default();
    lane.register(&subscribe);
    lane.register(&unsubscribe);
    assert!(
        lane.contains(23),
        "an earlier subscription lifetime is unproven"
    );
}
