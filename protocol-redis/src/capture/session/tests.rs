use super::*;

#[test]
fn authentication_secrets_are_never_recorded() {
    let auth = RedisCommand {
        name: "AUTH".to_string(),
        args: vec![b"alice".to_vec(), b"super-secret".to_vec()],
    };
    let (args, session_setup, replay_safe, _) = sanitize_and_classify(&auth);
    assert_eq!(args, vec![b"alice".to_vec(), b"<redacted>".to_vec()]);
    assert!(session_setup);
    assert!(replay_safe);

    let hello = RedisCommand {
        name: "HELLO".to_string(),
        args: vec![
            b"3".to_vec(),
            b"AUTH".to_vec(),
            b"alice".to_vec(),
            b"another-secret".to_vec(),
        ],
    };
    let (args, _, _, _) = sanitize_and_classify(&hello);
    assert_eq!(args[2], b"alice");
    assert_eq!(args[3], b"<redacted>");
}

#[test]
fn only_single_subscription_confirmations_are_classified_as_replay_safe() {
    let single = RedisCommand {
        name: "PSUBSCRIBE".to_string(),
        args: vec![b"/0.celery.pidbox".to_vec()],
    };
    let (_, _, replay_safe, warnings) = sanitize_and_classify(&single);
    assert!(replay_safe);
    assert!(warnings.is_empty());

    let multiple = RedisCommand {
        name: "SUBSCRIBE".to_string(),
        args: vec![b"one".to_vec(), b"two".to_vec()],
    };
    let (_, _, replay_safe, warnings) = sanitize_and_classify(&multiple);
    assert!(!replay_safe);
    assert!(warnings[0].contains("exactly one"));

    let unsubscribe = RedisCommand {
        name: "PUNSUBSCRIBE".to_string(),
        args: vec![b"events.*".to_vec()],
    };
    let (_, _, replay_safe, warnings) = sanitize_and_classify(&unsubscribe);
    assert!(replay_safe);
    assert!(warnings.is_empty());

    for args in [vec![], vec![b"one".to_vec(), b"two".to_vec()]] {
        let unsubscribe = RedisCommand {
            name: "UNSUBSCRIBE".to_string(),
            args,
        };
        let (_, _, replay_safe, warnings) = sanitize_and_classify(&unsubscribe);
        assert!(!replay_safe);
        assert!(warnings[0].contains("exactly one"));
    }
}
