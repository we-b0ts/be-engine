//! Finite RPC and self-echo PUBLISH own the same lease before delivery starts.
use super::*;

const CONFIRMED: &[u8] = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";

#[tokio::test]
async fn finite_rpc_and_self_echo_publish_cancel_during_the_real_pre_delivery_durable_wait() {
    for rpc_callback in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let subscriber = Uuid::new_v4();
        let publisher = Uuid::new_v4();
        let payload = request(SOURCE, 1);
        let mut publication = exchange(publisher, 1, "PUBLISH", &[b"jobs", &payload], b":1\r\n");
        let raw = crate::redis::encode_array(&[
            b"message",
            b"jobs",
            &if rpc_callback {
                callback(SOURCE, 1)
            } else {
                payload.clone()
            },
        ]);
        let notification = push(subscriber, rpc_callback.then_some(publisher), &raw, 0);
        let mut cases = vec![publication.clone()];
        let mut globals = vec![exchange(subscriber, 1, "SUBSCRIBE", &[b"jobs"], CONFIRMED)];
        if rpc_callback {
            cases.push(notification);
        } else {
            publication["rpc_callback_capture"] = json!("bounded_window");
            cases[0] = publication;
            globals.push(notification);
        }
        let runtime = runtime(temp.path(), &cases, &globals, false).await.unwrap();
        let (mut client, task) = connect(&runtime).await;
        assert_eq!(send(&mut client, &[b"SUBSCRIBE", b"jobs"]).await, CONFIRMED);
        let target = TargetKey {
            host: "redis.test".into(),
            port: 6379,
        };
        let matched = {
            let mut state = runtime.state.lock().await;
            state
                .redis
                .match_redis(
                    Some("case"),
                    &target,
                    TargetConnection::default(),
                    2,
                    0,
                    None,
                    "PUBLISH",
                    &[b"jobs".to_vec(), payload],
                )
                .unwrap()
        };
        assert_eq!(matched.rpc_push.is_some(), rpc_callback);
        assert!(rpc_callback || matched.adapter_echo.is_some());
        assert!(matches!(matched.claim, Claim::Finite(_)));
        let index = matched.index;
        let state_ref = runtime.state.clone();
        let state = runtime.state.lock().await;
        let before = state.redis.events.matched_count;
        let wait = async move {
            crate::replay::policy::request_contract::hypotheses::await_durable(&state_ref)
                .await
                .unwrap();
            drop(matched);
        };
        let mut wait = Box::pin(wait);
        tokio::select! {biased; ()=&mut wait=>panic!("real durable wait must park before delivery guard"),_=std::future::ready(())=>{}}
        drop(wait);
        assert_eq!(
            state.redis.exchange_status(index),
            Some(ReplayExchangeStatus::Failed)
        );
        assert_eq!(state.redis.lifecycle.cancelled_indices(), [index]);
        assert_eq!(state.redis.events.matched_count, before);
        assert!(!state.redis.has_case_in_flight());
        assert!(
            state
                .redis
                .snapshot()
                .unused_case
                .iter()
                .any(|exchange| exchange.index == index)
        );
        task.abort();
    }
}
