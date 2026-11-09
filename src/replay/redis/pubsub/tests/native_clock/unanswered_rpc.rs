use super::*;

fn notification(payload: &Value) -> Vec<u8> {
    crate::redis::encode_array(&[b"message", b"jobs", &serde_json::to_vec(payload).unwrap()])
}

#[tokio::test]
async fn process_rpc_without_reply_replays_once_after_the_live_local_event() {
    for (lazy, reanchored) in [(false, false), (false, true), (true, false), (true, true)] {
        let temp = tempfile::tempdir().unwrap();
        let (mut globals, _) = fixture(temp.path());
        if reanchored {
            let policy = temp.path().join(".traffic-e2e/policy.yaml");
            std::fs::create_dir_all(policy.parent().unwrap()).unwrap();
            std::fs::write(policy, "format: traffic-policy/v3\n").unwrap();
        }
        globals.truncate(1);
        let sub = Uuid::parse_str(globals[0]["connection_id"].as_str().unwrap()).unwrap();
        let path = temp.path().join("case/expected-response.json");
        let mut response: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        response["interaction"]["events"] = json!([{
            "sequence":1, "message":WireMessage::text("40/chat,{\"sid\":\"source-sid\"}")
        }]);
        std::fs::write(path, response.to_string()).unwrap();
        let mut local: Value = serde_json::from_slice(&request(SOURCE, 1)).unwrap();
        local["event"] = "first".into();
        local["namespace"] = "/chat".into();
        local["room"] = "source-sid".into();
        local["callback"] = json!(["source-sid", "/chat", 1]);
        let mut publish = exchange(
            Uuid::new_v4(),
            1,
            "PUBLISH",
            &[b"jobs", &serde_json::to_vec(&local).unwrap()],
            b":1\r\n",
        );
        publish["timestamp"] = "2020-01-01T00:10:00.010Z".into();
        publish["rpc_callback_capture"] = "bounded_window".into();
        let mut foreign = local.clone();
        foreign["host_id"] = TARGET.into();
        foreign["callback"][2] = 4.into();
        foreign["data"] = json!([{"value":"remote original"}]);
        let mut excluded = foreign.clone();
        excluded["callback"][2] = 5.into();
        excluded["skip_sid"] = "source-sid".into();
        let mut after_close = foreign.clone();
        after_close["callback"][2] = 6.into();
        for (payload, timestamp) in [
            (&local, "2020-01-01T00:10:00.011Z"),
            (&foreign, "2020-01-01T00:10:00.020Z"),
            (&excluded, "2020-01-01T00:10:00.030Z"),
            (&after_close, "2020-01-01T00:10:02Z"),
        ] {
            let mut observed = push(sub, None, &notification(payload), 600_000);
            observed["timestamp"] = timestamp.into();
            globals.push(observed);
        }
        let runtime = runtime(temp.path(), &[publish], &globals, lazy)
            .await
            .unwrap();
        let (mut subscriber, sub_task) = connect(&runtime).await;
        let (mut client, client_task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            SUBSCRIBED
        );
        let epoch = guards::begin(&runtime).await;
        if reanchored {
            let native: chrono::DateTime<chrono::Utc> =
                serde_json::from_value(epoch.clone()).unwrap();
            // A signed derived request has a later validation clock without
            // changing the live native session opened by request_begin.
            runtime
                .state
                .lock()
                .await
                .redis
                .request_contracts
                .restore_request_clock_for_test(CASE, native + chrono::TimeDelta::seconds(1));
        }
        let timing = guards::control(
            &runtime,
            json!({"command":"input_timing_begin","case_id":CASE}),
        )
        .await;
        assert_eq!(timing["epoch"], epoch, "{timing}");
        let received_connect = json!({"command":"native_connected","case_id":CASE,
            "native_event":{"epoch":epoch,"namespace":"/chat","sid":"target-sid"}});
        assert_eq!(
            guards::control(&runtime, received_connect).await["ok"],
            true
        );
        guards::silent(&mut subscriber).await;
        local["room"] = "target-sid".into();
        local["callback"][0] = "target-sid".into();
        assert_eq!(
            send(
                &mut client,
                &[b"PUBLISH", b"jobs", &serde_json::to_vec(&local).unwrap()]
            )
            .await,
            b":1\r\n"
        );
        assert_eq!(read(&mut subscriber).await, notification(&local));
        guards::silent(&mut subscriber).await;
        let event = json!({"command":"native_event","case_id":CASE,
            "native_event":{"epoch":epoch,"event":{"namespace":"/chat","event":"first","ordinal":1}}});
        assert_eq!(guards::control(&runtime, event).await["ok"], true);
        foreign["room"] = "target-sid".into();
        foreign["callback"][0] = "target-sid".into();
        assert_eq!(read(&mut subscriber).await, notification(&foreign));
        guards::silent(&mut subscriber).await;
        let state = runtime.state.lock().await;
        assert_eq!(state.redis.pubsub.report().unwrap().delivered_pushes, 2);
        assert!(state.redis.snapshot().unused_case.is_empty());
        sub_task.abort();
        client_task.abort();
    }
}
