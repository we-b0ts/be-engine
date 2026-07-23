use super::*;

fn frame(request_id: u64, request: bool, inner_flag: u8) -> Vec<u8> {
    let body = b"payload";
    let mut inner = vec![0_u8; 16];
    inner[..2].copy_from_slice(&[0xF0, 0xF0]);
    inner[2] = 1;
    inner[3] = inner_flag;
    inner[4..12].copy_from_slice(&request_id.to_be_bytes());
    inner[12..16].copy_from_slice(&(body.len() as u32).to_be_bytes());
    inner.extend_from_slice(body);
    let mut outer = vec![0_u8; 16];
    outer[..2].copy_from_slice(&[0xF1, 0xF1]);
    outer[3] = if request { 0 } else { 1 };
    outer[4..12].copy_from_slice(&request_id.to_be_bytes());
    outer[12..16].copy_from_slice(&(inner.len() as u32).to_be_bytes());
    outer.extend_from_slice(&inner);
    outer
}

fn capture(bytes: &[u8]) -> RecordedCapture {
    RecordedCapture {
        encoding: "base64".to_string(),
        data: STANDARD.encode(bytes),
        truncated: false,
    }
}

fn exchange(heartbeat: bool) -> RecordedExchange {
    let identity = if heartbeat {
        (
            Some("com.weibo.api.motan.rpc.heartbeat".to_string()),
            Some("heartbeat".to_string()),
            Some("void".to_string()),
        )
    } else {
        (
            Some("cn.sina.api.data.service.SinaUserService".to_string()),
            Some("getUser".to_string()),
            Some("long".to_string()),
        )
    };
    RecordedExchange {
        connection_id: Uuid::nil(),
        sequence: 1,
        target_host: "vintage-node-a.trp.test".to_string(),
        target_port: 8881,
        advertised_ip: "198.19.0.20".parse().unwrap(),
        codec_version: 1,
        interface_name: identity.0,
        method_name: identity.1,
        parameter_desc: identity.2,
        method_sign: None,
        command: if heartbeat {
            "com.weibo.api.motan.rpc.heartbeat#heartbeat".to_string()
        } else {
            "cn.sina.api.data.service.SinaUserService#getUser".to_string()
        },
        request: capture(&frame(1, true, 0)),
        response: capture(&frame(1, false, 1)),
        heartbeat,
        outcome: DependencyExchangeOutcome::Response,
        duration_ms: 0,
        replay_safe: true,
    }
}

#[test]
fn business_exchange_matches_across_nodes_in_same_rpc_pool() {
    let mut state = MotanReplayState::default();
    let mut targets = BTreeMap::new();
    state
        .register_exchange(
            exchange(false),
            ReplaySource::Case,
            Some("case"),
            &mut targets,
        )
        .unwrap();
    let identity = RequestIdentity {
        interface_name: Some("cn.sina.api.data.service.SinaUserService".to_string()),
        method_name: Some("getUser".to_string()),
        parameter_desc: Some("long".to_string()),
        method_sign: None,
    };

    let matched = state
        .match_exchange(
            Some("case"),
            &TargetKey {
                host: "vintage-node-b.trp.test".to_string(),
                port: 8881,
            },
            None,
            1,
            &identity,
        )
        .unwrap();
    state.complete(&matched);
    assert_eq!(state.snapshot().matched_count, 1);
    assert!(state.snapshot().unused_case.is_empty());
}

#[test]
fn heartbeat_template_can_serve_another_node_and_patch_request_id() {
    let mut state = MotanReplayState::default();
    let mut targets = BTreeMap::new();
    state
        .register_heartbeat(exchange(true), &mut targets)
        .unwrap();
    let mut template = state
        .heartbeat(
            &TargetKey {
                host: "vintage-node-b.trp.test".to_string(),
                port: 8881,
            },
            1,
        )
        .unwrap();

    patch_request_id(&mut template.response, 77).unwrap();
    assert_eq!(
        u64::from_be_bytes(template.response[4..12].try_into().unwrap()),
        77
    );
    assert_eq!(
        u64::from_be_bytes(template.response[20..28].try_into().unwrap()),
        77
    );
}
