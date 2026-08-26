use super::*;

use motan_codec::{Attachment, Attachments, Motan1RequestBuilder, Motan1RequestLimits};

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
    let request = if heartbeat {
        frame(1, true, 0)
    } else {
        business_request(1, 1, None)
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
        request: capture(&request),
        response: capture(&frame(1, false, 1)),
        heartbeat,
        outcome: DependencyExchangeOutcome::Response,
        duration_ms: 0,
        replay_safe: true,
    }
}

fn business_request(request_id: u64, uid: i64, authorization: Option<&str>) -> Vec<u8> {
    let mut attachments = Attachments::new();
    if let Some(authorization) = authorization {
        attachments.insert(Attachment::new("Authorization", authorization));
    }
    Motan1RequestBuilder::new(
        "cn.sina.api.data.service.SinaUserService",
        "getUser",
        "long",
    )
    .request_id(request_id)
    .hessian_argument(motan_hessian2::to_vec(&uid, motan_hessian2::Limits::default()).unwrap())
    .attachments(attachments)
    .build(Motan1RequestLimits::default())
    .unwrap()
    .raw()
    .to_vec()
}

fn request_match(raw: Vec<u8>) -> RequestMatch {
    RequestMatch::from_frame(&crate::motan::Frame::decode(raw).unwrap())
        .unwrap()
        .unwrap()
}

fn business_identity() -> RequestIdentity {
    RequestIdentity {
        interface_name: Some("cn.sina.api.data.service.SinaUserService".to_string()),
        method_name: Some("getUser".to_string()),
        parameter_desc: Some("long".to_string()),
        method_sign: None,
    }
}

fn business_target() -> TargetKey {
    TargetKey {
        host: "vintage-node-b.trp.test".to_string(),
        port: 8881,
    }
}

fn state_with_business_request(uid: i64, authorization: Option<&str>) -> MotanReplayState {
    let mut state = MotanReplayState::default();
    let mut targets = BTreeMap::new();
    let mut recorded = exchange(false);
    recorded.request = capture(&business_request(1, uid, authorization));
    state
        .register_exchange(recorded, ReplaySource::Case, Some("case"), &mut targets)
        .unwrap();
    state
}

fn mismatch_fields(
    result: std::result::Result<MatchedExchange, CommandMatchDiagnostic>,
) -> Vec<String> {
    match result.unwrap_err() {
        CommandMatchDiagnostic::Mismatch { fields } => fields,
        diagnostic => panic!("expected mismatch diagnostic, got {diagnostic:?}"),
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
    let identity = business_identity();
    let request_match = request_match(business_request(2, 1, None));

    let matched = state
        .match_exchange(
            Some("case"),
            &business_target(),
            None,
            1,
            &identity,
            Some(&request_match),
        )
        .unwrap();
    state.complete(&matched);
    assert_eq!(state.snapshot().matched_count, 1);
    assert!(state.snapshot().unused_case.is_empty());
}

#[test]
fn business_exchange_matches_when_tauth2_credentials_rotate() {
    let source = "TAuth2 token=\"old\",param=\"uid%3D1\",sign=\"first\"";
    let target = "TAuth2 token=\"new\",param=\"uid%3D1\",sign=\"second\"";
    let mut state = state_with_business_request(1, Some(source));
    let request_match = request_match(business_request(2, 1, Some(target)));

    let matched = state
        .match_exchange(
            Some("case"),
            &business_target(),
            None,
            1,
            &business_identity(),
            Some(&request_match),
        )
        .unwrap();

    state.complete(&matched);
    assert_eq!(state.snapshot().matched_count, 1);
}

#[test]
fn business_exchange_matches_when_arguments_differ() {
    let mut state = state_with_business_request(1, None);
    let changed_request = request_match(business_request(2, 2, None));

    let matched = state
        .match_exchange(
            Some("case"),
            &business_target(),
            None,
            1,
            &business_identity(),
            Some(&changed_request),
        )
        .unwrap();

    state.complete(&matched);
    assert_eq!(state.snapshot().matched_count, 1);
}

#[test]
fn business_exchange_reports_auth_semantic_mismatches() {
    let source = "TAuth2 token=\"old\",param=\"uid%3D1\",sign=\"first\"";
    let mut state = state_with_business_request(1, Some(source));
    let changed = "TAuth2 token=\"new\",param=\"uid%3D2\",sign=\"second\"";
    let changed_request = request_match(business_request(2, 2, Some(changed)));

    let fields = mismatch_fields(state.match_exchange(
        Some("case"),
        &business_target(),
        None,
        1,
        &business_identity(),
        Some(&changed_request),
    ));

    assert_eq!(fields, ["auth_parameters"]);

    let missing_auth = request_match(business_request(3, 1, None));
    let fields = mismatch_fields(state.match_exchange(
        Some("case"),
        &business_target(),
        None,
        1,
        &business_identity(),
        Some(&missing_auth),
    ));
    assert_eq!(fields, ["auth_presence"]);
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
