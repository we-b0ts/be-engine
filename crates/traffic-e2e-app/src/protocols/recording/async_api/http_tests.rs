use super::*;
use crate::policy::AsyncHttpEnd;
use crate::protocols::recording::events::HttpExchangeEvent;
use crate::recorder::capture_body;

fn scope() -> ResourceScope {
    ResourceScope::new(AsyncApiRule {
        end: vec![AsyncEnd::Http(AsyncHttpEnd {
            method: "POST".into(),
            endpoint: Endpoint {
                host: "executor.test".into(),
                port: 80,
            },
            path: "/submit".into(),
            status_codes: vec![202],
        })],
        ..Default::default()
    })
}

fn event() -> HttpExchangeEvent {
    HttpExchangeEvent {
        outcome: DependencyExchangeOutcome::Response,
        id: uuid::Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        request_started_at: chrono::Utc::now(),
        client_addr: None,
        scheme: "http".into(),
        method: "POST".into(),
        uri: "/submit?trace=1".into(),
        authority: Some("EXECUTOR.test".into()),
        request_headers: BTreeMap::new(),
        request_body: capture_body(b"{}", 100),
        response_status: Some(202),
        response_headers: Some(BTreeMap::new()),
        response_body: Some(capture_body(b"{}", 100)),
        response_stream: None,
        discovered_tcp_targets: Vec::new(),
        duration_ms: 10,
        error: None,
    }
}

fn assert_live_and_recorded(event: HttpExchangeEvent, reason: Option<AsyncEndReason>) {
    let event = RecorderEvent::HttpExchange(event);
    assert_eq!(
        scope().observe(&event).map(|signal| signal.end_reason),
        reason
    );
    assert_eq!(
        scope()
            .observe_recorded(&serde_json::to_value(event).unwrap())
            .unwrap()
            .map(|signal| signal.end_reason),
        reason
    );
}

#[test]
fn http_end_requires_complete_success_for_the_exact_method_endpoint_and_path() {
    assert_live_and_recorded(event(), Some(AsyncEndReason::Resource));
    for (field, value) in [
        ("method", "GET"),
        ("uri", "/submit/other"),
        ("authority", "other.test"),
        ("authority", "executor.test:81"),
        ("scheme", "https"),
    ] {
        let mut event = event();
        match field {
            "method" => event.method = value.into(),
            "uri" => event.uri = value.into(),
            "authority" => event.authority = Some(value.into()),
            "scheme" => event.scheme = value.into(),
            _ => unreachable!(),
        }
        assert_live_and_recorded(event, None);
    }
    let mut wrong_status = event();
    wrong_status.response_status = Some(200);
    assert_live_and_recorded(wrong_status, None);
    let mut no_response = event();
    no_response.outcome = DependencyExchangeOutcome::NoResponse;
    assert_live_and_recorded(no_response, None);
    let mut failure = event();
    failure.response_status = Some(500);
    assert_live_and_recorded(failure, None);
}

#[test]
fn http_authority_and_default_ports_are_identical_for_live_and_recorded_evidence() {
    let mut absolute = event();
    absolute.authority = None;
    absolute.uri = "http://executor.test/submit".into();
    assert_live_and_recorded(absolute, Some(AsyncEndReason::Resource));
    let mut scope = scope();
    let AsyncEnd::Http(end) = &mut scope.rule.end[0] else {
        unreachable!()
    };
    end.endpoint.port = 443;
    end.status_codes.clear();
    let mut event = event();
    event.scheme = "fake_ip_https".into();
    event.response_status = Some(200);
    let event = RecorderEvent::HttpExchange(event);
    assert_eq!(
        scope.observe(&event).unwrap().end_reason,
        AsyncEndReason::Resource
    );
    assert_eq!(
        scope
            .observe_recorded(&serde_json::to_value(event).unwrap())
            .unwrap()
            .unwrap()
            .end_reason,
        AsyncEndReason::Resource
    );

    let AsyncEnd::Http(end) = &mut scope.rule.end[0] else {
        unreachable!()
    };
    end.endpoint.host = "::1".into();
    end.endpoint.port = 80;
    let mut ipv6 = self::event();
    ipv6.authority = Some("[::1]:80".into());
    let ipv6 = RecorderEvent::HttpExchange(ipv6);
    assert_eq!(
        scope.observe(&ipv6).unwrap().end_reason,
        AsyncEndReason::Resource
    );
    assert_eq!(
        scope
            .observe_recorded(&serde_json::to_value(ipv6).unwrap())
            .unwrap()
            .unwrap()
            .end_reason,
        AsyncEndReason::Resource
    );
}
