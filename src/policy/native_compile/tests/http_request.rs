//! JSON formats are global; HTTP native effects own transport fields.
use crate::policy;
use serde_json::json;

#[test]
fn http_request_json_authoring_is_rejected_and_global_formats_need_no_http_scope() {
    let proof =
        json!({"source":"client.rs:send","fact":"Source sends a generated request identifier"});
    let old = json!({"format":"traffic-policy/v3","rules":[{"id":"body","match":{"api":"POST /api",
        "resource":{"protocol":"http","endpoint":"upstream.test:80"},"operation":"POST","path":"/send"},
        "effect":{"kind":"http_request","json":{"/token":{"kind":"jwt","algorithm":"HS256","signing_key":{"kind":"target_env","name":"SECRET"}}}},"proof":proof}]});
    assert!(policy::parse_policy(&old.to_string()).is_err());
    let global = json!({"format":"traffic-policy/v3","signatures":{
        "default":{"kind":"jwt","algorithm":"HS256","key":{"kind":"target_env","name":"SECRET_KEY"}}
    },"json":{"fields":{
        "/metadata/request_id":{"kind":"identity","formats":[{"hex":8}]},
        "/metadata/auth_token":{"kind":"jwt"},
        "/metadata/skill_identity_token":{"kind":"jwt"}
    }}});
    let compiled =
        policy::compile_policy(&policy::parse_policy(&global.to_string()).unwrap()).unwrap();
    assert!(compiled.native.is_empty());
    assert_eq!(compiled.global_json.unwrap().fields.len(), 3);
}

#[test]
fn native_http_query_and_multipart_keep_their_own_contracts() {
    for effect in [
        json!({"kind":"http_request","query":{"nonce":{"kind":"uuid_v4"}}}),
        json!({"kind":"http_request","multipart_boundary":true}),
    ] {
        let document = json!({"format":"traffic-policy/v3","rules":[{"id":"transport","match":{"api":"POST /api",
            "resource":{"protocol":"http","endpoint":"upstream.test:80"},"operation":"POST","path":"/send"},
            "effect":effect,"proof":{"source":"client.rs:send","fact":"Source generates this native protocol field"}}]});
        policy::compile_policy(&policy::parse_policy(&document.to_string()).unwrap()).unwrap();
    }
}
