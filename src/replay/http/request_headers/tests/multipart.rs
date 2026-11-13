use std::collections::BTreeMap;

fn headers(boundary: &str) -> BTreeMap<String, Vec<String>> {
    BTreeMap::from([(
        "content-type".into(),
        vec![format!("multipart/form-data; boundary={boundary}")],
    )])
}
fn body(boundary: &str, file: &[u8]) -> Vec<u8> {
    let mut body = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"ori\"\r\n\r\n1\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"pic\"; filename=\"image.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n").into_bytes();
    body.extend(file);
    body.extend(format!("\r\n--{boundary}--\r\n").bytes());
    body
}
#[test]
fn protocol_equivalence_does_not_expand_cross_case_fingerprint_sharing() {
    let source = body("source", b"file");
    let actual = body("target", b"file");
    assert!(
        traffic_protocol_http::multipart::preview(
            &source,
            &headers("source"),
            &actual,
            &headers("target")
        )
        .unwrap()
        .is_ok()
    );
    assert_ne!(
        crate::replay::http::cross_case::request_fingerprint(
            "/upload",
            &source,
            &headers("source")
        ),
        crate::replay::http::cross_case::request_fingerprint(
            "/upload",
            &actual,
            &headers("target")
        ),
    );
}
