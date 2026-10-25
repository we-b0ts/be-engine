use super::*;

fn headers(boundary: &str) -> Headers {
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
fn normalizes_transport_delimiters_including_quoted_header_and_binary_parts() {
    let file = b"\xff\0binary\r\n--source-not-a-delimiter";
    assert!(
        compare(
            &body("source", file),
            &headers("source"),
            &body("target-longer", file),
            &headers("\"target-longer\"")
        )
        .is_ok()
    );
    assert!(
        compare(
            &body("source", file),
            &headers("source"),
            &body("target", b"changed"),
            &headers("target")
        )
        .is_err()
    );
    let target = String::from_utf8_lossy(&body("target", b"file"))
        .replace("image.jpg", "image.png")
        .into_bytes();
    assert!(
        compare(
            &body("source", b"file"),
            &headers("source"),
            &target,
            &headers("target")
        )
        .is_err()
    );
}
#[test]
fn rejects_malformed_mismatched_truncated_duplicate_or_extra_content() {
    let source = body("source", b"file");
    let actual = body("target", b"file");
    for bad in [
        actual[..actual.len() - 5].to_vec(),
        [actual.as_slice(), b"extra"].concat(),
        actual[1..].to_vec(),
    ] {
        assert!(compare(&source, &headers("source"), &bad, &headers("target")).is_err());
    }
    for header in [
        "multipart/form-data",
        "multipart/form-data; boundary=target; boundary=other",
        "multipart/form-data; boundary=\"target",
        "multipart/form-data; boundary=wrong",
        "multipart/mixed; boundary=target",
    ] {
        assert!(
            compare(
                &source,
                &headers("source"),
                &actual,
                &BTreeMap::from([("content-type".into(), vec![header.into()])])
            )
            .is_err()
        );
    }
    let mut duplicate = headers("target");
    duplicate
        .get_mut("content-type")
        .unwrap()
        .push("multipart/form-data; boundary=target".into());
    assert!(compare(&source, &headers("source"), &actual, &duplicate).is_err());
    let actual = String::from_utf8(actual)
        .unwrap()
        .replace("name=\"ori\"", "name=\"different\"");
    assert!(
        compare(
            &source,
            &headers("source"),
            actual.as_bytes(),
            &headers("target")
        )
        .is_err()
    );
}

#[test]
fn protocol_equivalence_does_not_expand_cross_case_fingerprint_sharing() {
    let source = body("source", b"file");
    let actual = body("target", b"file");
    assert!(
        preview(&source, &headers("source"), &actual, &headers("target"))
            .unwrap()
            .is_ok()
    );
    assert_ne!(
        super::super::cross_case::request_fingerprint("/upload", &source, &headers("source")),
        super::super::cross_case::request_fingerprint("/upload", &actual, &headers("target")),
    );
}
