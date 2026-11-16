//! Contextual value checks preserve response structure and unselected bytes.
use super::*;

#[test]
fn contextual_json_consistency_keeps_response_structure_and_unselected_bytes_exact() {
    let owner = identity_runtime();
    bind(&owner);
    let original = array(&[
        bulk("field"),
        bulk(r#"{"id": "11", "stable": true}"#),
        bulk("other"),
        bulk("opaque"),
    ]);
    let prepared = delivery(&owner, "HGETALL", &["hash:1"], &original);
    let copied = r#"{"stable":true,"id":"999"}"#;
    let native = array(&[bulk("field"), bulk(copied), bulk("other"), bulk("opaque")]);
    let now = DateTime::from_timestamp(2000, 0).unwrap();
    assert_eq!(
        prepared.render_consistent(now, Some(&native)).unwrap(),
        native
    );
    for bad in [
        array(&[
            bulk("different-field"),
            bulk(copied),
            bulk("other"),
            bulk("opaque"),
        ]),
        array(&[bulk("field"), bulk(copied), bulk("other"), bulk("changed")]),
        array(&[
            bulk("field"),
            b"$-1\r\n".to_vec(),
            bulk("other"),
            bulk("opaque"),
        ]),
        array(&[
            bulk("field"),
            bulk("not-json"),
            bulk("other"),
            bulk("opaque"),
        ]),
        [native.as_slice(), b"+EXTRA\r\n"].concat(),
    ] {
        assert!(prepared.render_consistent(now, Some(&bad)).is_err());
    }
}
