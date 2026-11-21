use super::*;
use serde_json::json;

#[test]
fn array_patterns_select_nested_elements_and_preserve_pointer_escaping() {
    let expected = json!({"a/b": [{"~items": [{"id": 1}, {"id": 2}]}, {"~items": []}]});
    let actual = json!({"a/b": [{"~items": [{"id": 3}, {"id": 4}]}, {"~items": []}]});
    assert_eq!(
        select_json_pointers("/a~1b/*/~0items/*/id", &expected, &actual),
        ["/a~1b/0/~0items/0/id", "/a~1b/0/~0items/1/id"]
    );
    assert_eq!(
        select_json_pointers("/*", &json!([1, 2]), &json!([3, 4])),
        ["/0", "/1"]
    );
}

#[test]
fn array_patterns_do_not_expand_object_keys_or_missing_elements() {
    let value = json!({"data": {"0": {"id": 1}, "named": {"id": 2}}});
    assert!(select_json_pointers("/data/*/id", &value, &value).is_empty());
    assert!(select_json_pointers("/data/*/id", &json!({"data": []}), &value).is_empty());
    assert!(select_json_pointers("/*/id", &json!([{"id": 1}]), &json!([{}])).is_empty());
    let literal = json!({"data": {"*": {"id": 1}}});
    assert_eq!(
        select_json_pointers("/data/*/id", &literal, &literal),
        ["/data/*/id"]
    );
}

#[test]
fn array_patterns_match_evidence_and_detect_subtree_conflicts() {
    assert!(response_pointer_matches("/data/*/id", "/data/12/id"));
    assert!(!response_pointer_matches("/data/*/id", "/data/01/id"));
    assert!(!response_pointer_matches("/data/*/id", "/data/name/id"));
    assert!(!response_pointer_matches("/data/*/id", "/data/0/id/child"));
    for (left, right) in [
        ("/data/*/id", "/data/0/id"),
        ("/data/*/id", "/data"),
        ("/data/*/id", "/data/12/id/child"),
        ("/data/*/items/0", "/data/1/items/*"),
        ("", "/data/*/id"),
    ] {
        assert!(response_locations_overlap(left, right), "{left} {right}");
        assert!(response_locations_overlap(right, left), "{right} {left}");
    }
    assert!(!response_locations_overlap("/data/*/id", "/data/0/name"));
    assert!(!response_locations_overlap("/data/*/id", "/database/0/id"));
}
