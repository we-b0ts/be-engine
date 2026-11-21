use super::*;

fn args(values: &[&str]) -> Vec<Vec<u8>> {
    values
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect()
}

#[test]
fn request_values_use_native_positions_for_storage_scripts_and_publications() {
    for (command, arguments, index, stored) in [
        ("SET", args(&["key", "source", "NX"]), 1, true),
        ("HSET", args(&["key", "field", "source"]), 2, true),
        ("EVAL", args(&["script", "1", "key", "source"]), 3, false),
        ("PUBLISH", args(&["channel", "source"]), 1, false),
    ] {
        let values = request_values(command, &arguments).unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].argument, Some(index));
        assert_eq!(values[0].payload, Some(b"source".as_slice()));
        assert_eq!(values[0].stored, stored);
    }
}

#[test]
fn injected_value_semantics_return_an_opaque_identity_decision() {
    let source = args(&["source-key", "source-value", "NX"]);
    let target = args(&["target-key", "target-value", "NX"]);
    let result = compare_request(
        "SET",
        &source,
        &target,
        ClockPair::default(),
        Duration::ZERO,
        |field, source, target| {
            assert_eq!(field.key, b"source-key");
            ensure!(
                source == b"source-value" && target == b"target-value",
                "value rejected"
            );
            Ok(Comparison::default())
        },
        |comparison, target| {
            assert!(comparison.passed());
            let mut normalized = target.to_vec();
            normalized[0] = b"source-key".to_vec();
            Ok((37_u64, Some(normalized)))
        },
    )
    .unwrap()
    .unwrap();
    assert!(result.comparison.passed());
    assert_eq!(result.identity, 37);
}

#[test]
fn value_permission_keeps_other_native_arguments_and_projection_lengths_exact() {
    let source = args(&["key", "source", "NX"]);
    let target = args(&["key", "target", "XX"]);
    assert!(
        compare_request(
            "SET",
            &source,
            &target,
            ClockPair::default(),
            Duration::ZERO,
            |_, _, _| Ok(Comparison::default()),
            |_, _| Ok(((), None)),
        )
        .is_err()
    );
    assert!(
        compare_request(
            "SET",
            &source,
            &source,
            ClockPair::default(),
            Duration::ZERO,
            |_, _, _| Ok(Comparison::default()),
            |_, _| Ok(((), Some(args(&["key", "source"])))),
        )
        .is_err()
    );
}

#[test]
fn key_reference_projection_delegates_content_recognition_and_identity_lookup() {
    let source = args(&["script", "1", "old-key", "old-reference", "document:source"]);
    let target = args(&["script", "1", "new-key", "new-reference", "document:target"]);
    let normalized = project_key_references(
        "EVAL",
        &source,
        &target,
        &[],
        |bytes| bytes.starts_with(b"document:"),
        |source, target| {
            Ok(matches!(
                (source, target),
                ("old-key", "new-key") | ("old-reference", "new-reference")
            ))
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(&normalized[..4], &source[..4]);
    assert_eq!(normalized[4], target[4]);
}
