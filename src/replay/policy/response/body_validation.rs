use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};

use super::{
    Hessian2ResponseRules, Hessian2ValuePath, ProtobufFieldPath, ProtobufResponseRules,
    ResponseRules, parse_api, path_patterns_overlap, validate_audit_text, validate_rule_api,
    validate_separator,
};

const MAX_FIELD_NUMBER: u32 = (1 << 29) - 1;
const MAX_PATHS: usize = 32;
const MAX_PATH_DEPTH: usize = 32;

pub(super) fn validate_protobuf_rule_map(
    rules: &BTreeMap<String, ProtobufResponseRules>,
) -> Result<()> {
    for (api, rule) in rules {
        validate_rule_api(api)?;
        ensure!(
            rule.unordered.len() <= MAX_PATHS,
            "protobuf response rule API {api:?} selects more than {MAX_PATHS} unordered paths"
        );
        ensure!(
            rule.unordered_joined_string.len() <= MAX_PATHS,
            "protobuf response rule API {api:?} selects more than {MAX_PATHS} unordered joined-string paths"
        );
        let mut unique_path = BTreeSet::new();
        let mut unique_display = BTreeSet::new();
        for path in &rule.unordered {
            validate_protobuf_field_path(api, &path.field_path)?;
            validate_semantic_display_path(api, &path.display_path, "protobuf")?;
            validate_audit_text(&path.source_evidence, "source_evidence", 512)?;
            ensure!(
                path.display_path != path.field_path.display_path(),
                "protobuf response rule API {api:?} field path {:?} requires a semantic display_path",
                path.field_path.0
            );
            ensure!(
                unique_display.insert(&path.display_path),
                "protobuf response rule API {api:?} repeats display_path {:?}",
                path.display_path
            );
            ensure!(
                unique_path.insert(&path.field_path),
                "protobuf response rule API {api:?} repeats field path {:?}",
                path.field_path.0
            );
        }
        for path in &rule.unordered_joined_string {
            validate_protobuf_field_path(api, &path.field_path)?;
            validate_semantic_display_path(api, &path.display_path, "protobuf")?;
            validate_separator(
                &path.separator,
                "protobuf unordered joined-string separator",
            )?;
            validate_audit_text(&path.source_evidence, "source_evidence", 512)?;
            ensure!(
                path.display_path != path.field_path.display_path(),
                "protobuf response rule API {api:?} field path {:?} requires a semantic display_path",
                path.field_path.0
            );
            ensure!(
                unique_display.insert(&path.display_path),
                "protobuf response rule API {api:?} repeats display_path {:?}",
                path.display_path
            );
            ensure!(
                unique_path.insert(&path.field_path),
                "protobuf response rule API {api:?} uses field path {:?} more than once",
                path.field_path.0
            );
        }
    }
    Ok(())
}

pub(super) fn validate_hessian2_rule_map(
    rules: &BTreeMap<String, Hessian2ResponseRules>,
) -> Result<()> {
    for (api, rule) in rules {
        validate_rule_api(api)?;
        ensure!(
            rule.unordered.len() <= MAX_PATHS,
            "Hessian2 response rule API {api:?} selects more than {MAX_PATHS} unordered paths"
        );
        ensure!(
            rule.unordered_joined_string.len() <= MAX_PATHS,
            "Hessian2 response rule API {api:?} selects more than {MAX_PATHS} unordered joined-string paths"
        );
        let mut unique_path = BTreeSet::new();
        let mut unique_display = BTreeSet::new();
        for path in &rule.unordered {
            validate_hessian2_value_path(api, &path.value_path)?;
            validate_semantic_display_path(api, &path.display_path, "Hessian2")?;
            validate_audit_text(&path.source_evidence, "source_evidence", 512)?;
            ensure!(
                unique_display.insert(&path.display_path),
                "Hessian2 response rule API {api:?} repeats display_path {:?}",
                path.display_path
            );
            ensure!(
                unique_path.insert(&path.value_path),
                "Hessian2 response rule API {api:?} repeats value path {:?}",
                path.value_path.0
            );
        }
        for path in &rule.unordered_joined_string {
            validate_hessian2_value_path(api, &path.value_path)?;
            validate_semantic_display_path(api, &path.display_path, "Hessian2")?;
            validate_separator(&path.separator, "Hessian2 joined-string separator")?;
            validate_audit_text(&path.source_evidence, "source_evidence", 512)?;
            ensure!(
                unique_display.insert(&path.display_path),
                "Hessian2 response rule API {api:?} repeats display_path {:?}",
                path.display_path
            );
            ensure!(
                unique_path.insert(&path.value_path),
                "Hessian2 response rule API {api:?} uses value path {:?} more than once",
                path.value_path.0
            );
        }
    }
    Ok(())
}

fn validate_protobuf_field_path(api: &str, path: &ProtobufFieldPath) -> Result<()> {
    ensure!(
        !path.0.is_empty() && path.0.len() <= MAX_PATH_DEPTH,
        "protobuf response rule API {api:?} has an empty or over-deep field path"
    );
    ensure!(
        path.0
            .iter()
            .all(|number| (1..=MAX_FIELD_NUMBER).contains(number)),
        "protobuf response rule API {api:?} has an invalid field number"
    );
    Ok(())
}

fn validate_hessian2_value_path(api: &str, path: &Hessian2ValuePath) -> Result<()> {
    ensure!(
        path.0.len() <= MAX_PATH_DEPTH,
        "Hessian2 response rule API {api:?} has an over-deep value path"
    );
    for segment in &path.0 {
        validate_audit_text(segment, "Hessian2 value path segment", 256)?;
    }
    Ok(())
}

fn validate_semantic_display_path(api: &str, display_path: &str, codec: &str) -> Result<()> {
    validate_audit_text(display_path, "display_path", 512)?;
    ensure!(
        display_path
            .chars()
            .any(|character| character.is_alphabetic() || character == '_'),
        "{codec} response rule API {api:?} requires a semantic display_path"
    );
    Ok(())
}

pub(super) fn validate_body_codec_routes(rules: &ResponseRules) -> Result<()> {
    let routes = rules
        .json
        .keys()
        .map(|api| ("json", api))
        .chain(rules.protobuf.keys().map(|api| ("protobuf", api)))
        .chain(rules.hessian2.keys().map(|api| ("hessian2", api)))
        .chain(rules.docx.keys().map(|api| ("docx", api)))
        .map(|(codec, api)| {
            let (method, path) = parse_api(api)?;
            Ok((codec, api.as_str(), method, path))
        })
        .collect::<Result<Vec<_>>>()?;
    for (index, (left_codec, left_api, left_method, left_path)) in routes.iter().enumerate() {
        for (right_codec, right_api, right_method, right_path) in routes.iter().skip(index + 1) {
            if *left_codec == "json" && *right_codec == "json" {
                continue;
            }
            ensure!(
                !left_method.eq_ignore_ascii_case(right_method)
                    || !path_patterns_overlap(left_path, right_path),
                "overlapping body codec response rules select the same API: {left_codec} {left_api:?} and {right_codec} {right_api:?}"
            );
        }
    }
    Ok(())
}
