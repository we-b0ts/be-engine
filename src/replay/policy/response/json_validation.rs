//! JSON response rule validation and selector ownership.
use super::*;

pub(super) fn validate_json_rule_map<'a>(
    rules: &'a BTreeMap<String, JsonResponseRules>,
    locations: &mut Vec<RuleLocation<'a>>,
) -> Result<()> {
    for (api, rules) in rules {
        let (method, path) = validate_rule_api(api)?;
        ensure!(
            !rules.is_empty(),
            "JSON response rule API {api:?} must select at least one rule"
        );
        let mut unique_generated = BTreeSet::new();
        for (kind, field) in rules.generated() {
            validate_json_pointer(&field.pointer)?;
            ensure!(
                unique_generated.insert(field.pointer.as_str()),
                "generated response rules for API {api:?} repeat JSON Pointer {:?}",
                field.pointer
            );
            validate_generated_rule(kind, field)?;
            locations.push((method, path, &field.pointer, kind));
        }
        for rule in &rules.jwt {
            rule.validate()?;
            locations.push((method, path, &rule.pointer, ResponseRuleKind::Jwt));
            for pointer in rule.companion_pointers() {
                locations.push((method, path, pointer, ResponseRuleKind::Jwt));
            }
            if let Some(pointer) = &rule.ttl {
                locations.push((method, path, pointer, ResponseRuleKind::Jwt));
            }
        }
        let mut unique_unordered = BTreeSet::new();
        for field in &rules.unordered {
            validate_json_pointer(&field.pointer)?;
            ensure!(
                unique_unordered.insert(field.pointer.as_str()),
                "unordered response rule API {api:?} repeats JSON Pointer {:?}",
                field.pointer
            );
            validate_audit_text(&field.source_evidence, "source_evidence", 512)?;
            locations.push((method, path, &field.pointer, ResponseRuleKind::Unordered));
        }
        let mut unique_joined_string = BTreeSet::new();
        for field in &rules.unordered_joined_string {
            validate_json_pointer(&field.pointer)?;
            ensure!(
                unique_joined_string.insert(field.pointer.as_str()),
                "unordered joined-string response rule API {api:?} repeats JSON Pointer {:?}",
                field.pointer
            );
            validate_separator(&field.separator, "JSON unordered joined-string separator")?;
            validate_audit_text(&field.source_evidence, "source_evidence", 512)?;
            locations.push((
                method,
                path,
                &field.pointer,
                ResponseRuleKind::UnorderedJoinedString,
            ));
        }
    }
    Ok(())
}
