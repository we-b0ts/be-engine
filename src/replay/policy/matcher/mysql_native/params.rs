//! Generated scalar slots share SQL identity; live bindings remain atomic.
use super::*;
use crate::policy::native::GeneratedValue;

fn scalar(token: &Token) -> Result<Value> {
    match token {
        Token::Bytes(bytes) => Ok(Value::String(
            std::str::from_utf8(bytes)
                .context("generated SQL scalar must be UTF-8")?
                .into(),
        )),
        Token::Number(number) => crate::json_value::parse(number.as_bytes())
            .filter(Value::is_number)
            .context("generated SQL number is not exact JSON"),
        _ => anyhow::bail!("generated SQL parameter requires a non-null scalar"),
    }
}

pub(super) fn validate_shape(
    source: &Token,
    target: &Token,
    contract: &GeneratedValue,
) -> Result<()> {
    let source = scalar(source)?;
    let target = scalar(target)?;
    ensure!(
        std::mem::discriminant(&source) == std::mem::discriminant(&target),
        "generated SQL scalar type changed"
    );
    if source.is_number() {
        crate::value_contract::time::validate_numeric_category(&source, &target)
            .map_err(|_| anyhow::anyhow!("generated SQL numeric category changed"))?;
    }
    let projected = super::super::super::native_projection::generated(contract)?;
    if let Some(validator) = projected.validate {
        for value in [&source, &target] {
            super::super::super::value::validate_value(value, validator)
                .map_err(|_| anyhow::anyhow!("generated SQL scalar shape differs"))?;
        }
    }
    Ok(())
}

/// Shape comparison alone cannot prove a reference to an earlier request.
/// The caller keeps this decision speculative until protocol matching claims it.
#[allow(clippy::too_many_arguments)]
pub(in crate::replay::policy) fn validate_parameters(
    runtime: &ReplayPolicyRuntime,
    case: &str,
    source_sql: Option<&str>,
    source_params: Option<&[RecordedMysqlValue]>,
    actual_sql: Option<&str>,
    actual_params: Option<&[RecordedMysqlValue]>,
    rules: &[&CompiledNativeRule],
) -> Result<DependencyRuleDecision> {
    let source =
        mysql_values::materialized(source_sql, source_params).map_err(anyhow::Error::msg)?;
    let actual =
        mysql_values::materialized(actual_sql, actual_params).map_err(anyhow::Error::msg)?;
    let mut decision = DependencyRuleDecision::default();
    for compiled in rules {
        let rule = &compiled.rule;
        let NativeEffect::MysqlValues(effect) = &rule.effect else {
            continue;
        };
        let template = SqlValueTemplate::new(
            rule.selector
                .sql
                .as_deref()
                .context("SQL parameter template absent")?,
            &rule.selector.tables,
            &rule.selector.table_patterns,
            rule.selector.table_series.as_ref(),
        )?;
        for (slot, field) in &effect.params {
            let position = super::position(&template, &source, &actual, *slot)?;
            validate_shape(&source[position], &actual[position], &field.contract)?;
            let projected = super::super::super::native_projection::generated(&field.contract)?;
            runtime
                .preview_dynamic_value(
                    case,
                    &rule.id,
                    &projected,
                    &scalar(&source[position])?,
                    &scalar(&actual[position])?,
                    &mut decision,
                    Default::default(),
                )
                .map_err(anyhow::Error::msg)?;
        }
    }
    Ok(decision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn generated_sql_formats_and_times_compose_without_claiming_failed_candidates() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("case");
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(
            directory.join("request.json"),
            json!({"method":"POST","uri":"/events","timestamp":"2020-01-01T00:00:00Z"}).to_string(),
        )
        .unwrap();
        std::fs::write(directory.join("dependencies.jsonl"), "").unwrap();
        std::fs::write(directory.join("expected-response.json"), "{}").unwrap();
        let proof = json!({"source":"source.py:save","fact":"Source mints a UUID, keeps it for later updates, and stores the request-relative creation instant"});
        let resource = json!({"protocol":"mysql","endpoint":"db.test:3306","database":"app"});
        let document = json!({"format":"traffic-policy/v2","rules":[
            {"id":"created","match":{"api":"POST /events","resource":resource,"sql":"INSERT INTO events (id,created) VALUES (?,?)"},"effect":{"kind":"mysql_values","params":{"0":{"contract":{"kind":"uuid_v4"},"proof":proof}},"values":{"1":{"contract":{"kind":"time","format":"sql_datetime","relation":"preserve_offset","utc_offset":"+00:00"},"proof":proof}}},"proof":proof},
            {"id":"updated","match":{"api":"POST /events","resource":resource,"sql":"UPDATE events SET label=? WHERE id=?"},"effect":{"kind":"mysql_values","params":{"1":{"contract":{"kind":"uuid_v4"},"proof":proof}}},"proof":proof}
        ]});
        let document: crate::policy::TrafficPolicy = serde_json::from_value(document).unwrap();
        let compiled = crate::policy::compile_policy(&document).unwrap();
        let policy = temporary.path().join("policy.yaml");
        std::fs::write(&policy, serde_yaml::to_string(&document).unwrap()).unwrap();
        let cases = BTreeMap::from([(
            "case".into(),
            crate::replay::ReplayCase {
                id: "case".into(),
                dependencies_path: directory.join("dependencies.jsonl"),
                dir: directory,
                status: crate::replay::ReplayCaseStatus::Pending,
            },
        )]);
        let mut runtime = ReplayPolicyRuntime::load(&policy, &cases).unwrap();
        let clocks = AnchorClocks {
            dependency: crate::value_contract::time::ClockPair {
                source: Some("2020-01-01T00:00:00Z".parse().unwrap()),
                target: Some("2026-01-01T00:00:00Z".parse().unwrap()),
            },
            ..Default::default()
        };
        let source = "INSERT INTO events (id,created) VALUES ('00000000-0000-4000-8000-000000000001','2020-01-01 00:00:00.123456')";
        let candidate = |id: &str| {
            format!("INSERT INTO events (id,created) VALUES ('{id}','2026-01-01 00:00:00.123456')")
        };
        let first = "00000000-0000-4000-8000-000000000002";
        let selected = [compiled
            .native
            .iter()
            .find(|rule| rule.rule.id == "created")
            .unwrap()];
        let failed = candidate(first).replace("00:00:00.123456", "00:00:20.123456");
        assert!(
            !compare(
                Some("app"),
                Some(source),
                None,
                Some(&failed),
                None,
                &[],
                &selected,
                clocks
            )
            .unwrap()
            .passed()
        );
        // Previewing a losing candidate never reserves its UUID correspondence.
        let unused = validate_parameters(
            &runtime,
            "case",
            Some(source),
            None,
            Some(&candidate(first)),
            None,
            &selected,
        )
        .unwrap();
        drop(unused);
        assert!(!runtime.request_contracts.has_identities("case"));
        let actual = candidate("00000000-0000-4000-8000-000000000003");
        let comparison = compare(
            Some("app"),
            Some(source),
            None,
            Some(&actual),
            None,
            &[],
            &selected,
            clocks,
        )
        .unwrap();
        assert!(comparison.passed());
        let mut decision = validate_parameters(
            &runtime,
            "case",
            Some(source),
            None,
            Some(&actual),
            None,
            &selected,
        )
        .unwrap();
        decision.merge_value_comparison(comparison, &selected);
        runtime.commit(Some("case"), decision).unwrap();
        assert!(runtime.request_contracts.has_identities("case"));
        let conflict = crate::value_contract::identities::IdentityPair {
            source: serde_json::to_string("00000000-0000-4000-8000-000000000001").unwrap(),
            target: serde_json::to_string("00000000-0000-4000-8000-000000000002").unwrap(),
        };
        assert!(
            runtime
                .request_contracts
                .preview_identity_pairs("case", &[conflict])
                .is_err()
        );
        let source =
            "UPDATE events SET label='checked' WHERE id='00000000-0000-4000-8000-000000000001'";
        let correct =
            "UPDATE events SET label='checked' WHERE id='00000000-0000-4000-8000-000000000003'";
        let reference = [compiled
            .native
            .iter()
            .find(|rule| rule.rule.id == "updated")
            .unwrap()];
        assert!(
            compare(
                Some("app"),
                Some(source),
                None,
                Some(correct),
                None,
                &[],
                &reference,
                clocks
            )
            .unwrap()
            .passed()
        );
        assert!(
            validate_parameters(
                &runtime,
                "case",
                Some(source),
                None,
                Some(correct),
                None,
                &reference
            )
            .is_ok()
        );
        assert!(
            validate_parameters(
                &runtime,
                "case",
                Some(source),
                None,
                Some(&correct.replace("000000000003", "000000000002")),
                None,
                &reference
            )
            .is_err()
        );
        assert!(
            validate_parameters(
                &runtime,
                "another-case",
                Some(source),
                None,
                Some(correct),
                None,
                &reference
            )
            .is_ok()
        );
        assert!(
            compare(
                Some("app"),
                Some(source),
                None,
                Some(&correct.replace("label='checked'", "label='wrong'")),
                None,
                &[],
                &reference,
                clocks
            )
            .is_err()
        );
    }
}
