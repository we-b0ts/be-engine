use super::*;
use crate::replay::policy::{dynamic_values::DynamicValues, matcher::MysqlPolicyContext};
use crate::value_contract::identities::{IdentityDecision, IdentityDelivery, IdentityStore};
use serde_json::json;

const SOURCE: &str = "11111111-1111-4111-8111-111111111111";
const TARGET: &str = "22222222-2222-4222-8222-222222222222";
const SOURCE_TWO: &str = "33333333-3333-4333-8333-333333333333";
const TARGET_TWO: &str = "44444444-4444-4444-8444-444444444444";

fn session() -> ReplaySessionIdentity {
    ReplaySessionIdentity {
        target: Some(TargetKey {
            host: "db.test".into(),
            port: 3306,
        }),
        database: Some("app".into()),
        username: None,
    }
}

fn context<'a>(
    identity: &'a ReplaySessionIdentity,
    source: &'a str,
    target: &'a str,
) -> MysqlPolicyContext<'a> {
    MysqlPolicyContext {
        request_times: Default::default(),
        case_id: Some("case"),
        identity,
        command: "COM_QUERY",
        recorded_sql: Some(source),
        recorded: None,
        sql: Some(target),
        actual: None,
    }
}

fn native() -> DynamicValues {
    let rule = serde_json::from_value(json!({"id":"native-id","api":"/api",
        "targets":[{"host":"db.test","port":3306}],
        "capture":{"protocol":"mysql","target":{"host":"db.test","port":3306},
            "database":"app","sql":"INSERT INTO generators (id) VALUES (?)","value_index":0},
        "source_evidence":"Source creates this UUID and copies it into other database fields"}))
    .unwrap();
    let native = DynamicValues::new(vec![rule], BTreeMap::from([("case".into(), "/api".into())]));
    let identity = session();
    for (source, target) in [(SOURCE, TARGET), (SOURCE_TWO, TARGET_TWO)] {
        let source = format!("INSERT INTO generators (id) VALUES ('{source}')");
        let target = format!("INSERT INTO generators (id) VALUES ('{target}')");
        let normalized = native
            .mysql(&context(&identity, &source, &target))
            .unwrap()
            .unwrap();
        native.commit("case", normalized.decision);
    }
    native
}

fn policy(fields: Value, scalar: bool) -> crate::policy::CompiledPolicy {
    let column = if scalar { "owner_id" } else { "payload" };
    let field = if scalar {
        json!({"kind":"identity","binding":"entity","format":"uuid"})
    } else {
        json!({"codec":"json","fields":fields})
    };
    crate::policy::parse_and_compile_policy(&json!({"format":"traffic-policy/v2",
        "resources":{"db":{"protocol":"mysql","endpoint":"db.test:3306","database":"app",
            "proof":{"source":"rows.py:write","fact":"These physical fields store the generated UUID and preserve business data"},
            "tables":{"tasks":{"fields":{column:field}}}}}
    }).to_string()).unwrap()
}

fn record(sql: &str) -> RecordedMysqlExchange {
    serde_json::from_value(json!({"command":"COM_QUERY","database":"app","sql":sql,
        "response":{"status":"ok"}}))
    .unwrap()
}

fn restore_native(
    policy: &crate::policy::CompiledPolicy,
    source: &str,
    target: &str,
) -> Result<Vec<IdentityPair>> {
    let native = native();
    let identity = session();
    let normalized = native.mysql(&context(&identity, source, target)).unwrap()?;
    let raw = record(source);
    let normalized_source = record(normalized.source_sql.as_deref().unwrap());
    let rules = policy
        .rules
        .iter()
        .filter(|rule| rule.rule.surface == Surface::DependencyRequest)
        .collect::<Vec<_>>();
    let comparison = crate::replay::policy::matcher::mysql_native::compare(
        Some("app"),
        normalized.source_sql.as_deref(),
        normalized.source_params.as_deref(),
        normalized.actual_sql.as_deref(),
        normalized.actual_params.as_deref(),
        &rules,
        &[],
        Default::default(),
    )?;
    ensure!(comparison.passed(), "normalized contract rejected the pair");
    restore(
        &rules,
        &normalized_source,
        normalized.actual_sql.as_deref(),
        normalized.actual_params.as_deref(),
        RawMysqlIdentityRequest {
            source: &raw,
            target_sql: Some(target),
            target_params: None,
        },
        &comparison,
    )
}

#[test]
fn native_reference_projection_retains_real_target_id_for_shared_store_and_delivery() {
    let policy = policy(json!({}), true);
    let source = format!("UPDATE tasks SET owner_id='{SOURCE}' WHERE tenant=7");
    let target = format!("UPDATE tasks SET owner_id='{TARGET}' WHERE tenant=7");
    let pairs = restore_native(&policy, &source, &target).unwrap();
    assert_eq!(
        pairs,
        vec![IdentityPair {
            domain: "entity".into(),
            source: SOURCE.into(),
            target: TARGET.into()
        }]
    );
    let mut store = IdentityStore::default();
    store
        .commit(IdentityDecision::prepare("case", pairs).unwrap())
        .unwrap();
    let original = json!(SOURCE);
    let selected =
        crate::value_contract::identities::PreparedIdentityDelivery::prepare(IdentityDelivery {
            binding: "entity",
            prefix: "",
            format: crate::policy::IdentityFormat::Uuid,
            value: &original,
        })
        .unwrap();
    let (delivered, _) = store.deliveries("case", &[selected]).unwrap();
    assert_eq!(delivered, vec![json!(TARGET)]);
    assert!(
        store
            .validate(
                &IdentityDecision::prepare(
                    "case",
                    vec![IdentityPair {
                        domain: "entity".into(),
                        source: SOURCE.into(),
                        target: SOURCE.into(),
                    }]
                )
                .unwrap()
            )
            .is_err()
    );
}

#[test]
fn prepared_native_reference_restores_original_parameter_tokens() {
    let policy = policy(json!({}), true);
    let rules = policy
        .rules
        .iter()
        .filter(|rule| rule.rule.surface == Surface::DependencyRequest)
        .collect::<Vec<_>>();
    let sql = "UPDATE tasks SET owner_id=? WHERE tenant=?";
    let mut source = record(sql);
    source.command = "COM_STMT_EXECUTE".into();
    source.params = Some(
        serde_json::from_value(json!([
            {"kind":"string","value":SOURCE},{"kind":"integer","value":7}
        ]))
        .unwrap(),
    );
    let target = serde_json::from_value::<Vec<RecordedMysqlValue>>(json!([
        {"kind":"string","value":TARGET},{"kind":"integer","value":7}
    ]))
    .unwrap();
    let identity = session();
    let native = native();
    let normalized = native
        .mysql(&MysqlPolicyContext {
            request_times: Default::default(),
            case_id: Some("case"),
            identity: &identity,
            command: "COM_STMT_EXECUTE",
            recorded_sql: Some(sql),
            recorded: source.params.as_deref(),
            sql: Some(sql),
            actual: Some(&target),
        })
        .unwrap()
        .unwrap();
    let mut normalized_source = source.clone();
    normalized_source.params = normalized.source_params;
    let comparison = crate::replay::policy::matcher::mysql_native::compare(
        Some("app"),
        Some(sql),
        normalized_source.params.as_deref(),
        Some(sql),
        normalized.actual_params.as_deref(),
        &rules,
        &[],
        Default::default(),
    )
    .unwrap();
    assert!(comparison.passed());
    let restored = restore(
        &rules,
        &normalized_source,
        Some(sql),
        normalized.actual_params.as_deref(),
        RawMysqlIdentityRequest {
            source: &source,
            target_sql: Some(sql),
            target_params: Some(&target),
        },
        &comparison,
    )
    .unwrap();
    assert_eq!(
        restored,
        vec![IdentityPair {
            domain: "entity".into(),
            source: SOURCE.into(),
            target: TARGET.into(),
        }]
    );
}

#[test]
fn unordered_json_uses_the_validated_pairing_and_decodes_each_carrier_once() {
    let policy = policy(
        json!({"/items":"unordered","/items/*/id":{
        "kind":"conditional","when":{"relative_pointer":"../kind","equals":"generated"},
        "contract":{"kind":"identity","binding":"entity","format":"uuid"}}}),
        false,
    );
    let payload = |first, second| {
        json!({"items":[
        {"id":first,"kind":"generated","label":"one"},
        {"id":second,"kind":"generated","label":"two"}],"business":"exact"})
    };
    let source = format!(
        "UPDATE tasks SET payload='{}' WHERE tenant=7",
        payload(SOURCE, SOURCE_TWO)
    );
    let mut target_payload = payload(TARGET, TARGET_TWO);
    target_payload["items"].as_array_mut().unwrap().reverse();
    let target = format!("UPDATE tasks SET payload='{target_payload}' WHERE tenant=7");
    let pairs = restore_native(&policy, &source, &target).unwrap();
    let observed = pairs
        .into_iter()
        .map(|pair| (pair.source, pair.target))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        observed,
        BTreeMap::from([
            (SOURCE.into(), TARGET.into()),
            (SOURCE_TWO.into(), TARGET_TWO.into())
        ])
    );

    let rules = policy
        .rules
        .iter()
        .filter(|rule| rule.rule.surface == Surface::DependencyRequest)
        .collect::<Vec<_>>();
    let raw = record(&source);
    let normalized_target = target
        .replace(TARGET_TWO, SOURCE_TWO)
        .replace(TARGET, SOURCE);
    let comparison = crate::replay::policy::matcher::mysql_native::compare(
        Some("app"),
        Some(&source),
        None,
        Some(&normalized_target),
        None,
        &rules,
        &[],
        Default::default(),
    )
    .unwrap();
    let (restored, decodes) = crate::value_codec::measured_decodes(|| {
        restore(
            &rules,
            &raw,
            Some(&normalized_target),
            None,
            RawMysqlIdentityRequest {
                source: &raw,
                target_sql: Some(&target),
                target_params: None,
            },
            &comparison,
        )
        .unwrap()
    });
    assert_eq!(restored.len(), 2);
    assert_eq!(decodes, 3);
}

#[test]
fn raw_discriminator_and_inactive_values_cannot_be_repaired_by_native_normalization() {
    for discriminator in ["generated", SOURCE] {
        let policy = policy(
            json!({"/id":{"kind":"conditional",
            "when":{"relative_pointer":"../kind","equals":discriminator},
            "contract":{"kind":"identity","binding":"entity","format":"uuid"}}}),
            false,
        );
        let source =
            json!({"id":SOURCE,"kind":if discriminator == "generated" {"external"} else {SOURCE}});
        let target =
            json!({"id":TARGET,"kind":if discriminator == "generated" {"external"} else {TARGET}});
        let source = format!("UPDATE tasks SET payload='{source}' WHERE tenant=7");
        let target = format!("UPDATE tasks SET payload='{target}' WHERE tenant=7");
        assert!(restore_native(&policy, &source, &target).is_err());
    }
}

#[test]
fn one_normalized_token_cannot_hide_multiple_independent_target_ids() {
    let policy = policy(
        json!({"/items/*/id":{
        "kind":"identity","binding":"entity","format":"uuid"}}),
        false,
    );
    let source_body = json!({"items":[{"id":SOURCE},{"id":SOURCE}]});
    let target_body = json!({"items":[{"id":TARGET},{"id":TARGET_TWO}]});
    let source = format!("UPDATE tasks SET payload='{source_body}' WHERE tenant=7");
    let target = format!("UPDATE tasks SET payload='{target_body}' WHERE tenant=7");
    let raw = record(&source);
    let rules = policy
        .rules
        .iter()
        .filter(|rule| rule.rule.surface == Surface::DependencyRequest)
        .collect::<Vec<_>>();
    let comparison = crate::replay::policy::matcher::mysql_native::compare(
        Some("app"),
        Some(&source),
        None,
        Some(&source),
        None,
        &rules,
        &[],
        Default::default(),
    )
    .unwrap();
    assert!(comparison.passed());
    assert!(
        restore(
            &rules,
            &raw,
            Some(&source),
            None,
            RawMysqlIdentityRequest {
                source: &raw,
                target_sql: Some(&target),
                target_params: None
            },
            &comparison
        )
        .is_err()
    );
}
