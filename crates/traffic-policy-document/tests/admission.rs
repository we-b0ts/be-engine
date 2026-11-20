use anyhow::{Result, bail};
use std::sync::atomic::{AtomicUsize, Ordering};
use traffic_policy_compiler::{CompilationContext, CompiledNativeRule};
use traffic_policy_document::native::{NativeEffect, ProcessSelector};
use traffic_policy_document::{AuthoringContext, TrafficPolicy, authoring};

fn decode(text: &str, context: &AuthoringContext<'_>) -> Result<TrafficPolicy> {
    Ok(authoring::document::deserialize(
        serde_yaml::Deserializer::from_str(text),
        context,
    )?)
}

fn recording() -> String {
    format!(
        "format: traffic-policy/v3\nsource_revision: sha256:{}\nrecording:\n  case_paths: [/jobs]\n",
        "1".repeat(64)
    )
}

#[test]
fn document_expansion_and_rendering_use_the_supplied_admission_port() {
    let policies = Default::default();
    let codecs = Default::default();
    let admitted = AtomicUsize::new(0);
    let admit = |_: &CompiledNativeRule| {
        admitted.fetch_add(1, Ordering::Relaxed);
        Ok(())
    };
    let context = AuthoringContext {
        compilation: CompilationContext {
            policies: &policies,
            codecs: &codecs,
        },
        admit_native: &admit,
    };
    let policy = decode(&recording(), &context).unwrap();
    assert!(admitted.load(Ordering::Relaxed) > 0);
    let rendered = authoring::render_policy(&policy, &context).unwrap();
    let restored = decode(&rendered, &context).unwrap();
    assert_eq!(
        authoring::effective_rules(&policy).unwrap(),
        authoring::effective_rules(&restored).unwrap()
    );

    let deny = |_: &CompiledNativeRule| bail!("test application rejects this native adapter");
    let context = AuthoringContext {
        compilation: context.compilation,
        admit_native: &deny,
    };
    let error = decode(&recording(), &context).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("test application rejects this native adapter")
    );
}

#[test]
fn process_redis_eval_round_trips_an_exact_selector() {
    let policies = Default::default();
    let codecs = Default::default();
    let context = AuthoringContext {
        compilation: CompilationContext {
            policies: &policies,
            codecs: &codecs,
        },
        admit_native: &|_| Ok(()),
    };
    let digest = "ab".repeat(32);
    let yaml = format!(
        r#"format: traffic-policy/v3
resources:
  task_cache: {{protocol: redis, endpoint: cache.test:6379, database: 0}}
process_dependencies:
  tasks:
    claim_pending:
      requests:
        - redis:
            operation: eval
            resource: task_cache
            script: {{sha256: {digest}}}
            keys: ["task:pending", "task:claimed"]
"#
    );
    let policy = decode(&yaml, &context).unwrap();
    let rule = policy.rules[0].as_native().unwrap();
    let NativeEffect::ProcessOwned(effect) = &rule.effect else {
        panic!("expected process ownership");
    };
    let ProcessSelector::RedisScript(selector) = &effect.selector else {
        panic!("expected Redis EVAL");
    };
    assert_eq!(selector.operation.as_str(), "EVAL");
    assert_eq!(effect.task_name.as_deref(), Some("claim_pending"));
    assert!(effect.origin.is_none());
    assert_eq!(selector.script.sha256, digest);
    assert_eq!(selector.keys, ["task:pending", "task:claimed"]);
    assert_eq!(selector.resource.endpoint.host, "cache.test");
    context.compile_native(rule).unwrap();

    let rendered = authoring::render_policy(&policy, &context).unwrap();
    assert!(rendered.contains("operation: EVAL"));
    assert!(rendered.contains("resource: task_cache"));
    let restored = decode(&rendered, &context).unwrap();
    assert_eq!(restored.rules, policy.rules);

    for invalid in [
        yaml.replace(digest.as_str(), "abc"),
        yaml.replace(digest.as_str(), &digest.to_ascii_uppercase()),
        yaml.replace(r#"["task:pending", "task:claimed"]"#, "[]"),
        yaml.replace("database: 0", "database: -1"),
        yaml.replace("database: 0", "database: 0, username: worker"),
    ] {
        let result = decode(&invalid, &context)
            .and_then(|policy| context.compile_native(policy.rules[0].as_native().unwrap()));
        assert!(result.is_err(), "{invalid}");
    }
}
