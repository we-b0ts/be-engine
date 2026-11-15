use anyhow::{Result, bail};
use std::sync::atomic::{AtomicUsize, Ordering};
use traffic_policy_compiler::{CompilationContext, CompiledNativeRule};
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
