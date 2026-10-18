//! The custom signature has the same immutable request and private-key witnesses
//! as JWT input rules. Source self-validation still requires fresh Target Replay.
use super::*;
use crate::request_rules::{jwt, keys::ResolvedSigningKey, signed_timestamp};

pub(super) fn validate(
    compiled: &CompiledPolicy,
    root: &Path,
    case: &NativeSourceCase<'_>,
    checked: &mut NativeSourceDependencyValidation,
) -> Result<()> {
    let body = super::super::super::case_condition::request_body(case.request);
    let path = super::super::super::pattern::uri_path(
        case.request["uri"]
            .as_str()
            .context("Source input URI is absent")?,
    );
    for native in &compiled.native {
        let NativeEffect::InputSignedTimestamp(effect) = &native.rule.effect else {
            continue;
        };
        if !NativeScopeGuard::from_rule(&native.rule).matches_case(
            case.request["method"].as_str().unwrap_or_default(),
            &path,
            body.as_ref(),
        ) {
            continue;
        }
        let (original, decrypted) =
            crate::request_headers::read_request_file_parts(&case.dir.join("request.json"))?;
        let original: Value = serde_json::from_slice(&original)?;
        let source = decrypted
            .as_deref()
            .map(serde_json::from_slice::<Value>)
            .transpose()?
            .unwrap_or_else(|| original.clone());
        ensure!(
            *case.request == original || *case.request == source,
            "Source signed input differs from its immutable recording"
        );
        let Some(body) = signed_timestamp::body(&source)? else {
            continue;
        };
        let key = ResolvedSigningKey::resolve(root, &signed_timestamp::key_source(effect))?;
        if !signed_timestamp::verifies(&body, effect, key.bytes()) {
            continue;
        }
        let mut translated = source.clone();
        let Some(observation) = signed_timestamp::apply(
            &mut translated,
            effect,
            key.bytes(),
            jwt::request_timestamp(&source)?,
        )?
        else {
            continue;
        };
        ensure!(
            observation.offset_seconds == Some(0) && translated == source,
            "Source signed input self translation changed the request"
        );
        key.ensure_current()?;
        checked.key_witnesses.extend(key.witnesses().cloned());
        *checked.rules.entry(native.rule.id.clone()).or_default() += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use md5::{Digest, Md5};
    use serde_json::json;

    #[test]
    fn source_signed_input_requires_original_request_signature_and_freezes_key_witnesses() {
        let rule = json!({"id":"signed-login","match":{"api":"POST /login"},"effect":{
            "kind":"input_signed_timestamp","algorithm":"md5_sorted_fields",
            "fields":{"timestamp":"/timestamp","user":"/user"},
            "timestamp_pointer":"/timestamp","signature_pointer":"/sign","secret_parameter":"secret",
            "signing_key":{"kind":"target_env","name":"LOGIN_SECRET"},"time":"preserve_relative"},
            "proof":{"source":"login.py:verify","fact":"The application verifies sorted MD5 fields and timestamp age"}});
        let compiled = crate::policy::compile_policy(
            &serde_json::from_value(json!({"format":"traffic-policy/v1","rules":[rule]})).unwrap(),
        )
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let env = temp.path().join(crate::repository::LOCAL_TARGET_ENV_PATH);
        std::fs::create_dir_all(env.parent().unwrap()).unwrap();
        std::fs::write(&env, "LOGIN_SECRET=test-key\n").unwrap();
        let mut source = json!({"method":"POST","uri":"/login","timestamp":"1970-01-01T00:16:40Z","headers":{},
            "body":{"encoding":"utf8","truncated":false,"data":json!({"timestamp":"995","user":"user",
                "sign":format!("{:x}",Md5::digest(b"timestamp=995&user=user&secret=test-key"))}).to_string()}});
        let path = temp.path().join("request.json");
        let original = source.to_string();
        std::fs::write(&path, &original).unwrap();
        let check = |source: &Value| {
            validate_native_source_dependencies(
                &compiled,
                &BTreeSet::from(["signed-login".into()]),
                temp.path(),
                &[NativeSourceCase {
                    id: "case",
                    dir: temp.path(),
                    request: source,
                    events: &[],
                }],
            )
        };
        let checked = check(&source).unwrap();
        assert_eq!(checked.rules["signed-login"], 1);
        assert!(checked.key_witnesses.iter().any(|(path, _)| *path == env));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        source["uri"] = "/login?edited=true".into();
        assert!(check(&source).is_err());
        std::fs::write(&env, "LOGIN_SECRET=changed-key\n").unwrap();
        assert!(check(&serde_json::from_str(&original).unwrap()).is_err());
    }
}
