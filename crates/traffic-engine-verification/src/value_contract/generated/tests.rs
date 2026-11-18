use super::*;
use crate::policy::native::*;
use aes_gcm::aes::{
    Aes256,
    cipher::{Block, BlockEncrypt, KeyInit},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::json;

fn encrypted(fields: BTreeMap<String, Proven<PlaintextContract>>) -> GeneratedResponse {
    GeneratedResponse::EncryptedJson {
        envelope: CipherEnvelope::Base64IvAesCbcPkcs7,
        key: EncryptionKey::Startup {
            source: StartupKey::TargetEnv {
                name: "CRYPTO_KEY".into(),
            },
        },
        fields,
    }
}

fn encode<C: BlockEncrypt + KeyInit>(plaintext: &[u8], key: &[u8], iv: [u8; 16]) -> String {
    let cipher = C::new_from_slice(key).unwrap();
    let padding = 16 - plaintext.len() % 16;
    let mut padded = plaintext.to_vec();
    padded.resize(padded.len() + padding, padding as u8);
    let mut envelope = iv.to_vec();
    let mut previous = iv;
    for chunk in padded.as_chunks_mut::<16>().0 {
        for (byte, previous) in chunk.iter_mut().zip(previous) {
            *byte ^= previous;
        }
        cipher.encrypt_block(Block::<C>::from_mut_slice(chunk));
        previous.copy_from_slice(chunk);
        envelope.extend_from_slice(chunk);
    }
    STANDARD.encode(envelope)
}

#[test]
fn decoded_cipher_uses_global_formats_and_preserves_plaintext_and_iv_relationships() {
    let key = [8u8; 32];
    let plan = crate::policy::parse_and_compile_policy(
        "format: traffic-policy/v3\njson:\n  fields:\n    /expire_at: {kind: time, formats: [unix_seconds]}\n    /id: {kind: identity, formats: [uuid]}\n",
    ).unwrap().global_json.unwrap();
    let clocks = AnchorClocks {
        dependency: super::super::time::ClockPair {
            source: chrono::DateTime::from_timestamp(1_700_000_000, 0),
            target: chrono::DateTime::from_timestamp(1_700_001_000, 0),
        },
        ..Default::default()
    };
    let source = serde_json::json!({"expire_at": 1_700_000_060, "id": "01234567-89ab-4def-8123-456789abcdef", "stable": "original"});
    let target = serde_json::json!({"expire_at": 1_700_001_060, "id": "11234567-89ab-4def-8123-456789abcdef", "stable": "original"});
    let contract = encrypted(BTreeMap::new());
    let cipher = |value: &Value, iv| {
        json!(encode::<Aes256>(
            &serde_json::to_vec(value).unwrap(),
            &key,
            [iv; 16]
        ))
    };
    let check = |value: &Value, iv| {
        compare_value_global(
            &cipher(&source, 1),
            &cipher(value, iv),
            &contract,
            Some(&key),
            "cipher",
            clocks,
            Some(&plan),
        )
    };
    let compared = check(&target, 2).unwrap();
    assert_eq!(compared.identity_pairs().len(), 1);
    assert!(compared.time_validations.values().sum::<usize>() > 0);
    for (field, value) in [
        ("stable", json!("changed")),
        ("expire_at", json!(1_700_001_080)),
        ("expire_at", json!(null)),
        ("id", json!("invalid")),
    ] {
        let mut changed = target.clone();
        changed[field] = value;
        assert!(check(&changed, 2).is_err());
    }
    let mut missing = target.clone();
    missing.as_object_mut().unwrap().remove("expire_at");
    assert!(check(&missing, 2).is_err());
    let mut conflicting_iv = compared;
    conflicting_iv.merge_and_validate(check(&target, 3).unwrap());
    assert!(!conflicting_iv.passed());
    assert!(
        compare_value(
            &cipher(&source, 1),
            &cipher(&target, 2),
            &contract,
            Some(&key),
            "cipher",
            clocks
        )
        .is_err(),
        "without a global declaration plaintext remains exact"
    );
}

#[test]
fn decoded_cipher_occurrences_keep_independent_times_and_atomic_shared_identities() {
    let key = [8u8; 32];
    let plan = crate::policy::parse_and_compile_policy(
        "format: traffic-policy/v3\njson:\n  fields:\n    /items: {kind: unordered}\n    /expire_at: {kind: time, formats: [unix_seconds]}\n    /id: {kind: identity, formats: [uuid]}\n",
    ).unwrap().global_json.unwrap();
    let clocks = AnchorClocks {
        dependency: super::super::time::ClockPair {
            source: chrono::DateTime::from_timestamp(1_700_000_000, 0),
            target: chrono::DateTime::from_timestamp(1_700_001_000, 0),
        },
        ..Default::default()
    };
    let source_id = "01234567-89ab-4def-8123-456789abcdef";
    let other_source_id = "11234567-89ab-4def-8123-456789abcdef";
    let target_id = "21234567-89ab-4def-8123-456789abcdef";
    let other_target_id = "31234567-89ab-4def-8123-456789abcdef";
    let cipher = |time, id: &str, iv| {
        encode::<Aes256>(
            &serde_json::to_vec(&json!({"expire_at":time,"id":id,"stable":"same"})).unwrap(),
            &key,
            [iv; 16],
        )
    };
    let source = json!({"id":source_id,"expire_at":1_700_000_060,"items":[
        {"name":"first","cipher":cipher(1_700_000_060i64,source_id,1)},
        {"name":"second","cipher":cipher(1_700_000_060i64,other_source_id,2)},
    ]});
    let target = json!({"id":target_id,"expire_at":1_700_001_062,"items":[
        {"name":"second","cipher":cipher(1_700_001_060i64,other_target_id,4)},
        {"name":"first","cipher":cipher(1_700_001_061i64,target_id,3)},
    ]});
    let contract = encrypted(BTreeMap::new());
    let native = [json::NativeField {
        rule_id: "cipher",
        pointer: "/items/*/cipher",
        contract: &contract,
        key: Some(&key),
        global: Some(&plan),
    }];
    let selected = plan.comparison_fields(&source, &target, clocks).unwrap();
    let fields = selected
        .iter()
        .map(|(pointer, contract)| json::Field {
            rule_id: crate::policy::GLOBAL_JSON_ID,
            pointer,
            contract,
        })
        .collect::<Vec<_>>();
    let compare = |target| json::compare_with_native(&source, target, &fields, &native, clocks);
    let good = compare(&target);
    assert!(good.passed(), "{:?}", good.differences);
    assert_eq!(good.identity_pairs().len(), 2);
    let mut inconsistent_identity = target.clone();
    inconsistent_identity["items"][1]["cipher"] = cipher(1_700_001_061, other_target_id, 3).into();
    assert!(
        !compare(&inconsistent_identity).passed(),
        "plaintext identities must agree with outer JSON"
    );
    let mut bad_time = target.clone();
    bad_time["items"][1]["cipher"] = cipher(1_700_001_080, target_id, 3).into();
    assert!(
        !compare(&bad_time).passed(),
        "isolated clocks still enforce the request-relative bound"
    );
    let mut collapsed_iv = target.clone();
    collapsed_iv["items"][1]["cipher"] = cipher(1_700_001_061, target_id, 4).into();
    assert!(
        !compare(&collapsed_iv).passed(),
        "clock isolation must not isolate IV bijections"
    );
    assert!(
        compare(&target).passed(),
        "failed candidate identities must not mutate later comparisons"
    );
}
