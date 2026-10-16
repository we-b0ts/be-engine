//! Pure generated-value validation. Secret bytes and plaintext never enter errors.
use std::collections::BTreeMap;

use aes_gcm::aes::{
    Aes128, Aes192, Aes256,
    cipher::{Block, BlockDecrypt, KeyInit},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::Serialize;
use serde_json::Value;

use super::json::{self, AnchorClocks, Comparison, Field};
use crate::policy::{
    FieldContract,
    native::{GeneratedResponse, PlaintextContract, RandomEncoding},
};

pub(crate) mod template;

const MAX_CIPHERTEXT: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GeneratedError {
    InvalidType,
    InvalidShape,
    MissingKey,
    InvalidKeyLength,
    InvalidCiphertext,
    InvalidJson,
    ContractMismatch,
}

/// A caller supplies its immutable startup-key snapshot. This function cannot
/// resolve environment values, consume recorded exchanges or write evidence.
pub(crate) fn compare_value(
    source: &Value,
    target: &Value,
    contract: &GeneratedResponse,
    key: Option<&[u8]>,
    rule_id: &str,
    clocks: AnchorClocks,
) -> Result<Comparison, GeneratedError> {
    let source = source.as_str().ok_or(GeneratedError::InvalidType)?;
    let target = target.as_str().ok_or(GeneratedError::InvalidType)?;
    match contract {
        GeneratedResponse::Uuid => {
            uuid_value(source, false)?;
            uuid_value(target, false)?;
            Ok(evaluated(rule_id))
        }
        GeneratedResponse::UuidV4 => {
            uuid_value(source, true)?;
            uuid_value(target, true)?;
            Ok(evaluated(rule_id))
        }
        GeneratedResponse::Random { format, length } => {
            random_value(source, format, *length)?;
            random_value(target, format, *length)?;
            if length.is_none() && source.len() != target.len() {
                return Err(GeneratedError::InvalidShape);
            }
            Ok(evaluated(rule_id))
        }
        GeneratedResponse::Template { template, fields } => {
            self::template::compare(source, target, template, fields, rule_id)
        }
        GeneratedResponse::EncryptedJson {
            key: _,
            envelope: _,
            fields,
        } => {
            let key = key.ok_or(GeneratedError::MissingKey)?;
            let mut source = decrypt_json(source, key)?;
            let mut target = decrypt_json(target, key)?;
            let mut owned = BTreeMap::new();
            for (pointer, field) in fields {
                let contract = match &field.contract {
                    PlaintextContract::Unordered => FieldContract::Unordered,
                    PlaintextContract::Time(time) => FieldContract::Time {
                        format: time.format,
                        relation: time.relation,
                        anchor: time.anchor,
                        utc_offset: time.utc_offset.clone(),
                        clock_group: time.clock_group.clone(),
                    },
                    PlaintextContract::Duration { unit, anchor } => FieldContract::Duration {
                        unit: *unit,
                        anchor: *anchor,
                    },
                    PlaintextContract::UuidV4 => {
                        normalize_uuids(&mut source, pointer)?;
                        normalize_uuids(&mut target, pointer)?;
                        continue;
                    }
                };
                owned.insert(pointer.clone(), contract);
            }
            let selected = owned
                .iter()
                .map(|(pointer, contract)| Field {
                    rule_id,
                    pointer,
                    contract,
                })
                .collect::<Vec<_>>();
            let mut compared = json::compare(&source, &target, &selected, clocks);
            if !compared.passed() {
                return Err(GeneratedError::ContractMismatch);
            }
            compared.evaluated.insert(rule_id.into());
            Ok(compared)
        }
    }
}

fn evaluated(rule_id: &str) -> Comparison {
    let mut compared = Comparison::default();
    compared.evaluated.insert(rule_id.into());
    compared
}

fn uuid_value(value: &str, v4: bool) -> Result<(), GeneratedError> {
    let uuid = uuid::Uuid::parse_str(value).map_err(|_| GeneratedError::InvalidShape)?;
    if v4 && (uuid.get_version_num() != 4 || uuid.get_variant() != uuid::Variant::RFC4122) {
        return Err(GeneratedError::InvalidShape);
    }
    Ok(())
}

fn normalize_uuids(root: &mut Value, pattern: &str) -> Result<(), GeneratedError> {
    fn visit(
        value: &Value,
        segments: &[&str],
        pointer: &str,
        out: &mut Vec<String>,
    ) -> Result<(), GeneratedError> {
        if out.len() > 16_384 {
            return Err(GeneratedError::ContractMismatch);
        }
        let Some((segment, rest)) = segments.split_first() else {
            out.push(pointer.into());
            return Ok(());
        };
        if *segment == "*"
            && let Some(values) = value.as_array()
        {
            for (index, value) in values.iter().enumerate() {
                visit(value, rest, &format!("{pointer}/{index}"), out)?;
            }
        } else if let Some(value) = value.pointer(&format!("/{segment}")) {
            visit(value, rest, &format!("{pointer}/{segment}"), out)?;
        }
        Ok(())
    }
    let mut pointers = vec![];
    let segments = pattern.split('/').skip(1).collect::<Vec<_>>();
    visit(root, &segments, "", &mut pointers)?;
    if pointers.is_empty() {
        return Err(GeneratedError::ContractMismatch);
    }
    for pointer in pointers {
        let value = root
            .pointer_mut(&pointer)
            .ok_or(GeneratedError::ContractMismatch)?;
        uuid_value(value.as_str().ok_or(GeneratedError::InvalidType)?, true)?;
        // Both validated copies use one constant so outer multiset pairing is
        // independent of the original order. No identity binding is invented.
        *value = Value::Null;
    }
    Ok(())
}

fn random_value(
    value: &str,
    format: &RandomEncoding,
    length: Option<usize>,
) -> Result<(), GeneratedError> {
    if value.is_empty()
        || value.len() > MAX_CIPHERTEXT
        || length.is_some_and(|length| length != value.len())
    {
        return Err(GeneratedError::InvalidShape);
    }
    let valid = match format {
        RandomEncoding::Uuid => return uuid_value(value, false),
        RandomEncoding::Hex => value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        RandomEncoding::Base64 => STANDARD
            .decode(value)
            .ok()
            .is_some_and(|bytes| STANDARD.encode(bytes) == value),
        RandomEncoding::Base64url => URL_SAFE_NO_PAD
            .decode(value)
            .ok()
            .is_some_and(|bytes| URL_SAFE_NO_PAD.encode(bytes) == value),
        RandomEncoding::Alphanumeric => value.bytes().all(|byte| byte.is_ascii_alphanumeric()),
        RandomEncoding::Decimal => value.bytes().all(|byte| byte.is_ascii_digit()),
        RandomEncoding::String => !value.chars().any(char::is_control),
    };
    valid.then_some(()).ok_or(GeneratedError::InvalidShape)
}

fn decrypt_json(value: &str, key: &[u8]) -> Result<Value, GeneratedError> {
    let mut plaintext = decrypt(value, key)?;
    let result = crate::json_value::parse(&plaintext).ok_or(GeneratedError::InvalidJson);
    plaintext.fill(0);
    result
}

/// CBC is an encryption envelope, not an authentication or signature claim.
fn decrypt(value: &str, key: &[u8]) -> Result<Vec<u8>, GeneratedError> {
    if !matches!(key.len(), 16 | 24 | 32) {
        return Err(GeneratedError::InvalidKeyLength);
    }
    if value.len() > MAX_CIPHERTEXT {
        return Err(GeneratedError::InvalidCiphertext);
    }
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| GeneratedError::InvalidCiphertext)?;
    if STANDARD.encode(&bytes) != value || bytes.len() < 32 || bytes.len() % 16 != 0 {
        return Err(GeneratedError::InvalidCiphertext);
    }
    let mut plaintext = bytes[16..].to_vec();
    match key.len() {
        16 => decrypt_blocks::<Aes128>(&mut plaintext, &bytes, key)?,
        24 => decrypt_blocks::<Aes192>(&mut plaintext, &bytes, key)?,
        32 => decrypt_blocks::<Aes256>(&mut plaintext, &bytes, key)?,
        _ => unreachable!("validated AES key length"),
    }
    let padding = usize::from(*plaintext.last().ok_or(GeneratedError::InvalidCiphertext)?);
    if padding == 0
        || padding > 16
        || !plaintext[plaintext.len() - padding..]
            .iter()
            .all(|byte| usize::from(*byte) == padding)
    {
        plaintext.fill(0);
        return Err(GeneratedError::InvalidCiphertext);
    }
    plaintext.truncate(plaintext.len() - padding);
    Ok(plaintext)
}

fn decrypt_blocks<C>(
    plaintext: &mut [u8],
    envelope: &[u8],
    key: &[u8],
) -> Result<(), GeneratedError>
where
    C: BlockDecrypt + KeyInit,
    C::BlockSize: aes_gcm::aes::cipher::typenum::Unsigned,
{
    let cipher = C::new_from_slice(key).map_err(|_| GeneratedError::InvalidKeyLength)?;
    for (index, chunk) in plaintext.chunks_exact_mut(16).enumerate() {
        let block = Block::<C>::from_mut_slice(chunk);
        cipher.decrypt_block(block);
        for (byte, previous) in chunk.iter_mut().zip(&envelope[index * 16..index * 16 + 16]) {
            *byte ^= previous;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
