//! Typed assertion and encryption contract admission.
use super::*;

pub fn validate_generated_response(value: &GeneratedResponse) -> Result<()> {
    match value {
        GeneratedResponse::Uuid | GeneratedResponse::UuidV4 => Ok(()),
        GeneratedResponse::Random { length, .. } => {
            ensure!(
                length.is_none_or(|length| (1..=1_048_576).contains(&length)),
                "random value length exceeds bounds"
            );
            Ok(())
        }
        GeneratedResponse::Template { template, fields } => {
            let names = traffic_contract::template::validate_template(template)?;
            ensure!(
                (1..=16).contains(&fields.len()) && names == fields.keys().cloned().collect(),
                "template fields must exactly match 1..16 named slots"
            );
            for field in fields.values() {
                proven(field, |field| {
                    ensure!(
                        field.length.is_none_or(|value| (1..=4096).contains(&value)),
                        "template token length exceeds bounds"
                    );
                    if let Some(bytes) = field.decoded_bytes {
                        ensure!(
                            matches!(
                                field.format,
                                RandomEncoding::Base64 | RandomEncoding::Base64url
                            ) && (1..=1024).contains(&bytes),
                            "decoded_bytes requires bounded base64 token"
                        );
                    }
                    Ok(())
                })?;
            }
            Ok(())
        }
        GeneratedResponse::EncryptedJson { key, fields, .. } => {
            let source = match key {
                EncryptionKey::Startup { source } => source,
                EncryptionKey::StartupOrSourceDefault { source, fallback } => {
                    let path = std::path::Path::new(&fallback.path);
                    ensure!(
                        !fallback.path.is_empty()
                            && path.is_relative()
                            && path.components().all(|component| matches!(
                                component,
                                std::path::Component::Normal(_)
                            )),
                        "Source default key requires an exact relative Source file"
                    );
                    let digest = fallback
                        .file_sha256
                        .strip_prefix("sha256:")
                        .context("Source key file requires sha256 fingerprint")?;
                    ensure!(
                        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
                        "Source key file fingerprint is invalid"
                    );
                    ensure!(
                        fallback.byte_range[0] < fallback.byte_range[1]
                            && fallback.byte_range[1] - fallback.byte_range[0] <= 256,
                        "Source key literal range must contain 1..256 bytes"
                    );
                    source
                }
            };
            validate_startup_key(source)?;
            ensure!(fields.len() <= 128, "encrypted JSON exceeds 128 contracts");
            for (pointer, field) in fields {
                compiler::validate_pointer(pointer, true)?;
                proven(field, |field| match field {
                    PlaintextContract::Time(time) => validate_json_time(time, pointer),
                    _ => Ok(()),
                })?;
            }
            Ok(())
        }
    }
}

pub fn validate_body_field(
    codec: BodyCodec,
    field: &BodyField,
    context: &crate::CompilationContext<'_>,
) -> Result<()> {
    let selector = match field {
        BodyField::Timestamp {
            part,
            element,
            format,
        } => {
            ensure!(
                matches!(format, TimestampFormat::Rfc3339 | TimestampFormat::AmzDate),
                "DOCX XML timestamps require a supported text timestamp format"
            );
            ensure!(
                codec == BodyCodec::Docx,
                "part/element timestamp requires DOCX codec"
            );
            text(part, "DOCX part", 1024)?;
            text(element, "DOCX element", 256)?;
            ensure!(
                !part.starts_with('/')
                    && part.len() <= 256
                    && part
                        .split('/')
                        .all(|segment| !segment.is_empty() && !matches!(segment, "." | "..")),
                "DOCX part requires a safe relative OPC name"
            );
            ensure!(
                element.len() <= 128
                    && element
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b":_-.".contains(&byte)),
                "DOCX element requires a qualified XML name"
            );
            return Ok(());
        }
        BodyField::Unordered { selector } => {
            context
                .policies
                .prepare("unordered", &traffic_value::Value::Null)?;
            selector
        }
        BodyField::JoinedString {
            selector,
            separator,
        } => {
            ensure!(
                !separator.is_empty() && separator.len() <= 16 && !separator.contains(['\r', '\n']),
                "joined-string separator exceeds bounds"
            );
            let options = serde_json::from_value(serde_json::json!({"separator":separator}))?;
            context
                .policies
                .prepare("unordered-joined-string", &options)?;
            selector
        }
    };
    match selector {
        BodySelector::Json { pointer } => {
            ensure!(
                codec == BodyCodec::Json,
                "JSON selector requires JSON codec"
            );
            compiler::validate_pointer(pointer, true)?;
        }
        BodySelector::Protobuf {
            field_path,
            alias,
            element_type,
        } => {
            ensure!(
                codec == BodyCodec::Protobuf && !field_path.is_empty() && field_path.len() <= 32,
                "invalid Protobuf response selector"
            );
            ensure!(
                field_path
                    .iter()
                    .all(|n| (1..=536_870_911).contains(n) && !(19_000..=19_999).contains(n)),
                "invalid Protobuf field number"
            );
            text(alias, "Protobuf field alias", 1024)?;
            ensure!(
                !matches!(field, BodyField::JoinedString { .. })
                    || *element_type == ProtobufElement::String,
                "joined Protobuf value must be a string"
            );
        }
        BodySelector::Hessian2 { value_path, alias } => {
            ensure!(
                codec == BodyCodec::Hessian2 && value_path.len() <= 32,
                "invalid Hessian2 response selector"
            );
            for part in value_path {
                text(part, "Hessian2 path segment", 256)?;
            }
            text(alias, "Hessian2 field alias", 1024)?;
        }
    }
    Ok(())
}

pub fn validate_nonce(nonce: &NonceClaim) -> Result<()> {
    ensure!(
        matches!(nonce.pointer.as_str(), "/jti" | "/nonce"),
        "nonce contract selects /jti or /nonce"
    );
    if let NonceFormat::Base64url { decoded_bytes } = nonce.format {
        ensure!(
            (1..=256).contains(&decoded_bytes),
            "nonce size must be 1..256 bytes"
        );
    }
    Ok(())
}
