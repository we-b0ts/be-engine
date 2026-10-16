//! Explicit typed projection with a complete per-message raw remainder.
mod scalar;
mod wire;

use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Map, Value};

use super::{escape, pointer_matches};
use crate::policy::{ProtobufCodec, ProtobufField, ProtobufType};

// This is engine metadata, not an application field. Author selectors reject NUL.
// Keeping the remainder inside each message preserves whole-element associations
// when the common contract evaluator matches unordered repeated messages.
pub(super) const INTERNAL_KEY: &str = "\0protobuf";

#[derive(Debug, Clone)]
pub(super) struct Document {
    pub logical: Value,
    message: Message,
}

#[derive(Default)]
struct Binding {
    value: Option<(Vec<String>, ProtobufField)>,
    children: BTreeMap<u32, Binding>,
}

#[derive(Debug, Clone)]
struct Message {
    fields: Vec<StoredField>,
}
#[derive(Debug, Clone)]
struct StoredField {
    raw: Vec<u8>,
    tag: Vec<u8>,
    length_padding: usize,
    content: Content,
}
#[derive(Debug, Clone)]
enum Content {
    Raw,
    Scalar {
        pointer: String,
        kind: ProtobufType,
        value: Value,
    },
    Packed {
        kind: ProtobufType,
        elements: Vec<PackedElement>,
    },
    Message(Message),
}
#[derive(Debug, Clone)]
struct PackedElement {
    pointer: String,
    value: Value,
    raw: Vec<u8>,
}

#[derive(Default)]
struct Budget {
    fields: usize,
    values: usize,
}
impl Budget {
    fn field(&mut self) -> Result<()> {
        self.fields += 1;
        ensure!(
            self.fields <= 65_536,
            "Protobuf exceeds 65536 decoded fields"
        );
        Ok(())
    }
    fn value(&mut self) -> Result<()> {
        self.values += 1;
        ensure!(
            self.values <= 65_536,
            "Protobuf exceeds 65536 projected values"
        );
        Ok(())
    }
}

impl Document {
    pub(super) fn decode(codec: &ProtobufCodec, bytes: &[u8]) -> Result<Self> {
        let binding = bindings(codec)?;
        let (message, logical) =
            decode_message(bytes, &binding, &[], &[], None, &mut Budget::default(), 0)?;
        Ok(Self { message, logical })
    }

    pub(super) fn encode(&self, logical: &Value) -> Result<Vec<u8>> {
        Ok(self.message.encode(logical)?.0)
    }
}

fn bindings(codec: &ProtobufCodec) -> Result<Binding> {
    ensure!(
        !codec.fields.is_empty() && codec.fields.len() <= 256,
        "Protobuf requires 1..256 typed bindings"
    );
    let mut root = Binding::default();
    for (alias, field) in &codec.fields {
        ensure!(
            alias.starts_with('/') && !alias.contains('\0'),
            "Protobuf aliases require a non-root application pointer"
        );
        crate::policy::validate_pointer(alias, true)?;
        ensure!(
            !field.field_path.is_empty()
                && field.field_path.len() <= 32
                && field
                    .field_path
                    .iter()
                    .all(|number| (1..(1 << 29)).contains(number)),
            "invalid Protobuf wire path"
        );
        let mut current = &mut root;
        for number in &field.field_path {
            current = current.children.entry(*number).or_default();
        }
        ensure!(current.value.is_none(), "duplicate Protobuf wire path");
        current.value = Some((segments(alias), field.clone()));
    }
    validate_bindings(&root, &[])?;
    Ok(root)
}

fn validate_bindings(binding: &Binding, parent: &[String]) -> Result<()> {
    let mut scope = parent.to_vec();
    if let Some((alias, field)) = &binding.value {
        let relative = alias
            .strip_prefix(parent)
            .context("Protobuf alias is outside its parent message")?;
        ensure!(
            !relative.is_empty() && !relative.iter().any(|segment| segment == "*"),
            "Protobuf wildcard requires an explicitly repeated message ancestor"
        );
        if field.field_type == ProtobufType::Message {
            scope = alias.clone();
            if field.repeated {
                scope.push("*".into());
            }
        } else {
            ensure!(
                binding.children.is_empty(),
                "scalar Protobuf binding cannot have child fields"
            );
        }
    }
    for child in binding.children.values() {
        validate_bindings(child, &scope)?;
    }
    Ok(())
}

fn segments(pointer: &str) -> Vec<String> {
    pointer
        .split('/')
        .skip(1)
        .map(|segment| segment.replace("~1", "/").replace("~0", "~"))
        .collect()
}
fn pointer(path: &[String]) -> String {
    path.iter()
        .map(|segment| format!("/{}", escape(segment)))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn decode_message(
    bytes: &[u8],
    binding: &Binding,
    schema_scope: &[String],
    logical_scope: &[String],
    framing: Option<(&[u8], usize)>,
    budget: &mut Budget,
    depth: usize,
) -> Result<(Message, Value)> {
    ensure!(depth <= 32, "Protobuf message nesting exceeds 32");
    let fields = wire::fields(bytes, budget)?;
    let mut stored = fields
        .iter()
        .map(|field| StoredField {
            raw: field.raw.to_vec(),
            tag: field.tag.to_vec(),
            length_padding: field.length_padding,
            content: Content::Raw,
        })
        .collect::<Vec<_>>();
    let mut groups = BTreeMap::<u32, Vec<usize>>::new();
    for (index, field) in fields.iter().enumerate() {
        groups.entry(field.number).or_default().push(index);
    }
    let mut logical = Map::new();
    let mut unknown = Map::new();
    let mut known = Map::new();
    let mut nested = Map::new();
    for (number, indices) in &groups {
        if !binding.children.contains_key(number) {
            unknown.insert(number.to_string(), raw_values(&fields, indices));
        }
    }
    for (number, child) in &binding.children {
        let indices = groups.get(number).cloned().unwrap_or_default();
        let Some((alias, spec)) = &child.value else {
            ensure!(
                indices.len() <= 1,
                "implicit Protobuf message ancestor is repeated; declare its type and scope"
            );
            if let Some(&index) = indices.first() {
                let field = &fields[index];
                ensure!(
                    field.wire == 2,
                    "Protobuf path traverses a non-message field"
                );
                let (message, mut projection) = decode_message(
                    field.payload,
                    child,
                    schema_scope,
                    logical_scope,
                    Some((field.tag, field.length_padding)),
                    budget,
                    depth + 1,
                )?;
                let projection = projection
                    .as_object_mut()
                    .expect("message projections are objects");
                nested.insert(number.to_string(), projection.remove(INTERNAL_KEY).unwrap());
                merge_objects(&mut logical, std::mem::take(projection))?;
                stored[index].content = Content::Message(message);
            }
            continue;
        };
        ensure!(
            spec.repeated || indices.len() <= 1,
            "duplicate singular Protobuf field"
        );
        let relative = alias
            .strip_prefix(schema_scope)
            .context("invalid Protobuf alias scope")?;
        let mut path = logical_scope.to_vec();
        path.extend(relative.iter().cloned());
        if spec.field_type == ProtobufType::Message {
            let mut values = Vec::new();
            for (position, &index) in indices.iter().enumerate() {
                budget.value()?;
                let field = &fields[index];
                ensure!(
                    field.wire == 2,
                    "Protobuf message requires length-delimited wire data"
                );
                let mut child_schema = alias.clone();
                let mut child_path = path.clone();
                if spec.repeated {
                    child_schema.push("*".into());
                    child_path.push(position.to_string());
                }
                let (message, projection) = decode_message(
                    field.payload,
                    child,
                    &child_schema,
                    &child_path,
                    Some((field.tag, field.length_padding)),
                    budget,
                    depth + 1,
                )?;
                values.push(projection);
                stored[index].content = Content::Message(message);
            }
            if spec.repeated {
                insert(&mut logical, relative, Value::Array(values))?;
            } else if let Some(value) = values.pop() {
                insert(&mut logical, relative, value)?;
            }
            continue;
        }
        let mut values = Vec::new();
        let mut element_raw = Vec::new();
        for (group, &index) in indices.iter().enumerate() {
            let field = &fields[index];
            if spec.repeated && field.wire == 2 && scalar::packable(spec.field_type) {
                let mut offset = 0;
                let mut elements = Vec::new();
                while offset < field.payload.len() {
                    budget.value()?;
                    let start = offset;
                    let value = scalar::decode_packed(spec.field_type, field.payload, &mut offset)?;
                    let mut element_path = path.clone();
                    element_path.push(values.len().to_string());
                    elements.push(PackedElement {
                        pointer: pointer(&element_path),
                        value: value.clone(),
                        raw: field.payload[start..offset].to_vec(),
                    });
                    element_raw.push(serde_json::json!({"raw": STANDARD.encode(&field.payload[start..offset]),
                        "packed": true, "group": group, "tag": STANDARD.encode(field.tag), "length_padding": field.length_padding}));
                    values.push(value);
                }
                stored[index].content = Content::Packed {
                    kind: spec.field_type,
                    elements,
                };
            } else {
                budget.value()?;
                let value = scalar::decode(spec.field_type, field.wire, field.payload)?;
                let mut element_path = path.clone();
                if spec.repeated {
                    element_path.push(values.len().to_string());
                }
                stored[index].content = Content::Scalar {
                    pointer: pointer(&element_path),
                    kind: spec.field_type,
                    value: value.clone(),
                };
                values.push(value);
                element_raw
                    .push(serde_json::json!({"raw": STANDARD.encode(field.raw), "packed": false}));
            }
        }
        if spec.repeated {
            insert(&mut logical, relative, Value::Array(values))?;
        } else if let Some(value) = values.pop() {
            insert(&mut logical, relative, value)?;
        }
        if !indices.is_empty() {
            known.insert(pointer(relative), if spec.repeated {
                serde_json::json!({"raw": raw_values(&fields, &indices), "elements": element_raw})
            } else { raw_values(&fields, &indices) });
        }
    }
    let mut remainder = Map::from_iter([
        ("unknown".into(), Value::Object(unknown)),
        ("known".into(), Value::Object(known)),
        ("nested".into(), Value::Object(nested)),
    ]);
    if let Some((tag, padding)) = framing {
        remainder.insert("tag".into(), Value::String(STANDARD.encode(tag)));
        remainder.insert("length_padding".into(), Value::from(padding));
    }
    logical.insert(INTERNAL_KEY.into(), Value::Object(remainder));
    Ok((Message { fields: stored }, Value::Object(logical)))
}

fn raw_values(fields: &[wire::Field<'_>], indices: &[usize]) -> Value {
    Value::Array(
        indices
            .iter()
            .map(|index| Value::String(STANDARD.encode(fields[*index].raw)))
            .collect(),
    )
}

fn insert(object: &mut Map<String, Value>, path: &[String], value: Value) -> Result<()> {
    let (first, rest) = path
        .split_first()
        .context("Protobuf binding requires a non-root pointer")?;
    if rest.is_empty() {
        ensure!(
            object.insert(first.clone(), value).is_none(),
            "Protobuf logical aliases overlap"
        );
    } else {
        let nested = object
            .entry(first.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        insert(
            nested
                .as_object_mut()
                .context("Protobuf logical alias traverses a scalar")?,
            rest,
            value,
        )?;
    }
    Ok(())
}

fn merge_objects(target: &mut Map<String, Value>, source: Map<String, Value>) -> Result<()> {
    for (key, value) in source {
        match target.get_mut(&key) {
            None => {
                target.insert(key, value);
            }
            Some(Value::Object(existing)) if value.is_object() => {
                merge_objects(existing, value.as_object().unwrap().clone())?;
            }
            _ => anyhow::bail!("Protobuf logical aliases overlap"),
        }
    }
    Ok(())
}

pub(super) fn prepare_comparison(value: &mut Value, scope: &str, selected: &[String]) {
    match value {
        Value::Object(object) => {
            if let Some(metadata) = object.get_mut(INTERNAL_KEY) {
                prepare_remainder(metadata, scope, selected);
            }
            for (key, value) in object
                .iter_mut()
                .filter(|(key, _)| key.as_str() != INTERNAL_KEY)
            {
                prepare_comparison(value, &format!("{scope}/{}", escape(key)), selected);
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter_mut().enumerate() {
                prepare_comparison(value, &format!("{scope}/{index}"), selected);
            }
        }
        _ => {}
    }
}

fn prepare_remainder(metadata: &mut Value, scope: &str, selected: &[String]) {
    if let Some(known) = metadata.get_mut("known").and_then(Value::as_object_mut) {
        known.retain(|path, value| {
            let full_path = format!("{scope}{path}");
            if selected
                .iter()
                .any(|pattern| pointer_matches(pattern, &full_path))
            {
                return false;
            }
            if let Some(elements) = value.get("elements").and_then(Value::as_array) {
                let mut raw = elements.clone();
                let mut masked = false;
                for (index, item) in raw.iter_mut().enumerate() {
                    if selected
                        .iter()
                        .any(|pattern| pointer_matches(pattern, &format!("{full_path}/{index}")))
                    {
                        *item = Value::Null;
                        masked = true;
                    }
                }
                if masked {
                    *value = Value::Array(raw);
                }
            }
            true
        });
    }
    if let Some(nested) = metadata.get_mut("nested").and_then(Value::as_object_mut) {
        for metadata in nested.values_mut() {
            prepare_remainder(metadata, scope, selected);
        }
    }
}

impl Message {
    fn encode(&self, logical: &Value) -> Result<(Vec<u8>, bool)> {
        let mut output = Vec::new();
        let mut changed = false;
        for field in &self.fields {
            let replacement = match &field.content {
                Content::Raw => None,
                Content::Scalar {
                    pointer,
                    kind,
                    value,
                } => {
                    let next = logical
                        .pointer(pointer)
                        .context("delivery removed a Protobuf field")?;
                    if next == value {
                        None
                    } else {
                        Some(scalar::encode(*kind, next)?)
                    }
                }
                Content::Packed { kind, elements } => {
                    let mut payload = Vec::new();
                    let mut edited = false;
                    for element in elements {
                        let next = logical
                            .pointer(&element.pointer)
                            .context("delivery removed a packed element")?;
                        if next == &element.value {
                            payload.extend_from_slice(&element.raw);
                        } else {
                            payload.extend(scalar::encode(*kind, next)?);
                            edited = true;
                        }
                    }
                    if edited {
                        Some(length_delimited(&payload))
                    } else {
                        None
                    }
                }
                Content::Message(message) => {
                    let (payload, edited) = message.encode(logical)?;
                    if edited {
                        Some(length_delimited(&payload))
                    } else {
                        None
                    }
                }
            };
            if let Some(replacement) = replacement {
                output.extend_from_slice(&field.tag);
                if field.length_padding != 0 {
                    let mut offset = 0;
                    let length = wire::varint(&replacement, &mut offset)?;
                    let mut prefix = wire::encode_varint(length);
                    ensure!(
                        prefix.len() + field.length_padding <= 10,
                        "derived Protobuf length cannot preserve its original framing padding"
                    );
                    *prefix.last_mut().expect("varints are nonempty") |= 128;
                    prefix.extend(std::iter::repeat_n(128, field.length_padding - 1));
                    prefix.push(0);
                    output.extend(prefix);
                    output.extend_from_slice(&replacement[offset..]);
                } else {
                    output.extend(replacement);
                }
                changed = true;
            } else {
                output.extend_from_slice(&field.raw);
            }
        }
        Ok((output, changed))
    }
}

fn length_delimited(payload: &[u8]) -> Vec<u8> {
    let mut output = wire::encode_varint(payload.len() as u64);
    output.extend_from_slice(payload);
    output
}
