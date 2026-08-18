use std::borrow::Cow;
use std::collections::BTreeSet;
use std::rc::Rc;

use anyhow::{Context, Result, bail, ensure};
use motan_hessian2::{ClassId, Decoder, Limits, TypeId, ValueKind};

use super::binary_body::{MotanBodyEnvelope, simple_payload};
use super::model::{Hessian2BodyDifference, Hessian2BodyDifferenceKind};
use crate::config::DEFAULT_BODY_LIMIT_BYTES;
use crate::replay::policy::{
    Hessian2JoinedStringPath, Hessian2UnorderedPath, Hessian2ValuePath,
};

const MAX_NODES: usize = 1_000_000;
const MAX_DISCOVERED_PATHS: usize = 32;
const MAX_DIFFERENCES: usize = 32;

/// Separators tried when discovering joined-string candidates. Kept to the
/// common Set-join separators in this business; extend only when a real case
/// appears.
const JOINED_STRING_SEPARATORS: [&str; 3] = [",", ";", "|"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Hessian2OrderDiscovery {
    pub(super) envelope: MotanBodyEnvelope,
    pub(super) unordered_paths: Vec<Hessian2ValuePath>,
    pub(super) unordered_joined_string_paths: Vec<(Hessian2ValuePath, String)>,
    pub(super) differences: Vec<Hessian2BodyDifference>,
    pub(super) order_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum IntegerKind {
    Int,
    Long,
}

/// Java class name and field layout shared by every instance of one class
/// definition in a body.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ClassLayout {
    name: Rc<str>,
    fields: Vec<Rc<str>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum HessianValue<'a> {
    Null,
    Boolean(bool),
    Integer(IntegerKind, i64),
    Double(u64),
    Date(i64),
    String(Cow<'a, str>),
    Binary(Cow<'a, [u8]>),
    List {
        type_name: Option<Rc<str>>,
        values: Vec<HessianValue<'a>>,
    },
    Map {
        type_name: Option<Rc<str>>,
        entries: Vec<(HessianValue<'a>, HessianValue<'a>)>,
    },
    Object {
        class: Rc<ClassLayout>,
        fields: Vec<HessianValue<'a>>,
    },
    Reference(usize),
}

struct Parser<'a> {
    decoder: Decoder<'a>,
    classes: Vec<Option<Rc<ClassLayout>>>,
    types: Vec<Option<Rc<str>>>,
    nodes: usize,
}

pub(crate) fn is_motan_hessian2_body(body: &[u8]) -> bool {
    resolve_body(body).is_ok()
}

/// Reports how a Motan body carries its Hessian2 value, or `None` when it
/// carries no complete Hessian2 value at all.
pub(crate) fn motan_hessian2_envelope_name(body: &[u8]) -> Option<&'static str> {
    resolve_body(body)
        .ok()
        .map(|(envelope, _)| envelope.as_str())
}

pub(in crate::replay) fn compare_motan_hessian2(
    expected: &[u8],
    actual: &[u8],
    unordered_paths: &[Hessian2UnorderedPath],
    joined_string_paths: &[Hessian2JoinedStringPath],
) -> Result<bool> {
    let (_, mut expected, mut actual) = parse_bodies(expected, actual)?;
    for path in unordered_paths {
        canonicalize_path(&mut expected, &path.value_path.0, &path.value_path)?;
        canonicalize_path(&mut actual, &path.value_path.0, &path.value_path)?;
    }
    for path in joined_string_paths {
        canonicalize_joined_string(&mut expected, &path.value_path.0, &path.separator)?;
        canonicalize_joined_string(&mut actual, &path.value_path.0, &path.separator)?;
    }
    Ok(expected == actual)
}

pub(super) fn evaluate_motan_hessian2(
    expected: &[u8],
    actual: &[u8],
    unordered_paths: &[Hessian2UnorderedPath],
    joined_string_paths: &[Hessian2JoinedStringPath],
) -> Result<(bool, Hessian2OrderDiscovery)> {
    let mut discovery = discover_motan_hessian2_order(expected, actual)?;
    let matches = compare_motan_hessian2(expected, actual, unordered_paths, joined_string_paths)?;
    for rule in unordered_paths {
        for difference in discovery
            .differences
            .iter_mut()
            .filter(|difference| difference.value_path == rule.value_path)
        {
            difference.display_path.clone_from(&rule.display_path);
        }
    }
    for rule in joined_string_paths {
        for difference in discovery
            .differences
            .iter_mut()
            .filter(|difference| difference.value_path == rule.value_path)
        {
            difference.display_path.clone_from(&rule.display_path);
        }
    }
    if matches {
        discovery.order_only = true;
    }
    Ok((matches, discovery))
}

pub(super) fn discover_motan_hessian2_order(
    expected: &[u8],
    actual: &[u8],
) -> Result<Hessian2OrderDiscovery> {
    let (envelope, mut expected, mut actual) = parse_bodies(expected, actual)?;
    let mut selected = BTreeSet::new();
    let mut joined_string = BTreeSet::<(Hessian2ValuePath, String)>::new();

    while expected != actual && selected.len() < MAX_DISCOVERED_PATHS {
        let mut discovered = BTreeSet::new();
        discover_paths(
            &expected,
            &actual,
            &mut Vec::new(),
            &mut discovered,
            &mut joined_string,
        );
        discovered.retain(|path| !selected.contains(path));
        if discovered.is_empty() {
            break;
        }
        let remaining = MAX_DISCOVERED_PATHS - selected.len();
        let next = discovered.into_iter().take(remaining).collect::<Vec<_>>();
        for path in &next {
            canonicalize_path(&mut expected, &path.0, path)?;
            canonicalize_path(&mut actual, &path.0, path)?;
        }
        selected.extend(next);
    }
    // Joined-string discovery does not feed back into the canonicalization loop:
    // canonicalizing a joined string would require a chosen separator, which the
    // discovery pass does not fix. Candidates are reported as-is for review.

    let order_only = expected == actual;
    let mut differences = selected
        .iter()
        .cloned()
        .map(|value_path| Hessian2BodyDifference {
            display_path: value_path.display_path(),
            value_path,
            kind: Hessian2BodyDifferenceKind::ListOrderMismatch,
        })
        .collect::<Vec<_>>();
    if !order_only {
        collect_residual_differences(&expected, &actual, &mut Vec::new(), &mut differences);
    }
    differences.sort();
    differences.dedup();
    differences.truncate(MAX_DIFFERENCES);
    Ok(Hessian2OrderDiscovery {
        envelope,
        unordered_paths: selected.into_iter().collect(),
        unordered_joined_string_paths: joined_string.into_iter().collect(),
        differences,
        order_only,
    })
}

fn validate_complete_value(payload: &[u8]) -> Result<()> {
    let mut decoder = Decoder::new(payload, hessian_limits())
        .context("failed to initialize Hessian2 body decoder")?;
    decoder
        .skip_value()
        .context("failed to parse one complete Hessian2 value")?;
    ensure!(decoder.remaining() == 0, "Hessian2 body has trailing bytes");
    Ok(())
}

/// Resolves the Hessian2 value carried by a Motan body.
///
/// A Motan method returning `byte[]` wraps its value in the simple
/// byte-array envelope, while Hessian2 serialization of any other return type
/// occupies the whole body. Both are accepted, and the framing is selected by
/// the parse that succeeds so the choice never depends on payload guessing.
fn resolve_body(body: &[u8]) -> Result<(MotanBodyEnvelope, &[u8])> {
    if let Some(payload) = simple_payload(body)
        && validate_complete_value(payload).is_ok()
    {
        return Ok((MotanBodyEnvelope::SimpleByteArray, payload));
    }
    validate_complete_value(body)
        .context("Motan body is not one complete Hessian2 value in either supported envelope")?;
    Ok((MotanBodyEnvelope::Raw, body))
}

fn parse_body(body: &[u8]) -> Result<(MotanBodyEnvelope, HessianValue<'_>)> {
    let (envelope, payload) = resolve_body(body)?;
    let value = Parser::new(payload)?.parse_complete()?;
    Ok((envelope, value))
}

/// Parses both compared bodies and rejects a framing change, which is a
/// response-shape difference rather than a body-value difference.
fn parse_bodies<'a>(
    expected: &'a [u8],
    actual: &'a [u8],
) -> Result<(MotanBodyEnvelope, HessianValue<'a>, HessianValue<'a>)> {
    let (expected_envelope, expected_value) =
        parse_body(expected).context("source-before Motan Hessian2 body")?;
    let (actual_envelope, actual_value) =
        parse_body(actual).context("candidate Motan Hessian2 body")?;
    ensure!(
        expected_envelope == actual_envelope,
        "Motan Hessian2 bodies use different envelopes: source-before {} and candidate {}",
        expected_envelope.as_str(),
        actual_envelope.as_str()
    );
    Ok((expected_envelope, expected_value, actual_value))
}

fn hessian_limits() -> Limits {
    Limits {
        max_input_bytes: DEFAULT_BODY_LIMIT_BYTES,
        max_output_bytes: DEFAULT_BODY_LIMIT_BYTES,
        max_string_bytes: DEFAULT_BODY_LIMIT_BYTES,
        max_binary_bytes: DEFAULT_BODY_LIMIT_BYTES,
        ..Limits::default()
    }
}

impl<'a> Parser<'a> {
    fn new(input: &'a [u8]) -> Result<Self> {
        let decoder = Decoder::new(input, hessian_limits())
            .context("failed to initialize Hessian2 semantic decoder")?;
        Ok(Self {
            decoder,
            classes: Vec::new(),
            types: Vec::new(),
            nodes: 0,
        })
    }

    fn parse_complete(mut self) -> Result<HessianValue<'a>> {
        let value = self.parse_value()?;
        ensure!(
            self.decoder.remaining() == 0,
            "Hessian2 body has trailing bytes"
        );
        Ok(value)
    }

    fn parse_value(&mut self) -> Result<HessianValue<'a>> {
        self.nodes = self
            .nodes
            .checked_add(1)
            .context("Hessian2 body value count overflow")?;
        ensure!(self.nodes <= MAX_NODES, "Hessian2 body has too many values");
        match self.decoder.peek_kind()? {
            ValueKind::Null => {
                ensure!(self.decoder.try_read_null()?, "expected Hessian2 null");
                Ok(HessianValue::Null)
            }
            ValueKind::Bool => Ok(HessianValue::Boolean(self.decoder.read_bool()?)),
            ValueKind::Int => Ok(HessianValue::Integer(
                IntegerKind::Int,
                self.decoder.read_i64()?,
            )),
            ValueKind::Long => Ok(HessianValue::Integer(
                IntegerKind::Long,
                self.decoder.read_i64()?,
            )),
            ValueKind::Double => Ok(HessianValue::Double(self.decoder.read_f64()?.to_bits())),
            ValueKind::Date => Ok(HessianValue::Date(self.decoder.read_date_millis()?)),
            ValueKind::String => Ok(HessianValue::String(self.decoder.read_str()?)),
            ValueKind::Binary => Ok(HessianValue::Binary(self.decoder.read_binary()?)),
            ValueKind::List => self.parse_list(),
            ValueKind::Map => self.parse_map(),
            ValueKind::Object => self.parse_object(),
            ValueKind::Reference => Ok(HessianValue::Reference(self.decoder.read_reference()?)),
        }
    }

    fn parse_list(&mut self) -> Result<HessianValue<'a>> {
        let header = self.decoder.begin_list()?;
        let type_name = self.type_name(header.type_id());
        let mut values = Vec::with_capacity(header.length().unwrap_or(0).min(1024));
        while self.decoder.list_has_next(header, values.len())? {
            values.push(self.parse_value()?);
        }
        self.decoder.end_list(header, values.len())?;
        Ok(HessianValue::List { type_name, values })
    }

    fn parse_map(&mut self) -> Result<HessianValue<'a>> {
        let header = self.decoder.begin_map()?;
        let type_name = self.type_name(header.type_id());
        let mut entries = Vec::new();
        while self.decoder.map_has_next(entries.len())? {
            entries.push((self.parse_value()?, self.parse_value()?));
        }
        self.decoder.end_map()?;
        entries.sort();
        Ok(HessianValue::Map { type_name, entries })
    }

    fn parse_object(&mut self) -> Result<HessianValue<'a>> {
        let class_id = self.decoder.begin_object()?;
        let class = self.class_layout(class_id)?;
        let mut fields = Vec::with_capacity(class.fields.len());
        for _ in 0..class.fields.len() {
            fields.push(self.parse_value()?);
        }
        self.decoder.end_object();
        Ok(HessianValue::Object { class, fields })
    }

    /// Interns the class name and field layout once per class definition, so
    /// every instance shares them instead of copying field names.
    fn class_layout(&mut self, class_id: ClassId) -> Result<Rc<ClassLayout>> {
        let index = class_id.index();
        if self.classes.len() <= index {
            self.classes.resize(index + 1, None);
        }
        if let Some(layout) = &self.classes[index] {
            return Ok(Rc::clone(layout));
        }
        let field_count = self.decoder.object_field_count(class_id);
        let mut fields = Vec::with_capacity(field_count.min(1024));
        for position in 0..field_count {
            let name = self
                .decoder
                .object_field_name(class_id, position)
                .context("Hessian2 class definition is missing a declared field")?;
            fields.push(Rc::from(name));
        }
        let layout = Rc::new(ClassLayout {
            name: Rc::from(self.decoder.class_name(class_id)),
            fields,
        });
        self.classes[index] = Some(Rc::clone(&layout));
        Ok(layout)
    }

    /// Interns the declared type of a typed collection once per type reference.
    fn type_name(&mut self, type_id: Option<TypeId>) -> Option<Rc<str>> {
        let type_id = type_id?;
        let index = type_id.index();
        if self.types.len() <= index {
            self.types.resize(index + 1, None);
        }
        let name =
            self.types[index].get_or_insert_with(|| Rc::from(self.decoder.type_name(type_id)));
        Some(Rc::clone(name))
    }
}

fn canonicalize_path(
    value: &mut HessianValue<'_>,
    path: &[String],
    full_path: &Hessian2ValuePath,
) -> Result<bool> {
    let Some((segment, remaining)) = path.split_first() else {
        let HessianValue::List { values, .. } = value else {
            bail!(
                "Hessian2 unordered path {:?} does not select a list",
                full_path.0
            );
        };
        values.sort();
        return Ok(true);
    };
    match value {
        HessianValue::Object { class, fields } => {
            let mut found = false;
            for (name, value) in class.fields.iter().zip(fields.iter_mut()) {
                if name.as_ref() == segment {
                    found |= canonicalize_path(value, remaining, full_path)?;
                }
            }
            Ok(found)
        }
        HessianValue::Map { entries, .. } => {
            let mut found = false;
            for (key, value) in entries {
                if matches!(key, HessianValue::String(name) if name.as_ref() == segment) {
                    found |= canonicalize_path(value, remaining, full_path)?;
                }
            }
            Ok(found)
        }
        HessianValue::List { values, .. } if segment == "*" => {
            let mut found = false;
            for value in values {
                found |= canonicalize_path(value, remaining, full_path)?;
            }
            Ok(found)
        }
        _ => Ok(false),
    }
}

/// Canonicalizes a joined-string field: split on `separator`, sort the parts
/// (multiset semantics — duplicates preserved), and re-join. Walking the value
/// tree mirrors `canonicalize_path`; the terminal must be a Hessian2 string.
fn canonicalize_joined_string(
    value: &mut HessianValue<'_>,
    path: &[String],
    separator: &str,
) -> Result<bool> {
    let Some((segment, remaining)) = path.split_first() else {
        let HessianValue::String(text) = value else {
            bail!("joined-string path does not select a Hessian2 string");
        };
        let mut parts = text.split(separator).collect::<Vec<_>>();
        parts.sort_unstable();
        let canonical = parts.join(separator);
        *text = Cow::Owned(canonical);
        return Ok(true);
    };
    match value {
        HessianValue::Object { class, fields } => {
            let mut found = false;
            for (name, value) in class.fields.iter().zip(fields.iter_mut()) {
                if name.as_ref() == segment {
                    found |= canonicalize_joined_string(value, remaining, separator)?;
                }
            }
            Ok(found)
        }
        HessianValue::Map { entries, .. } => {
            let mut found = false;
            for (key, value) in entries {
                if matches!(key, HessianValue::String(name) if name.as_ref() == segment) {
                    found |= canonicalize_joined_string(value, remaining, separator)?;
                }
            }
            Ok(found)
        }
        HessianValue::List { values, .. } if segment == "*" => {
            let mut found = false;
            for value in values {
                found |= canonicalize_joined_string(value, remaining, separator)?;
            }
            Ok(found)
        }
        _ => Ok(false),
    }
}

fn discover_paths(
    expected: &HessianValue<'_>,
    actual: &HessianValue<'_>,
    path: &mut Vec<String>,
    discovered: &mut BTreeSet<Hessian2ValuePath>,
    joined_string: &mut BTreeSet<(Hessian2ValuePath, String)>,
) {
    if discovered.len() >= MAX_DISCOVERED_PATHS || expected == actual {
        return;
    }
    match (expected, actual) {
        (
            HessianValue::List {
                type_name: expected_type,
                values: expected_values,
            },
            HessianValue::List {
                type_name: actual_type,
                values: actual_values,
            },
        ) if expected_type == actual_type && expected_values.len() == actual_values.len() => {
            let mut expected_sorted = expected_values.iter().collect::<Vec<_>>();
            let mut actual_sorted = actual_values.iter().collect::<Vec<_>>();
            expected_sorted.sort();
            actual_sorted.sort();
            if expected_values != actual_values && expected_sorted == actual_sorted {
                discovered.insert(Hessian2ValuePath(path.clone()));
                return;
            }
            path.push("*".to_string());
            for (expected, actual) in expected_values.iter().zip(actual_values) {
                discover_paths(expected, actual, path, discovered, joined_string);
            }
            path.pop();
        }
        (
            HessianValue::Object {
                class: expected_class,
                fields: expected_fields,
            },
            HessianValue::Object {
                class: actual_class,
                fields: actual_fields,
            },
        ) if expected_class == actual_class => {
            for (name, (expected, actual)) in expected_class
                .fields
                .iter()
                .zip(expected_fields.iter().zip(actual_fields))
            {
                path.push(name.to_string());
                discover_paths(expected, actual, path, discovered, joined_string);
                path.pop();
            }
        }
        (
            HessianValue::Map {
                type_name: expected_type,
                entries: expected_entries,
            },
            HessianValue::Map {
                type_name: actual_type,
                entries: actual_entries,
            },
        ) if expected_type == actual_type && expected_entries.len() == actual_entries.len() => {
            for ((expected_key, expected), (actual_key, actual)) in
                expected_entries.iter().zip(actual_entries)
            {
                if expected_key != actual_key {
                    return;
                }
                let HessianValue::String(key) = expected_key else {
                    continue;
                };
                path.push(key.to_string());
                discover_paths(expected, actual, path, discovered, joined_string);
                path.pop();
            }
        }
        (HessianValue::String(expected), HessianValue::String(actual)) => {
            for separator in JOINED_STRING_SEPARATORS {
                let mut expected_parts = expected.split(separator).collect::<Vec<_>>();
                let mut actual_parts = actual.split(separator).collect::<Vec<_>>();
                // A separator that does not appear in either string yields a
                // single-element split on both sides, which trivially compares
                // equal — ignore those to avoid spurious candidates.
                if expected_parts.len() < 2 && actual_parts.len() < 2 {
                    continue;
                }
                expected_parts.sort_unstable();
                actual_parts.sort_unstable();
                if expected_parts == actual_parts {
                    joined_string.insert((Hessian2ValuePath(path.clone()), separator.to_string()));
                }
            }
        }
        _ => {}
    }
}

fn collect_residual_differences(
    expected: &HessianValue<'_>,
    actual: &HessianValue<'_>,
    path: &mut Vec<String>,
    differences: &mut Vec<Hessian2BodyDifference>,
) {
    if expected == actual || differences.len() >= MAX_DIFFERENCES {
        return;
    }
    match (expected, actual) {
        (
            HessianValue::List {
                type_name: expected_type,
                values: expected_values,
            },
            HessianValue::List {
                type_name: actual_type,
                values: actual_values,
            },
        ) if expected_type == actual_type => {
            if expected_values.len() != actual_values.len() {
                push_difference(
                    path,
                    Hessian2BodyDifferenceKind::ListLengthMismatch,
                    differences,
                );
                return;
            }
            let before = differences.len();
            path.push("*".to_string());
            for (expected, actual) in expected_values.iter().zip(actual_values) {
                collect_residual_differences(expected, actual, path, differences);
            }
            path.pop();
            if differences.len() == before {
                push_difference(path, Hessian2BodyDifferenceKind::ValueMismatch, differences);
            }
        }
        (
            HessianValue::Object {
                class: expected_class,
                fields: expected_fields,
            },
            HessianValue::Object {
                class: actual_class,
                fields: actual_fields,
            },
        ) if expected_class == actual_class => {
            for (name, (expected, actual)) in expected_class
                .fields
                .iter()
                .zip(expected_fields.iter().zip(actual_fields))
            {
                path.push(name.to_string());
                collect_residual_differences(expected, actual, path, differences);
                path.pop();
            }
        }
        (
            HessianValue::Object {
                class: expected_class,
                ..
            },
            HessianValue::Object {
                class: actual_class,
                ..
            },
        ) if expected_class != actual_class => {
            push_difference(path, Hessian2BodyDifferenceKind::TypeMismatch, differences);
        }
        (
            HessianValue::Map {
                type_name: expected_type,
                entries: expected_entries,
            },
            HessianValue::Map {
                type_name: actual_type,
                entries: actual_entries,
            },
        ) if expected_type == actual_type && expected_entries.len() == actual_entries.len() => {
            for ((expected_key, expected), (actual_key, actual)) in
                expected_entries.iter().zip(actual_entries)
            {
                if expected_key != actual_key {
                    push_difference(path, Hessian2BodyDifferenceKind::ValueMismatch, differences);
                    return;
                }
                let HessianValue::String(key) = expected_key else {
                    if expected != actual {
                        push_difference(
                            path,
                            Hessian2BodyDifferenceKind::ValueMismatch,
                            differences,
                        );
                    }
                    continue;
                };
                path.push(key.to_string());
                collect_residual_differences(expected, actual, path, differences);
                path.pop();
            }
        }
        (left, right) if std::mem::discriminant(left) != std::mem::discriminant(right) => {
            push_difference(path, Hessian2BodyDifferenceKind::TypeMismatch, differences);
        }
        _ => push_difference(path, Hessian2BodyDifferenceKind::ValueMismatch, differences),
    }
}

fn push_difference(
    path: &[String],
    kind: Hessian2BodyDifferenceKind,
    differences: &mut Vec<Hessian2BodyDifference>,
) {
    if differences.len() >= MAX_DIFFERENCES {
        return;
    }
    let value_path = Hessian2ValuePath(path.to_vec());
    differences.push(Hessian2BodyDifference {
        display_path: value_path.display_path(),
        value_path,
        kind,
    });
}

#[cfg(test)]
mod tests;
