use std::borrow::Cow;
use std::collections::BTreeSet;

use anyhow::{Context, Result, bail, ensure};
use motan_hessian2::{Decoder, Limits};

use super::binary_body::extract_simple_payload;
use super::model::{Hessian2BodyDifference, Hessian2BodyDifferenceKind};
use crate::config::DEFAULT_BODY_LIMIT_BYTES;
use crate::replay::policy::{Hessian2UnorderedPath, Hessian2ValuePath};

const MAX_NODES: usize = 1_000_000;
const MAX_DISCOVERED_PATHS: usize = 32;
const MAX_DIFFERENCES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Hessian2OrderDiscovery {
    pub(super) unordered_paths: Vec<Hessian2ValuePath>,
    pub(super) differences: Vec<Hessian2BodyDifference>,
    pub(super) order_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum IntegerKind {
    Int,
    Long,
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
        type_name: Option<Cow<'a, str>>,
        values: Vec<HessianValue<'a>>,
    },
    Map {
        type_name: Option<Cow<'a, str>>,
        entries: Vec<(HessianValue<'a>, HessianValue<'a>)>,
    },
    Object {
        class_name: Cow<'a, str>,
        fields: Vec<(Cow<'a, str>, HessianValue<'a>)>,
    },
    Reference(usize),
}

#[derive(Debug, Clone)]
struct ClassDefinition<'a> {
    name: Cow<'a, str>,
    fields: Vec<Cow<'a, str>>,
}

struct Parser<'a> {
    input: &'a [u8],
    decoder: Decoder<'a>,
    limits: Limits,
    class_definitions: Vec<ClassDefinition<'a>>,
    type_references: Vec<Cow<'a, str>>,
    nodes: usize,
}

pub(crate) fn is_motan_hessian2_body(body: &[u8]) -> bool {
    extract_simple_payload(body)
        .and_then(validate_complete_value)
        .is_ok()
}

pub(in crate::replay) fn compare_motan_hessian2(
    expected: &[u8],
    actual: &[u8],
    unordered_paths: &[Hessian2UnorderedPath],
) -> Result<bool> {
    let mut expected = parse_body(expected)?;
    let mut actual = parse_body(actual)?;
    for path in unordered_paths {
        canonicalize_path(&mut expected, &path.value_path.0, &path.value_path)?;
        canonicalize_path(&mut actual, &path.value_path.0, &path.value_path)?;
    }
    Ok(expected == actual)
}

pub(super) fn evaluate_motan_hessian2(
    expected: &[u8],
    actual: &[u8],
    unordered_paths: &[Hessian2UnorderedPath],
) -> Result<(bool, Hessian2OrderDiscovery)> {
    let mut discovery = discover_motan_hessian2_order(expected, actual)?;
    let matches = compare_motan_hessian2(expected, actual, unordered_paths)?;
    for rule in unordered_paths {
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
    let mut expected = parse_body(expected)?;
    let mut actual = parse_body(actual)?;
    let mut selected = BTreeSet::new();

    while expected != actual && selected.len() < MAX_DISCOVERED_PATHS {
        let mut discovered = BTreeSet::new();
        discover_paths(&expected, &actual, &mut Vec::new(), &mut discovered);
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
        unordered_paths: selected.into_iter().collect(),
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

fn parse_body(body: &[u8]) -> Result<HessianValue<'_>> {
    let payload = extract_simple_payload(body)?;
    Parser::new(payload)?.parse_complete()
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
        let limits = hessian_limits();
        let decoder = Decoder::new(input, limits)
            .context("failed to initialize Hessian2 semantic decoder")?;
        Ok(Self {
            input,
            decoder,
            limits,
            class_definitions: Vec::new(),
            type_references: Vec::new(),
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
        let position = self.decoder.position();
        let tag = *self
            .input
            .get(position)
            .context("Hessian2 body ended before the next value")?;
        match tag {
            b'N' => {
                ensure!(self.decoder.try_read_null()?, "expected Hessian2 null");
                Ok(HessianValue::Null)
            }
            b'T' | b'F' => Ok(HessianValue::Boolean(self.decoder.read_bool()?)),
            _ if is_int_tag(tag) => Ok(HessianValue::Integer(
                IntegerKind::Int,
                self.decoder.read_i64()?,
            )),
            _ if is_long_tag(tag) => Ok(HessianValue::Integer(
                IntegerKind::Long,
                self.decoder.read_i64()?,
            )),
            b'D' | 0x5b..=0x5f => Ok(HessianValue::Double(self.decoder.read_f64()?.to_bits())),
            b'J' | b'K' => Ok(HessianValue::Date(self.decoder.read_date_millis()?)),
            _ if is_string_tag(tag) => Ok(HessianValue::String(self.decoder.read_str()?)),
            _ if is_binary_tag(tag) => Ok(HessianValue::Binary(self.decoder.read_binary()?)),
            0x70..=0x7f | b'X' | b'l' | b'U' | b'V' => self.parse_list(position, tag),
            b'H' | b'M' => self.parse_map(position, tag),
            b'C' | b'O' | 0x60..=0x6f => self.parse_object(position),
            b'Q' => self.parse_reference(position),
            _ => bail!("invalid Hessian2 tag 0x{tag:02x} at byte {position}"),
        }
    }

    fn parse_list(&mut self, position: usize, tag: u8) -> Result<HessianValue<'a>> {
        let type_name = self.inspect_type_name(position, tag)?;
        let header = self.decoder.begin_list()?;
        let mut values = Vec::with_capacity(header.length().unwrap_or(0).min(1024));
        while self.decoder.list_has_next(header, values.len())? {
            values.push(self.parse_value()?);
        }
        self.decoder.end_list(header, values.len())?;
        Ok(HessianValue::List { type_name, values })
    }

    fn parse_map(&mut self, position: usize, tag: u8) -> Result<HessianValue<'a>> {
        let type_name = self.inspect_type_name(position, tag)?;
        self.decoder.begin_map()?;
        let mut entries = Vec::new();
        while self.decoder.map_has_next(entries.len())? {
            entries.push((self.parse_value()?, self.parse_value()?));
        }
        self.decoder.end_map()?;
        entries.sort();
        Ok(HessianValue::Map { type_name, entries })
    }

    fn parse_object(&mut self, position: usize) -> Result<HessianValue<'a>> {
        let class_index = self.inspect_class_definitions(position)?;
        let class = self
            .class_definitions
            .get(class_index)
            .cloned()
            .with_context(|| format!("unknown Hessian2 class reference {class_index}"))?;
        let class_id = self.decoder.begin_object()?;
        ensure!(
            self.decoder.object_field_count(class_id) == class.fields.len(),
            "Hessian2 class field count changed during decoding"
        );
        let mut fields = Vec::with_capacity(class.fields.len());
        for (index, field_name) in class.fields.into_iter().enumerate() {
            ensure!(
                self.decoder.object_field_name(class_id, index) == Some(field_name.as_ref()),
                "Hessian2 class field layout changed during decoding"
            );
            fields.push((field_name, self.parse_value()?));
        }
        self.decoder.end_object();
        Ok(HessianValue::Object {
            class_name: class.name,
            fields,
        })
    }

    fn parse_reference(&mut self, position: usize) -> Result<HessianValue<'a>> {
        let index = self.inspect_nonnegative_integer(position + 1)?;
        self.decoder.skip_value()?;
        Ok(HessianValue::Reference(index))
    }

    fn inspect_type_name(&mut self, position: usize, tag: u8) -> Result<Option<Cow<'a, str>>> {
        if !matches!(tag, 0x70..=0x77 | b'l' | b'V' | b'M') {
            return Ok(None);
        }
        let value_position = position
            .checked_add(1)
            .context("Hessian2 type-name position overflow")?;
        let type_input = self
            .input
            .get(value_position..)
            .context("Hessian2 typed value has no type name")?;
        let mut probe = Decoder::new(type_input, self.limits)?;
        let next = *type_input
            .first()
            .context("Hessian2 typed value has no type name")?;
        if is_string_tag(next) {
            let type_name = probe.read_str()?;
            self.type_references.push(type_name.clone());
            return Ok(Some(type_name));
        }
        let index = usize::try_from(probe.read_i32()?)
            .map_err(|_| anyhow::anyhow!("negative Hessian2 type reference"))?;
        self.type_references
            .get(index)
            .cloned()
            .map(Some)
            .with_context(|| format!("unknown Hessian2 type reference {index}"))
    }

    fn inspect_class_definitions(&mut self, position: usize) -> Result<usize> {
        let mut cursor = position;
        while self.input.get(cursor) == Some(&b'C') {
            let definition_position = cursor
                .checked_add(1)
                .context("Hessian2 class-definition position overflow")?;
            let definition_input = self
                .input
                .get(definition_position..)
                .context("Hessian2 class definition is incomplete")?;
            let mut probe = Decoder::new(definition_input, self.limits)?;
            let name = probe.read_str()?;
            let field_count = usize::try_from(probe.read_i32()?)
                .map_err(|_| anyhow::anyhow!("negative Hessian2 class field count"))?;
            ensure!(
                field_count <= self.limits.max_fields_per_class,
                "Hessian2 class has too many fields"
            );
            let mut fields = Vec::with_capacity(field_count.min(1024));
            for _ in 0..field_count {
                fields.push(probe.read_str()?);
            }
            cursor = definition_position
                .checked_add(probe.position())
                .context("Hessian2 class-definition length overflow")?;
            self.class_definitions
                .push(ClassDefinition { name, fields });
            ensure!(
                self.class_definitions.len() <= self.limits.max_class_defs,
                "Hessian2 body has too many class definitions"
            );
        }
        let tag = *self
            .input
            .get(cursor)
            .context("Hessian2 class definition has no object value")?;
        match tag {
            0x60..=0x6f => Ok(usize::from(tag - 0x60)),
            b'O' => self.inspect_nonnegative_integer(cursor + 1),
            _ => bail!("Hessian2 class definition is not followed by an object"),
        }
    }

    fn inspect_nonnegative_integer(&self, position: usize) -> Result<usize> {
        let mut probe = Decoder::new(&self.input[position..], self.limits)?;
        usize::try_from(probe.read_i32()?).map_err(|_| anyhow::anyhow!("negative Hessian2 index"))
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
        HessianValue::Object { fields, .. } => {
            let mut found = false;
            for (name, value) in fields {
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

fn discover_paths(
    expected: &HessianValue<'_>,
    actual: &HessianValue<'_>,
    path: &mut Vec<String>,
    discovered: &mut BTreeSet<Hessian2ValuePath>,
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
                discover_paths(expected, actual, path, discovered);
            }
            path.pop();
        }
        (
            HessianValue::Object {
                class_name: expected_class,
                fields: expected_fields,
            },
            HessianValue::Object {
                class_name: actual_class,
                fields: actual_fields,
            },
        ) if expected_class == actual_class && expected_fields.len() == actual_fields.len() => {
            for ((expected_name, expected), (actual_name, actual)) in
                expected_fields.iter().zip(actual_fields)
            {
                if expected_name != actual_name {
                    return;
                }
                path.push(expected_name.to_string());
                discover_paths(expected, actual, path, discovered);
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
                discover_paths(expected, actual, path, discovered);
                path.pop();
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
                class_name: expected_class,
                fields: expected_fields,
            },
            HessianValue::Object {
                class_name: actual_class,
                fields: actual_fields,
            },
        ) if expected_class == actual_class && expected_fields.len() == actual_fields.len() => {
            for ((expected_name, expected), (actual_name, actual)) in
                expected_fields.iter().zip(actual_fields)
            {
                if expected_name != actual_name {
                    push_difference(path, Hessian2BodyDifferenceKind::TypeMismatch, differences);
                    return;
                }
                path.push(expected_name.to_string());
                collect_residual_differences(expected, actual, path, differences);
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

fn is_int_tag(tag: u8) -> bool {
    matches!(tag, 0x80..=0xd7 | b'I')
}

fn is_long_tag(tag: u8) -> bool {
    matches!(tag, 0xd8..=0xff | 0x38..=0x3f | b'L' | b'Y')
}

fn is_string_tag(tag: u8) -> bool {
    matches!(tag, 0x00..=0x1f | 0x30..=0x33 | b'R' | b'S')
}

fn is_binary_tag(tag: u8) -> bool {
    matches!(tag, 0x20..=0x2f | 0x34..=0x37 | b'A' | b'B')
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use motan_hessian2::{ClassSchema, Encoder, Limits, to_vec};

    use super::*;

    fn body(payload: Vec<u8>) -> Vec<u8> {
        let mut body = vec![3];
        body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        body.extend(payload);
        body
    }

    #[test]
    fn recognizes_one_complete_hessian_value_and_rejects_trailing_bytes() {
        let encoded = to_vec(&vec!["alpha", "beta"], Limits::default()).unwrap();
        assert!(is_motan_hessian2_body(&body(encoded.clone())));
        let mut trailing = encoded;
        trailing.push(b'N');
        assert!(!is_motan_hessian2_body(&body(trailing)));
    }

    #[test]
    fn discovers_and_applies_root_list_order() {
        let expected = body(to_vec(&vec!["alpha", "beta"], Limits::default()).unwrap());
        let actual = body(to_vec(&vec!["beta", "alpha"], Limits::default()).unwrap());

        let discovery = discover_motan_hessian2_order(&expected, &actual).unwrap();

        assert_eq!(discovery.unordered_paths, vec![Hessian2ValuePath(vec![])]);
        assert!(discovery.order_only);
        let rule = Hessian2UnorderedPath {
            value_path: Hessian2ValuePath(vec![]),
            display_path: "response.members".to_string(),
        };
        assert!(compare_motan_hessian2(&expected, &actual, &[rule]).unwrap());
    }

    #[test]
    fn unordered_list_preserves_duplicate_multiplicity() {
        let expected = body(to_vec(&vec![1_i32, 1, 2], Limits::default()).unwrap());
        let actual = body(to_vec(&vec![2_i32, 1, 2], Limits::default()).unwrap());
        let rule = Hessian2UnorderedPath {
            value_path: Hessian2ValuePath(vec![]),
            display_path: "response.members".to_string(),
        };

        assert!(!compare_motan_hessian2(&expected, &actual, &[rule]).unwrap());
    }

    #[test]
    fn missing_path_is_a_no_op_but_a_non_list_terminal_is_rejected() {
        let expected = body(to_vec(&vec!["alpha", "beta"], Limits::default()).unwrap());
        let missing = Hessian2UnorderedPath {
            value_path: Hessian2ValuePath(vec!["missing".to_string()]),
            display_path: "response.missing".to_string(),
        };
        assert!(
            compare_motan_hessian2(&expected, &expected, std::slice::from_ref(&missing)).unwrap()
        );

        let scalar = Hessian2UnorderedPath {
            value_path: Hessian2ValuePath(vec![]),
            display_path: "response.value".to_string(),
        };
        let scalar_body = body(to_vec(&42_i32, Limits::default()).unwrap());
        assert!(compare_motan_hessian2(&scalar_body, &scalar_body, &[scalar]).is_err());
    }

    #[test]
    fn discovers_and_applies_nested_lists_through_map_keys_and_wildcards() {
        let collection = |groups: &[&[&str]]| {
            BTreeMap::from([(
                "groups".to_string(),
                groups
                    .iter()
                    .map(|names| {
                        BTreeMap::from([(
                            "names".to_string(),
                            names.iter().map(ToString::to_string).collect::<Vec<_>>(),
                        )])
                    })
                    .collect::<Vec<_>>(),
            )])
        };
        let expected = body(
            to_vec(
                &collection(&[&["alice", "bob"], &["carol", "dave"]]),
                Limits::default(),
            )
            .unwrap(),
        );
        let actual = body(
            to_vec(
                &collection(&[&["bob", "alice"], &["dave", "carol"]]),
                Limits::default(),
            )
            .unwrap(),
        );

        let discovery = discover_motan_hessian2_order(&expected, &actual).unwrap();

        let value_path = Hessian2ValuePath(vec![
            "groups".to_string(),
            "*".to_string(),
            "names".to_string(),
        ]);
        assert_eq!(discovery.unordered_paths, vec![value_path.clone()]);
        assert!(discovery.order_only);
        assert!(
            compare_motan_hessian2(
                &expected,
                &actual,
                &[Hessian2UnorderedPath {
                    value_path,
                    display_path: "rule_collection.groups[].names".to_string(),
                }],
            )
            .unwrap()
        );
    }

    #[test]
    fn applies_a_list_path_through_an_object_field() {
        fn response(names: &[&str]) -> Vec<u8> {
            let mut payload = Vec::new();
            let mut encoder = Encoder::new(&mut payload, Limits::default());
            encoder
                .begin_object(ClassSchema::new("example.Response", &["names"]))
                .unwrap();
            encoder.encode_value(&names.to_vec()).unwrap();
            encoder.end_object();
            body(payload)
        }

        let expected = response(&["alice", "bob"]);
        let actual = response(&["bob", "alice"]);
        let rule = Hessian2UnorderedPath {
            value_path: Hessian2ValuePath(vec!["names".to_string()]),
            display_path: "response.names".to_string(),
        };

        assert!(compare_motan_hessian2(&expected, &actual, &[rule]).unwrap());
    }
}
