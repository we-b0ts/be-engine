use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail, ensure};

use super::binary_body::BodyEnvelope;
use super::joined_string;
use super::model::{ProtobufBodyDifference, ProtobufBodyDifferenceKind};
use crate::replay::policy::{
    ProtobufFieldPath, ProtobufJoinedStringPath, ProtobufRepeatedElementType, ProtobufUnorderedPath,
};

const MAX_DISCOVERED_PATHS: usize = 32;
const MAX_NESTING_DEPTH: usize = 32;
const MAX_FIELDS: usize = 1_000_000;

mod envelope;
mod selection;

use envelope::{parse_bodies, resolve_body};
pub(in crate::replay) use selection::selected_paths_match;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProtobufOrderDiscovery {
    pub(super) envelope: BodyEnvelope,
    pub(super) unordered_paths: Vec<ProtobufFieldPath>,
    pub(super) unordered_joined_string_paths: Vec<(ProtobufFieldPath, String)>,
    pub(super) differences: Vec<ProtobufBodyDifference>,
    pub(super) candidates_explain_all_differences: bool,
    pub(super) order_only: bool,
}

#[derive(Debug)]
struct Field<'a> {
    number: u32,
    wire_type: u8,
    raw: &'a [u8],
    payload: Option<&'a [u8]>,
    value_offset: usize,
    payload_offset: usize,
}

pub(crate) fn is_protobuf_body(body: &[u8]) -> bool {
    resolve_body(body).is_ok()
}

pub(in crate::replay) fn compare_protobuf(
    expected: &[u8],
    actual: &[u8],
    unordered_paths: &[ProtobufUnorderedPath],
    joined_string_paths: &[ProtobufJoinedStringPath],
) -> Result<bool> {
    let (_, expected, actual) = parse_bodies(expected, actual)?;
    let expected = canonicalize_rules(expected, unordered_paths, joined_string_paths)?;
    let actual = canonicalize_rules(actual, unordered_paths, joined_string_paths)?;
    Ok(expected == actual)
}

pub(super) fn evaluate_protobuf(
    expected: &[u8],
    actual: &[u8],
    unordered_paths: &[ProtobufUnorderedPath],
    joined_string_paths: &[ProtobufJoinedStringPath],
) -> Result<(bool, ProtobufOrderDiscovery)> {
    let mut discovery = discover_protobuf_order(expected, actual)?;
    let matches = compare_protobuf(expected, actual, unordered_paths, joined_string_paths)?;
    for rule in unordered_paths {
        for difference in discovery
            .differences
            .iter_mut()
            .filter(|difference| difference.field_path == rule.field_path)
        {
            difference.display_path.clone_from(&rule.display_path);
        }
    }
    for rule in joined_string_paths {
        for difference in discovery
            .differences
            .iter_mut()
            .filter(|difference| difference.field_path == rule.field_path)
        {
            difference.display_path.clone_from(&rule.display_path);
        }
    }
    if matches {
        for (index, rule) in unordered_paths.iter().enumerate() {
            let without_rule = unordered_paths
                .iter()
                .enumerate()
                .filter(|(candidate, _)| *candidate != index)
                .map(|(_, rule)| rule.clone())
                .collect::<Vec<_>>();
            if compare_protobuf(expected, actual, &without_rule, joined_string_paths)? {
                continue;
            }
            discovery.differences.retain(|difference| {
                difference.kind == ProtobufBodyDifferenceKind::RepeatedFieldOrderMismatch
                    || !difference.field_path.0.starts_with(&rule.field_path.0)
            });
            discovery.unordered_paths.push(rule.field_path.clone());
            discovery.differences.push(ProtobufBodyDifference {
                field_path: rule.field_path.clone(),
                display_path: rule.display_path.clone(),
                kind: ProtobufBodyDifferenceKind::RepeatedFieldOrderMismatch,
            });
        }
        for (index, rule) in joined_string_paths.iter().enumerate() {
            let without_rule = joined_string_paths
                .iter()
                .enumerate()
                .filter(|(candidate, _)| *candidate != index)
                .map(|(_, rule)| rule.clone())
                .collect::<Vec<_>>();
            if compare_protobuf(expected, actual, unordered_paths, &without_rule)? {
                continue;
            }
            discovery
                .differences
                .retain(|difference| !difference.field_path.0.starts_with(&rule.field_path.0));
            discovery
                .unordered_joined_string_paths
                .push((rule.field_path.clone(), rule.separator.clone()));
            discovery.differences.push(ProtobufBodyDifference {
                field_path: rule.field_path.clone(),
                display_path: rule.display_path.clone(),
                kind: ProtobufBodyDifferenceKind::JoinedStringOrderMismatch,
            });
        }
        discovery.candidates_explain_all_differences = true;
        discovery.order_only = true;
    }
    discovery.unordered_paths.sort();
    discovery.unordered_paths.dedup();
    discovery.unordered_joined_string_paths.sort();
    discovery.unordered_joined_string_paths.dedup();
    discovery.differences.sort_by(|left, right| {
        left.field_path
            .cmp(&right.field_path)
            .then_with(|| left.kind.cmp(&right.kind))
    });
    discovery
        .differences
        .dedup_by(|left, right| left.field_path == right.field_path && left.kind == right.kind);
    Ok((matches, discovery))
}

pub(super) fn discover_protobuf_order(
    expected: &[u8],
    actual: &[u8],
) -> Result<ProtobufOrderDiscovery> {
    let (envelope, expected, actual) = parse_bodies(expected, actual)?;
    let mut expected = expected.to_vec();
    let mut actual = actual.to_vec();
    let mut selected = BTreeSet::new();

    while expected != actual && selected.len() < MAX_DISCOVERED_PATHS {
        let mut discovered = BTreeSet::new();
        discover_paths(&expected, &actual, &[], 0, &mut discovered);
        discovered.retain(|path| !selected.contains(path));
        if discovered.is_empty() {
            break;
        }
        let remaining = MAX_DISCOVERED_PATHS - selected.len();
        selected.extend(discovered.into_iter().take(remaining));
        let paths = selected.iter().cloned().collect::<Vec<_>>();
        let next_expected = canonicalize_paths(&expected, &paths)?;
        let next_actual = canonicalize_paths(&actual, &paths)?;
        if next_expected == expected && next_actual == actual {
            break;
        }
        expected = next_expected;
        actual = next_actual;
    }

    let order_only = expected == actual;
    let mut joined_string_paths = BTreeSet::new();
    discover_joined_string_paths(&expected, &actual, &[], 0, &mut joined_string_paths);
    joined_string_paths.retain(|(path, separator)| {
        canonicalize_joined_string_path(&expected, &path.0, separator, 0).is_ok()
            && canonicalize_joined_string_path(&actual, &path.0, separator, 0).is_ok()
    });
    let candidate_expected = canonicalize_joined_paths(&expected, &joined_string_paths)?;
    let candidate_actual = canonicalize_joined_paths(&actual, &joined_string_paths)?;
    let candidates_explain_all_differences = candidate_expected == candidate_actual;
    let mut differences = selected
        .iter()
        .cloned()
        .map(|field_path| ProtobufBodyDifference {
            display_path: field_path.display_path(),
            field_path,
            kind: ProtobufBodyDifferenceKind::RepeatedFieldOrderMismatch,
        })
        .collect::<Vec<_>>();
    if !order_only {
        collect_residual_differences(&expected, &actual, &[], 0, &mut differences);
    }
    for (field_path, _) in &joined_string_paths {
        differences.retain(|difference| !difference.field_path.0.starts_with(&field_path.0));
        differences.push(ProtobufBodyDifference {
            display_path: field_path.display_path(),
            field_path: field_path.clone(),
            kind: ProtobufBodyDifferenceKind::JoinedStringOrderMismatch,
        });
    }
    differences.sort_by(|left, right| {
        left.field_path
            .cmp(&right.field_path)
            .then_with(|| left.kind.cmp(&right.kind))
    });
    differences
        .dedup_by(|left, right| left.field_path == right.field_path && left.kind == right.kind);
    Ok(ProtobufOrderDiscovery {
        envelope,
        unordered_paths: selected.into_iter().collect(),
        unordered_joined_string_paths: joined_string_paths.into_iter().collect(),
        differences,
        candidates_explain_all_differences,
        order_only,
    })
}

fn collect_residual_differences(
    expected: &[u8],
    actual: &[u8],
    prefix: &[u32],
    depth: usize,
    differences: &mut Vec<ProtobufBodyDifference>,
) {
    if expected == actual || depth >= MAX_NESTING_DEPTH {
        return;
    }
    let (Ok(expected_fields), Ok(actual_fields)) = (parse_fields(expected), parse_fields(actual))
    else {
        push_difference(
            prefix,
            ProtobufBodyDifferenceKind::ValueMismatch,
            differences,
        );
        return;
    };
    let numbers = expected_fields
        .iter()
        .map(|field| field.number)
        .chain(actual_fields.iter().map(|field| field.number))
        .collect::<BTreeSet<_>>();
    for number in numbers {
        let expected_group = expected_fields
            .iter()
            .filter(|field| field.number == number)
            .collect::<Vec<_>>();
        let actual_group = actual_fields
            .iter()
            .filter(|field| field.number == number)
            .collect::<Vec<_>>();
        let mut path = prefix.to_vec();
        path.push(number);
        if expected_group.len() != actual_group.len() {
            push_difference(
                &path,
                ProtobufBodyDifferenceKind::OccurrenceCountMismatch,
                differences,
            );
            continue;
        }
        if expected_group
            .iter()
            .map(|field| field.wire_type)
            .ne(actual_group.iter().map(|field| field.wire_type))
        {
            push_difference(
                &path,
                ProtobufBodyDifferenceKind::WireTypeMismatch,
                differences,
            );
            continue;
        }
        let expected_payloads = expected_group
            .iter()
            .filter_map(|field| field.payload)
            .collect::<Vec<_>>();
        let actual_payloads = actual_group
            .iter()
            .filter_map(|field| field.payload)
            .collect::<Vec<_>>();
        if expected_payloads.len() == expected_group.len() {
            let pairs =
                pair_nested_payloads(&expected_payloads, &actual_payloads).unwrap_or_else(|| {
                    (0..expected_payloads.len())
                        .map(|index| (index, index))
                        .collect()
                });
            let before = differences.len();
            for (expected_index, actual_index) in pairs {
                collect_residual_differences(
                    expected_payloads[expected_index],
                    actual_payloads[actual_index],
                    &path,
                    depth + 1,
                    differences,
                );
            }
            if differences.len() == before
                && expected_group
                    .iter()
                    .zip(&actual_group)
                    .any(|(expected, actual)| expected.raw != actual.raw)
            {
                push_difference(
                    &path,
                    ProtobufBodyDifferenceKind::ValueMismatch,
                    differences,
                );
            }
        } else if expected_group
            .iter()
            .zip(&actual_group)
            .any(|(expected, actual)| expected.raw != actual.raw)
        {
            push_difference(
                &path,
                ProtobufBodyDifferenceKind::ValueMismatch,
                differences,
            );
        }
    }
}

fn push_difference(
    path: &[u32],
    kind: ProtobufBodyDifferenceKind,
    differences: &mut Vec<ProtobufBodyDifference>,
) {
    if path.is_empty() {
        return;
    }
    let field_path = ProtobufFieldPath(path.to_vec());
    differences.push(ProtobufBodyDifference {
        display_path: field_path.display_path(),
        field_path,
        kind,
    });
}

fn canonicalize_paths(payload: &[u8], paths: &[ProtobufFieldPath]) -> Result<Vec<u8>> {
    let mut canonical = payload.to_vec();
    let mut ordered = paths.to_vec();
    ordered.sort_by(|left, right| {
        right
            .0
            .len()
            .cmp(&left.0.len())
            .then_with(|| left.cmp(right))
    });
    for path in ordered {
        let (next, found) = canonicalize_path(&canonical, &path.0, None, 0)?;
        ensure!(
            found,
            "protobuf unordered path {:?} is missing from the response body",
            path.0
        );
        canonical = next;
    }
    Ok(canonical)
}

fn canonicalize_rules(
    payload: &[u8],
    rules: &[ProtobufUnorderedPath],
    joined_string_rules: &[ProtobufJoinedStringPath],
) -> Result<Vec<u8>> {
    let mut canonical = payload.to_vec();
    let mut ordered = rules.to_vec();
    ordered.sort_by(|left, right| {
        right
            .field_path
            .0
            .len()
            .cmp(&left.field_path.0.len())
            .then_with(|| left.field_path.cmp(&right.field_path))
    });
    for rule in ordered {
        let (next, _) =
            canonicalize_path(&canonical, &rule.field_path.0, Some(rule.element_type), 0)?;
        canonical = next;
    }
    for rule in joined_string_rules {
        let (next, _) =
            canonicalize_joined_string_path(&canonical, &rule.field_path.0, &rule.separator, 0)?;
        canonical = next;
    }
    Ok(canonical)
}

fn canonicalize_joined_paths(
    payload: &[u8],
    paths: &BTreeSet<(ProtobufFieldPath, String)>,
) -> Result<Vec<u8>> {
    let mut canonical = payload.to_vec();
    for (path, separator) in paths {
        let (next, _) = canonicalize_joined_string_path(&canonical, &path.0, separator, 0)?;
        canonical = next;
    }
    Ok(canonical)
}

fn canonicalize_joined_string_path(
    payload: &[u8],
    path: &[u32],
    separator: &str,
    depth: usize,
) -> Result<(Vec<u8>, bool)> {
    ensure!(depth < MAX_NESTING_DEPTH, "protobuf nesting is too deep");
    let fields = parse_fields(payload)?;
    let number = *path
        .first()
        .expect("validated protobuf joined-string path is non-empty");
    let mut replacements = fields
        .iter()
        .map(|field| field.raw.to_vec())
        .collect::<Vec<_>>();
    if path.len() == 1 {
        let indexes = fields
            .iter()
            .enumerate()
            .filter(|(_, field)| field.number == number)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if indexes.is_empty() {
            return Ok((payload.to_vec(), false));
        }
        ensure!(
            indexes.len() == 1,
            "protobuf joined-string field {number} is repeated"
        );
        let index = indexes[0];
        let field = &fields[index];
        ensure!(
            field.wire_type == 2,
            "protobuf joined-string field {number} is not length-delimited"
        );
        let text = std::str::from_utf8(field.payload.expect("wire type 2 has a payload"))
            .context("protobuf joined-string field is not UTF-8")?;
        let canonical = joined_string::canonicalize(text, separator);
        ensure!(
            canonical.len() == text.len(),
            "protobuf joined-string canonicalization changed field length"
        );
        let mut replacement = field.raw[..field.payload_offset].to_vec();
        replacement.extend_from_slice(canonical.as_bytes());
        replacements[index] = replacement;
        return Ok((replacements.concat(), true));
    }

    let mut found = false;
    for (index, field) in fields.iter().enumerate() {
        if field.number != number {
            continue;
        }
        ensure!(
            field.wire_type == 2,
            "intermediate protobuf joined-string field {number} is not length-delimited"
        );
        let original_nested = field.payload.expect("wire type 2 has a payload");
        let (nested, nested_found) =
            canonicalize_joined_string_path(original_nested, &path[1..], separator, depth + 1)?;
        if nested_found {
            ensure!(
                nested.len() == original_nested.len(),
                "protobuf joined-string canonicalization changed message length"
            );
            let mut replacement = field.raw[..field.payload_offset].to_vec();
            replacement.extend_from_slice(&nested);
            replacements[index] = replacement;
            found = true;
        }
    }
    Ok((replacements.concat(), found))
}

fn canonicalize_path(
    payload: &[u8],
    path: &[u32],
    element_type: Option<ProtobufRepeatedElementType>,
    depth: usize,
) -> Result<(Vec<u8>, bool)> {
    ensure!(depth < MAX_NESTING_DEPTH, "protobuf nesting is too deep");
    let fields = parse_fields(payload)?;
    let number = *path.first().expect("validated protobuf path is non-empty");
    let mut replacements = fields
        .iter()
        .map(|field| field.raw.to_vec())
        .collect::<Vec<_>>();
    if path.len() == 1 {
        let indexes = fields
            .iter()
            .enumerate()
            .filter(|(_, field)| field.number == number)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if indexes.is_empty() {
            return Ok((payload.to_vec(), false));
        }
        canonicalize_terminal(&fields, &indexes, element_type, &mut replacements)?;
        return Ok((replacements.concat(), true));
    }

    let mut found = false;
    for (index, field) in fields.iter().enumerate() {
        if field.number != number {
            continue;
        }
        ensure!(
            field.wire_type == 2,
            "intermediate protobuf unordered field {number} is not length-delimited"
        );
        let nested = field.payload.expect("wire type 2 has a payload");
        let (nested, nested_found) =
            canonicalize_path(nested, &path[1..], element_type, depth + 1)?;
        if nested_found {
            ensure!(
                nested.len() == field.payload.expect("wire type 2 has a payload").len(),
                "protobuf unordered canonicalization changed message length"
            );
            let mut replacement = field.raw[..field.payload_offset].to_vec();
            replacement.extend_from_slice(&nested);
            replacements[index] = replacement;
            found = true;
        }
    }
    Ok((replacements.concat(), found))
}

fn canonicalize_terminal(
    fields: &[Field<'_>],
    indexes: &[usize],
    element_type: Option<ProtobufRepeatedElementType>,
    replacements: &mut [Vec<u8>],
) -> Result<()> {
    let Some(element_type) = element_type else {
        let wire_type = fields[indexes[0]].wire_type;
        ensure!(
            indexes
                .iter()
                .all(|index| fields[*index].wire_type == wire_type),
            "protobuf unordered field uses multiple wire types"
        );
        let mut sorted = indexes
            .iter()
            .map(|index| fields[*index].raw.to_vec())
            .collect::<Vec<_>>();
        sorted.sort();
        for (index, value) in indexes.iter().copied().zip(sorted) {
            replacements[index] = value;
        }
        return Ok(());
    };

    match element_type {
        ProtobufRepeatedElementType::String | ProtobufRepeatedElementType::Message => {
            for index in indexes {
                let field = &fields[*index];
                ensure!(
                    field.wire_type == 2,
                    "protobuf {:?} repeated field is not length-delimited",
                    element_type
                );
                let payload = field.payload.expect("wire type 2 has a payload");
                match element_type {
                    ProtobufRepeatedElementType::String => {
                        std::str::from_utf8(payload).map_err(|_| {
                            anyhow::anyhow!("protobuf repeated string is not UTF-8")
                        })?;
                    }
                    ProtobufRepeatedElementType::Message => {
                        parse_fields(payload)
                            .context("protobuf repeated message element is malformed")?;
                    }
                    _ => unreachable!(),
                }
            }
            let mut sorted = indexes
                .iter()
                .map(|index| fields[*index].raw.to_vec())
                .collect::<Vec<_>>();
            sorted.sort();
            for (index, value) in indexes.iter().copied().zip(sorted) {
                replacements[index] = value;
            }
        }
        numeric => canonicalize_numeric(fields, indexes, numeric, replacements)?,
    }
    Ok(())
}

fn canonicalize_numeric(
    fields: &[Field<'_>],
    indexes: &[usize],
    element_type: ProtobufRepeatedElementType,
    replacements: &mut [Vec<u8>],
) -> Result<()> {
    let scalar_wire = numeric_wire_type(element_type);
    let mut layouts = Vec::new();
    let mut elements = Vec::new();
    for index in indexes {
        let field = &fields[*index];
        if field.wire_type == scalar_wire {
            elements.push(field.raw[field.value_offset..].to_vec());
            layouts.push((*index, false, 1));
            continue;
        }
        ensure!(
            field.wire_type == 2,
            "protobuf {:?} repeated field has incompatible wire type {}",
            element_type,
            field.wire_type
        );
        let packed = split_packed_numeric(
            field.payload.expect("wire type 2 has a payload"),
            scalar_wire,
        )?;
        ensure!(
            !packed.is_empty(),
            "packed protobuf repeated field is empty"
        );
        let count = packed.len();
        elements.extend(packed);
        layouts.push((*index, true, count));
    }
    elements.sort();
    let mut elements = elements.into_iter();
    for (index, packed, count) in layouts {
        let field = &fields[index];
        let selected = elements.by_ref().take(count).collect::<Vec<_>>();
        if packed {
            let payload = selected.concat();
            let mut replacement = field.raw[..field.value_offset].to_vec();
            write_varint(&mut replacement, payload.len() as u64);
            replacement.extend(payload);
            replacements[index] = replacement;
        } else {
            let mut replacement = field.raw[..field.value_offset].to_vec();
            replacement.extend_from_slice(&selected[0]);
            replacements[index] = replacement;
        }
    }
    Ok(())
}

fn numeric_wire_type(element_type: ProtobufRepeatedElementType) -> u8 {
    match element_type {
        ProtobufRepeatedElementType::Int32
        | ProtobufRepeatedElementType::Int64
        | ProtobufRepeatedElementType::Uint32
        | ProtobufRepeatedElementType::Uint64
        | ProtobufRepeatedElementType::Sint32
        | ProtobufRepeatedElementType::Sint64
        | ProtobufRepeatedElementType::Bool
        | ProtobufRepeatedElementType::Enum => 0,
        ProtobufRepeatedElementType::Fixed64
        | ProtobufRepeatedElementType::Sfixed64
        | ProtobufRepeatedElementType::Double => 1,
        ProtobufRepeatedElementType::Fixed32
        | ProtobufRepeatedElementType::Sfixed32
        | ProtobufRepeatedElementType::Float => 5,
        ProtobufRepeatedElementType::String | ProtobufRepeatedElementType::Message => {
            unreachable!("non-numeric protobuf type")
        }
    }
}

fn split_packed_numeric(payload: &[u8], wire_type: u8) -> Result<Vec<Vec<u8>>> {
    let mut elements = Vec::new();
    let mut index = 0;
    while index < payload.len() {
        let start = index;
        match wire_type {
            0 => {
                read_varint(payload, &mut index)?;
            }
            1 => advance(payload, &mut index, 8)?,
            5 => advance(payload, &mut index, 4)?,
            _ => unreachable!("validated numeric protobuf wire type"),
        }
        elements.push(payload[start..index].to_vec());
    }
    Ok(elements)
}

fn write_varint(output: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn discover_paths(
    expected: &[u8],
    actual: &[u8],
    prefix: &[u32],
    depth: usize,
    discovered: &mut BTreeSet<ProtobufFieldPath>,
) {
    if depth >= MAX_NESTING_DEPTH || discovered.len() >= MAX_DISCOVERED_PATHS {
        return;
    }
    let (Ok(expected_fields), Ok(actual_fields)) = (parse_fields(expected), parse_fields(actual))
    else {
        return;
    };
    let numbers = expected_fields
        .iter()
        .map(|field| field.number)
        .chain(actual_fields.iter().map(|field| field.number))
        .collect::<BTreeSet<_>>();

    for number in numbers {
        let expected_group = expected_fields
            .iter()
            .filter(|field| field.number == number)
            .collect::<Vec<_>>();
        let actual_group = actual_fields
            .iter()
            .filter(|field| field.number == number)
            .collect::<Vec<_>>();
        if expected_group.len() > 1
            && expected_group.len() == actual_group.len()
            && expected_group
                .iter()
                .map(|field| field.wire_type)
                .eq(actual_group.iter().map(|field| field.wire_type))
        {
            let expected_raw = expected_group
                .iter()
                .map(|field| field.raw)
                .collect::<Vec<_>>();
            let actual_raw = actual_group
                .iter()
                .map(|field| field.raw)
                .collect::<Vec<_>>();
            let mut sorted_expected = expected_raw.clone();
            let mut sorted_actual = actual_raw.clone();
            sorted_expected.sort();
            sorted_actual.sort();
            if expected_raw != actual_raw && sorted_expected == sorted_actual {
                let mut path = prefix.to_vec();
                path.push(number);
                discovered.insert(ProtobufFieldPath(path));
            }
        }

        if expected_group.len() != actual_group.len()
            || expected_group.is_empty()
            || expected_group
                .iter()
                .chain(&actual_group)
                .any(|field| field.wire_type != 2)
        {
            continue;
        }
        let expected_payloads = expected_group
            .iter()
            .map(|field| field.payload.expect("wire type 2 has a payload"))
            .collect::<Vec<_>>();
        let actual_payloads = actual_group
            .iter()
            .map(|field| field.payload.expect("wire type 2 has a payload"))
            .collect::<Vec<_>>();
        let pairs =
            pair_nested_payloads(&expected_payloads, &actual_payloads).unwrap_or_else(|| {
                (0..expected_payloads.len())
                    .map(|index| (index, index))
                    .collect()
            });
        let mut nested_prefix = prefix.to_vec();
        nested_prefix.push(number);
        for (expected_index, actual_index) in pairs {
            discover_paths(
                expected_payloads[expected_index],
                actual_payloads[actual_index],
                &nested_prefix,
                depth + 1,
                discovered,
            );
        }
    }
}

fn discover_joined_string_paths(
    expected: &[u8],
    actual: &[u8],
    prefix: &[u32],
    depth: usize,
    discovered: &mut BTreeSet<(ProtobufFieldPath, String)>,
) {
    if depth >= MAX_NESTING_DEPTH || discovered.len() >= MAX_DISCOVERED_PATHS {
        return;
    }
    let (Ok(expected_fields), Ok(actual_fields)) = (parse_fields(expected), parse_fields(actual))
    else {
        return;
    };
    let numbers = expected_fields
        .iter()
        .map(|field| field.number)
        .chain(actual_fields.iter().map(|field| field.number))
        .collect::<BTreeSet<_>>();
    for number in numbers {
        if discovered.len() >= MAX_DISCOVERED_PATHS {
            return;
        }
        let expected_group = expected_fields
            .iter()
            .filter(|field| field.number == number)
            .collect::<Vec<_>>();
        let actual_group = actual_fields
            .iter()
            .filter(|field| field.number == number)
            .collect::<Vec<_>>();
        if expected_group.len() != actual_group.len()
            || expected_group.is_empty()
            || expected_group
                .iter()
                .chain(&actual_group)
                .any(|field| field.wire_type != 2)
        {
            continue;
        }
        let expected_payloads = expected_group
            .iter()
            .map(|field| field.payload.expect("wire type 2 has a payload"))
            .collect::<Vec<_>>();
        let actual_payloads = actual_group
            .iter()
            .map(|field| field.payload.expect("wire type 2 has a payload"))
            .collect::<Vec<_>>();
        let mut path = prefix.to_vec();
        path.push(number);
        if expected_payloads.len() == 1
            && let (Ok(expected_text), Ok(actual_text)) = (
                std::str::from_utf8(expected_payloads[0]),
                std::str::from_utf8(actual_payloads[0]),
            )
        {
            for separator in
                joined_string::matching_discovery_separators(expected_text, actual_text)
            {
                if discovered.len() >= MAX_DISCOVERED_PATHS {
                    return;
                }
                discovered.insert((ProtobufFieldPath(path.clone()), separator));
            }
        }
        let pairs =
            pair_nested_payloads(&expected_payloads, &actual_payloads).unwrap_or_else(|| {
                (0..expected_payloads.len())
                    .map(|index| (index, index))
                    .collect()
            });
        for (expected_index, actual_index) in pairs {
            discover_joined_string_paths(
                expected_payloads[expected_index],
                actual_payloads[actual_index],
                &path,
                depth + 1,
                discovered,
            );
        }
    }
}

fn pair_nested_payloads(expected: &[&[u8]], actual: &[&[u8]]) -> Option<Vec<(usize, usize)>> {
    let expected_fields = expected
        .iter()
        .map(|payload| parse_fields(payload).ok())
        .collect::<Option<Vec<_>>>()?;
    let actual_fields = actual
        .iter()
        .map(|payload| parse_fields(payload).ok())
        .collect::<Option<Vec<_>>>()?;
    let candidate_numbers = expected_fields
        .iter()
        .flat_map(|fields| fields.iter().map(|field| field.number))
        .collect::<BTreeSet<_>>();
    for number in candidate_numbers {
        let Some(expected_keys) = unique_identity_keys(&expected_fields, number) else {
            continue;
        };
        let Some(actual_keys) = unique_identity_keys(&actual_fields, number) else {
            continue;
        };
        if expected_keys.keys().eq(actual_keys.keys()) {
            return Some(
                expected_keys
                    .iter()
                    .map(|(key, expected_index)| (*expected_index, actual_keys[key]))
                    .collect(),
            );
        }
    }
    None
}

fn unique_identity_keys(
    messages: &[Vec<Field<'_>>],
    number: u32,
) -> Option<BTreeMap<Vec<u8>, usize>> {
    let mut keys = BTreeMap::new();
    for (index, fields) in messages.iter().enumerate() {
        let mut matching = fields.iter().filter(|field| field.number == number);
        let field = matching.next()?;
        if matching.next().is_some() || keys.insert(field.raw.to_vec(), index).is_some() {
            return None;
        }
    }
    Some(keys)
}

#[cfg(test)]
#[path = "protobuf/tests.rs"]
mod tests;

pub(in crate::replay) mod unordered_evidence;

mod wire;
use wire::{advance, parse_fields, read_varint};
