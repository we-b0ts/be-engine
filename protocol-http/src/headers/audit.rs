//! Native header differences with bounded, explicitly protected observations.
use super::{HeaderSnapshot, Mode, mode, normalized, protected};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize)]
pub struct Observation {
    pub presence: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    pub protected: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Difference {
    pub header: String,
    pub reason: String,
    pub kind: &'static str,
    pub comparison: &'static str,
    pub expected: Observation,
    pub actual: Observation,
}

#[derive(Debug, Default)]
pub struct Audit {
    pub mismatches: Vec<Difference>,
    pub observations: Vec<Difference>,
    pub observation_count: usize,
}

pub fn compare(
    expected: &HeaderSnapshot,
    actual: &HeaderSnapshot,
    encrypted: &BTreeSet<String>,
    retain_observations: bool,
) -> Audit {
    let expected = normalized(expected);
    let actual = normalized(actual);
    let connection_headers = [&expected, &actual]
        .into_iter()
        .filter_map(|headers| headers.get("connection"))
        .flatten()
        .flat_map(|value| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let names = expected
        .keys()
        .chain(actual.keys())
        .collect::<BTreeSet<_>>();
    let mut audit = Audit::default();
    for name in names {
        let mode = mode(name, &connection_headers);
        let recorded = expected.get(name);
        let sent = actual.get(name);
        if mode == Mode::Ignore
            || mode == Mode::SourcePresence && (recorded.is_none() || sent.is_some())
        {
            continue;
        }
        let presence_differs = recorded.is_some() != sent.is_some();
        let unavailable = !presence_differs
            && recorded.is_some_and(|values| values.iter().any(|v| v == "<redacted>"));
        if recorded == sent && !unavailable {
            continue;
        }
        let dirty = !unavailable
            && (mode == Mode::Strict
                || mode == Mode::Presence && presence_differs
                || mode == Mode::SourcePresence && recorded.is_some() && sent.is_none());
        if !dirty {
            audit.observation_count += 1;
            if !retain_observations {
                continue;
            }
        }
        let kind = if unavailable {
            "header_unavailable"
        } else if recorded.is_none() {
            "header_added"
        } else if sent.is_none() {
            "header_missing"
        } else {
            "header_value_mismatch"
        };
        let mut expected = observation(name, recorded, encrypted.contains(name));
        let mut actual = observation(name, sent, encrypted.contains(name));
        if mode == Mode::SourcePresence {
            expected.values = None;
            actual.values = None;
        }
        if unavailable {
            expected.presence = "unavailable";
            expected.values = None;
        }
        let difference = Difference {
            header: name.clone(),
            reason: format!("{kind}: {name}"),
            kind,
            comparison: match mode {
                Mode::Ignore => "ignore",
                Mode::Observe => "observe",
                Mode::Presence => "presence",
                Mode::SourcePresence => "source_presence",
                Mode::Strict => "strict",
            },
            expected,
            actual,
        };
        if dirty {
            audit.mismatches.push(difference);
        } else {
            audit.observations.push(difference);
        }
    }
    audit
}

fn observation(name: &str, values: Option<&Vec<String>>, encrypted: bool) -> Observation {
    let protected = encrypted || protected(name);
    Observation {
        presence: if values.is_some() {
            "present"
        } else {
            "missing"
        },
        values: values.map(|values| {
            if protected {
                vec!["<redacted>".into()]
            } else {
                values
                    .iter()
                    .take(8)
                    .map(|value| value.chars().take(256).collect())
                    .collect()
            }
        }),
        protected,
    }
}

#[cfg(test)]
mod tests;
