//! Stream sealed locator metadata, retaining only the requested physical UUID.
use super::*;
use crate::dependency::observation::{SCOPE_SCHEMA, ScopeKind, ScopeRecordLocation};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::io::{BufReader, Read};
#[cfg(test)]
mod tests;

#[derive(Default)]
pub(super) struct Selected {
    pub count: u64,
    pub locations: Vec<crate::dependency_index::RecordLocation>,
}

pub(super) fn read(
    root: &Path,
    file: &LedgerFileIdentity,
    id: Uuid,
    source_size: u64,
) -> Result<Selected> {
    let path = root.join(&file.path);
    let stamp = crate::dependency_index::FileStamp::read_native(&path)?;
    ensure!(
        stamp.size == file.length,
        "sealed Source locator length changed"
    );
    let mut hash = Sha256::new();
    let reader = Hashed {
        input: fs::File::open(&path)?,
        hash: &mut hash,
    };
    let mut input = serde_json::Deserializer::from_reader(BufReader::new(reader));
    let (run, selected) = ScopeSeed { id, source_size }.deserialize(&mut input)?;
    input.end()?;
    drop(input);
    ensure!(
        format!("{:x}", hash.finalize()) == file.sha256.trim_start_matches("sha256:"),
        "sealed Source locator content changed"
    );
    ensure!(
        crate::dependency_index::FileStamp::read_native(&path)? == stamp,
        "Source locator changed during lookup"
    );
    ensure!(
        fs::canonicalize(
            path.parent()
                .context("Source locator has no directory")?
                .join(run)
        )? == fs::canonicalize(root)?,
        "Source locator escapes the recording boundary"
    );
    Ok(selected)
}

struct Hashed<'a> {
    input: fs::File,
    hash: &'a mut Sha256,
}
impl Read for Hashed<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let count = self.input.read(bytes)?;
        self.hash.update(&bytes[..count]);
        Ok(count)
    }
}

#[derive(Clone, Copy)]
struct ScopeSeed {
    id: Uuid,
    source_size: u64,
}
impl<'de> DeserializeSeed<'de> for ScopeSeed {
    type Value = (String, Selected);
    fn deserialize<D: de::Deserializer<'de>>(self, input: D) -> Result<Self::Value, D::Error> {
        input.deserialize_map(self)
    }
}
impl<'de> Visitor<'de> for ScopeSeed {
    type Value = (String, Selected);
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a sealed Source scope index")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut input: M) -> Result<Self::Value, M::Error> {
        let (mut schema, mut run, mut scope, mut locations) = (None, None, None, None);
        while let Some(key) = input.next_key::<String>()? {
            match key.as_str() {
                "schema" if schema.is_none() => schema = Some(input.next_value::<String>()?),
                "run_relpath" if run.is_none() => run = Some(input.next_value::<String>()?),
                "scope" if scope.is_none() => scope = Some(input.next_value::<ScopeKind>()?),
                "locations" if locations.is_none() => {
                    locations = Some(input.next_value_seed(LocationsSeed(self))?)
                }
                "schema" | "run_relpath" | "scope" | "locations" => {
                    return Err(de::Error::custom("duplicate Source scope field"));
                }
                _ => {
                    input.next_value::<de::IgnoredAny>()?;
                }
            }
        }
        if schema.as_deref() != Some(SCOPE_SCHEMA) || scope.is_none() {
            return Err(de::Error::custom(
                "unsupported or incomplete Source scope index",
            ));
        }
        Ok((
            run.ok_or_else(|| de::Error::missing_field("run_relpath"))?,
            locations.ok_or_else(|| de::Error::missing_field("locations"))?,
        ))
    }
}

struct LocationsSeed(ScopeSeed);
impl<'de> DeserializeSeed<'de> for LocationsSeed {
    type Value = Selected;
    fn deserialize<D: de::Deserializer<'de>>(self, input: D) -> Result<Self::Value, D::Error> {
        input.deserialize_seq(self)
    }
}
impl<'de> Visitor<'de> for LocationsSeed {
    type Value = Selected;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("Source record locations")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> Result<Self::Value, A::Error> {
        let mut selected = Selected::default();
        let (mut end, mut line) = (0, 0);
        while let Some(location) = input.next_element::<ScopeRecordLocation>()? {
            let next = location.offset.checked_add(location.length);
            if location.length == 0
                || location.offset < end
                || location.line <= line
                || !next.is_some_and(|n| n <= self.0.source_size)
                || location.sha256.len() != 64
                || !location.sha256.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(de::Error::custom("invalid Source scope location"));
            }
            end = next.expect("checked location");
            line = location.line;
            selected.count += 1;
            if location.exchange_id == self.0.id {
                selected
                    .locations
                    .push(crate::dependency_index::RecordLocation {
                        line: location.line,
                        offset: location.offset,
                        length: location.length,
                        sha256: location.sha256,
                    });
            }
        }
        Ok(selected)
    }
}
