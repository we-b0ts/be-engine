//! Case-local, source-bound write observations. This is not a Redis value store.
use super::*;

#[derive(Debug, Clone)]
pub(super) struct Binding {
    pub case: String,
    pub rule: String,
    pub entry: usize,
    pub database: i64,
    pub username: Option<String>,
    pub key: Vec<u8>,
    pub target_key: Vec<u8>,
    pub pointer: String,
    pub source: Value,
    pub target: Value,
    pub connection: uuid::Uuid,
    pub sequence: u64,
    pub completed: DateTime<Utc>,
}

#[derive(Default)]
pub(in crate::replay::policy::request_contract) struct ReadBackState {
    pub(super) bindings: Vec<Binding>,
    pub(super) used: BTreeSet<(String, usize)>,
    pub(super) reports: Vec<RedisReadBackReport>,
}

impl ReadBackState {
    pub(in crate::replay::policy::request_contract) fn begin_case(&mut self, case: &str) {
        self.bindings.retain(|value| value.case != case);
        self.reports.retain(|value| value.case_id != case);
    }

    pub(super) fn validate(&self, pending: &[Binding]) -> Result<()> {
        let mut count = self.bindings.len();
        let mut bytes = self.bindings.iter().map(size).sum::<usize>();
        for (index, next) in pending.iter().enumerate() {
            let previous = self
                .bindings
                .iter()
                .chain(pending[..index].iter())
                .filter(|old| {
                    old.case == next.case
                        && old.rule == next.rule
                        && old.entry == next.entry
                        && old.database == next.database
                        && old.username == next.username
                        && old.key == next.key
                        && old.pointer == next.pointer
                        && old.source == next.source
                })
                .collect::<Vec<_>>();
            for old in &previous {
                ensure!(
                    old.target == next.target && old.target_key == next.target_key,
                    "read_back changed a previously bound write value"
                );
            }
            if !previous.iter().any(|old| old.connection == next.connection) {
                count += 1;
                bytes = bytes
                    .checked_add(size(next))
                    .context("read_back binding size overflow")?;
            }
        }
        ensure!(
            count <= 4096 && bytes <= 16 * 1024 * 1024,
            "read_back binding budget exceeded"
        );
        Ok(())
    }

    pub(super) fn lookup(
        &self,
        context: &RedisRequestContext<'_>,
        rule: &str,
        entry: usize,
        keys: (&[u8], &[u8]),
        pointer: &str,
        source: &Value,
    ) -> Result<&Binding> {
        let connection = context
            .connection_id
            .context("read_back needs original read connection identity")?;
        let sequence = context
            .sequence
            .context("read_back needs original read sequence")?;
        let started = context
            .recorded_at
            .context("read_back needs original read start")?;
        let mut selected = self.bindings.iter().filter(|binding| {
            binding.case == context.case
                && binding.rule == rule
                && binding.entry == entry
                && binding.database == context.database
                && binding.username.as_deref() == context.username
                && binding.key == keys.0
                && binding.target_key == keys.1
                && binding.pointer == pointer
                && &binding.source == source
                && if binding.connection == connection {
                    binding.sequence < sequence
                } else {
                    binding.completed <= started
                }
        });
        let binding = selected.next().context(
            "read_back has no preceding successfully matched write for the Source read value",
        )?;
        ensure!(
            selected.all(|other| other.target == binding.target),
            "ambiguous read_back write origin"
        );
        Ok(binding)
    }

    pub(super) fn commit(&mut self, pending: Vec<Binding>) {
        for value in pending {
            // Keep an origin per Source connection: another writer can finish
            // first even when its request started later. Repeated touches on
            // one ordered connection do not allocate another identical binding.
            if !self.bindings.iter().any(|old| {
                old.case == value.case
                    && old.rule == value.rule
                    && old.entry == value.entry
                    && old.database == value.database
                    && old.username == value.username
                    && old.key == value.key
                    && old.pointer == value.pointer
                    && old.source == value.source
                    && old.connection == value.connection
            }) {
                self.bindings.push(value);
            }
        }
    }
}

fn size(binding: &Binding) -> usize {
    binding.key.len()
        + binding.username.as_ref().map_or(0, String::len)
        + binding.target_key.len()
        + binding.pointer.len()
        + serde_json::to_vec(&binding.source).map_or(usize::MAX / 4, |v| v.len())
        + serde_json::to_vec(&binding.target).map_or(usize::MAX / 4, |v| v.len())
}
