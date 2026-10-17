//! A rule-level match cannot authorize an unobserved nested relationship.
use super::*;

#[derive(Default)]
pub(super) struct Coverage {
    references: BTreeSet<(String, usize)>,
    columns: BTreeSet<(String, String)>,
}
impl Coverage {
    pub(super) fn references(&mut self, hits: impl IntoIterator<Item = (String, usize)>) {
        self.references.extend(hits);
    }
    pub(super) fn column(&mut self, id: &str, column: &str) {
        self.columns.insert((id.into(), column.into()));
    }
    pub(super) fn finish(
        &self,
        compiled: &CompiledPolicy,
        selected: &BTreeSet<String>,
        counts: &BTreeMap<String, usize>,
    ) -> Result<()> {
        for compiled in compiled
            .native
            .iter()
            .filter(|rule| selected.contains(&rule.rule.id) && dependency_effect(&rule.rule.effect))
        {
            let rule = &compiled.rule;
            ensure!(
                counts.get(&rule.id).is_some_and(|count| *count > 0),
                "native rule {} has no positive complete Source evidence",
                rule.id
            );
            match &rule.effect {
                NativeEffect::Identity(effect) => {
                    for index in 0..effect.references.len() {
                        ensure!(
                            self.references.contains(&(rule.id.clone(), index)),
                            "native identity {} reference resource {index} has no use after a Source capture",
                            rule.id
                        );
                    }
                }
                NativeEffect::MysqlValues(effect) => {
                    for column in effect.response_time.keys() {
                        ensure!(
                            self.columns.contains(&(rule.id.clone(), column.clone())),
                            "native SQL rule {} response column {column} has no positive Source time cell",
                            rule.id
                        );
                    }
                }
                _ => (),
            }
        }
        Ok(())
    }
}
