//! Connection-local Target transaction ownership, independent of Source matching.
//! A case switch cannot change the owner of an already active transaction.

#[derive(Debug, Default)]
pub(super) struct Scope {
    // None: no active transaction. Some(None): an active Global transaction.
    owner: Option<Option<String>>,
    confirmed: bool,
}

fn starts_transaction(sql: &str) -> bool {
    let sql = sql.trim().trim_end_matches(';').trim();
    sql.eq_ignore_ascii_case("begin") || sql.eq_ignore_ascii_case("start transaction")
}

impl Scope {
    pub(super) fn confirm(&mut self, owner: &Option<String>) -> Result<(), ()> {
        if let Some(current) = &self.owner {
            if self.confirmed && current != owner {
                return Err(());
            }
            self.owner = Some(owner.clone());
            self.confirmed = true;
        }
        Ok(())
    }

    pub(super) fn case(&self, active: Option<&str>, sql: Option<&str>) -> Option<String> {
        // A successful new BEGIN replaces the old transaction. Its request is
        // admitted under the current case; failure preserves the old owner.
        if sql.is_some_and(starts_transaction) {
            return active.map(ToOwned::to_owned);
        }
        self.owner
            .as_ref()
            .map_or_else(|| active.map(ToOwned::to_owned), Clone::clone)
    }

    pub(super) fn observe(&mut self, before: u16, after: u16, sql: &str, case: Option<&str>) {
        if after & 1 == 0 {
            self.owner = None;
            self.confirmed = false;
        } else if before & 1 == 0 || starts_transaction(sql) {
            self.owner = Some(case.map(ToOwned::to_owned));
            self.confirmed = false;
        }
    }
}

pub(super) fn is_business(normalized: &str) -> bool {
    !matches!(normalized, "select 1" | "select 2")
        && normalized.split_whitespace().next().is_some_and(|word| {
            matches!(
                word,
                "select" | "insert" | "update" | "delete" | "replace" | "with"
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_transaction_survives_case_changes_and_resets_for_pool_reuse() {
        let mut scope = Scope::default();
        scope.observe(2, 3, "BEGIN", None);
        assert_eq!(scope.case(Some("next"), Some("UPDATE t SET a=1")), None);
        assert_eq!(scope.case(Some("next"), Some("COMMIT")), None);
        scope.observe(3, 2, "COMMIT", None);
        assert_eq!(scope.case(Some("next"), None).as_deref(), Some("next"));
        scope.observe(2, 3, "BEGIN", Some("next"));
        assert_eq!(scope.case(Some("other"), None).as_deref(), Some("next"));
        scope.observe(3, 2, "SET AUTOCOMMIT=1", Some("next"));
        assert_eq!(scope.case(Some("other"), None).as_deref(), Some("other"));
    }

    #[test]
    fn source_anchor_corrects_provisional_owner_but_rejects_conflicting_business() {
        let mut scope = Scope::default();
        scope.observe(2, 3, "BEGIN", Some("case"));
        assert_eq!(scope.confirm(&None), Ok(()));
        assert_eq!(scope.case(Some("case"), None), None);
        assert_eq!(scope.confirm(&Some("case".into())), Err(()));
        scope.observe(3, 2, "COMMIT", None);
        scope.observe(2, 3, "BEGIN", Some("case"));
        assert_eq!(scope.confirm(&Some("case".into())), Ok(()));
        assert_eq!(scope.confirm(&None), Err(()));
        assert_eq!(scope.case(None, None).as_deref(), Some("case"));
    }
}
