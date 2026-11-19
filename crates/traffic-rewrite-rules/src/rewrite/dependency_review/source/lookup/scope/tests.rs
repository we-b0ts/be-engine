use super::*;
use crate::dependency::observation::ScopeIndex;

#[test]
fn sealed_scope_stream_retains_requested_uuid_and_rejects_corrupt_or_escaping_indexes() {
    let directory = tempfile::tempdir().unwrap();
    let mut scope: ScopeIndex = ScopeIndex {
        schema: SCOPE_SCHEMA.into(),
        run_relpath: ".".into(),
        scope: ScopeKind::Process,
        locations: (0..4096)
            .map(|index| ScopeRecordLocation {
                line: index + 1,
                offset: index as u64,
                length: 1,
                sha256: "a".repeat(64),
                exchange_id: Uuid::from_u128(index as u128 + 1),
                effect_index: 0,
            })
            .collect(),
    };
    let path = directory.path().join("process-scope.json");
    let write = |scope: &ScopeIndex| {
        let bytes = serde_json::to_vec(scope).unwrap();
        fs::write(&path, &bytes).unwrap();
        LedgerFileIdentity {
            path: "process-scope.json".into(),
            length: bytes.len() as u64,
            sha256: digest(&bytes),
        }
    };
    let identity = write(&scope);
    let selected = read(directory.path(), &identity, Uuid::from_u128(4096), 4096).unwrap();
    assert_eq!(selected.count, 4096);
    assert_eq!(selected.locations.len(), 1);
    assert_eq!(selected.locations[0].offset, 4095);
    assert!(
        read(directory.path(), &identity, Uuid::nil(), 4096)
            .unwrap()
            .locations
            .is_empty()
    );
    assert!(read(directory.path(), &identity, Uuid::nil(), 4095).is_err());
    scope.locations[0].sha256 = "b".repeat(64);
    write(&scope);
    assert!(read(directory.path(), &identity, Uuid::nil(), 4096).is_err());
    scope.run_relpath = "..".into();
    let escaping = write(&scope);
    assert!(read(directory.path(), &escaping, Uuid::nil(), 4096).is_err());
}
